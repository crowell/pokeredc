from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
    REGISTERS,
    assembly_registers,
    native_registers,
    set_assembly_registers,
    store_native_registers,
    symbolic_registers,
)
from verification.harness.rom import rom_window, sm83_flags_to_z80, symbol_location
from verification.tests.test_cancelled_evolution_transition import MEMORY_FIELDS

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
DONE = 0xEFFF


@dataclass(frozen=True)
class Endpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    memory: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class LoadInBattle(angr.SimProcedure):
    def __init__(self, continuation: int):
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:
        self.state.regs.a = self.state.globals["is_in_battle"]
        self.jump(self.continuation)


class AndBattleBranch(angr.SimProcedure):
    def __init__(self, zero_target: int, nonzero_target: int):
        super().__init__()
        self.zero_target = zero_target
        self.nonzero_target = nonzero_target

    def run(self) -> None:
        self.inhibit_autoret = True
        value = self.state.regs.a
        canonical_flags = claripy.Concat(
            claripy.If(value == 0, claripy.BVV(1, 1), claripy.BVV(0, 1)),
            claripy.BVV(0, 1),
            claripy.BVV(1, 1),
            claripy.BVV(0, 1),
            claripy.BVV(0, 4),
        )
        zero = self.state.copy()
        zero.regs.f = sm83_flags_to_z80(canonical_flags)
        self.successors.add_successor(
            zero, self.zero_target, value == 0, "Ijk_Boring"
        )
        nonzero = self.state.copy()
        nonzero.regs.f = sm83_flags_to_z80(canonical_flags)
        self.successors.add_successor(
            nonzero, self.nonzero_target, value != 0, "Ijk_Boring"
        )


class ReloadWrapper(angr.SimProcedure):
    def __init__(self, continuation: int):
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:
        link_state = self.state.globals["link_state"]
        self.state.regs.a = link_state
        canonical_flags = claripy.Concat(
            claripy.If(link_state == 2, claripy.BVV(1, 1), claripy.BVV(0, 1)),
            claripy.BVV(1, 1),
            claripy.If(
                (link_state & 0x0F) < 2,
                claripy.BVV(1, 1),
                claripy.BVV(0, 1),
            ),
            claripy.If(
                link_state < 2,
                claripy.BVV(1, 1),
                claripy.BVV(0, 1),
            ),
            claripy.BVV(0, 4),
        )
        self.state.regs.f = sm83_flags_to_z80(canonical_flags)
        self.state.globals["reload_called"] = claripy.If(
            link_state == 2,
            self.state.globals["reload_called"],
            claripy.BVV(1, 8),
        )
        self.jump(self.continuation)


class Boundary(angr.SimProcedure):
    def run(self) -> None:
        self.jump(DONE)


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for name in MEMORY_FIELDS:
        values[name] = claripy.BVS(f"{prefix}_{name}", 8)
    return values


def _setup(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    set_assembly_registers(state, values)
    for name in MEMORY_FIELDS:
        state.globals[name] = values[name]


def _endpoint(state: angr.SimState) -> Endpoint:
    return Endpoint(
        **assembly_registers(state),
        memory=claripy.Concat(*(state.globals[name] for name in MEMORY_FIELDS)),
        constraints=tuple(state.solver.constraints),
    )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "EvolutionAfterBattle")
    project = angr.Project(
        rom_window(ROM, location.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": location.address,
        },
    )
    base = location.address + 0x191
    project.hook(base, LoadInBattle(base + 3), length=3)
    project.hook(base + 3, AndBattleBranch(base + 4, base + 7), length=1)
    project.hook(base + 4, ReloadWrapper(base + 7), length=3)
    project.hook(base + 7, Boundary(), length=2)
    state = project.factory.blank_state(addr=base)
    _setup(state, values)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=4)
    assert not manager.errored
    return [_endpoint(end) for end in manager.found]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_evolution_success_reload_transition")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(
        NATIVE_STATE + 8,
        claripy.Concat(*(values[name] for name in MEMORY_FIELDS)),
    )
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=end.memory.load(NATIVE_STATE + 8, len(MEMORY_FIELDS)),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_evolution_success_reload_transition_pathwise_equivalence() -> None:
    values = _inputs("success_reload")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "memory"),
    )
