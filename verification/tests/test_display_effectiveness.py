from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
    assembly_registers,
    native_registers,
    set_assembly_registers,
    store_native_registers,
    symbolic_registers,
)
from verification.harness.rom import linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import Sm83AndImmediate, Sm83CpImmediate

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
    constraints: tuple[claripy.ast.Bool, ...]


class LoadDamageMultiplier(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals["damage_multipliers"]
        self.jump(self.state.addr + 3)




class LoadHL(angr.SimProcedure):
    def __init__(self, value: int, next_address: int) -> None:
        super().__init__()
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = claripy.BVV(self.value >> 8, 8)
        self.state.regs.l = claripy.BVV(self.value & 0xff, 8)
        self.jump(self.next_address)
class BranchZ(angr.SimProcedure):
    def __init__(self, taken: int, fallthrough: int) -> None:
        super().__init__()
        self.taken = taken
        self.fallthrough = fallthrough

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        condition = (self.state.regs.f & 0x40) != 0
        self.successors.add_successor(self.state.copy(), self.taken, condition, "Ijk_Boring")
        self.successors.add_successor(
            self.state.copy(), self.fallthrough, claripy.Not(condition), "Ijk_Boring"
        )


class BranchNC(angr.SimProcedure):
    def __init__(self, taken: int, fallthrough: int) -> None:
        super().__init__()
        self.taken = taken
        self.fallthrough = fallthrough

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        condition = (self.state.regs.f & 1) == 0
        self.successors.add_successor(self.state.copy(), self.taken, condition, "Ijk_Boring")
        self.successors.add_successor(
            self.state.copy(), self.fallthrough, claripy.Not(condition), "Ijk_Boring"
        )


class Boundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(DONE)


def _assembly(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    loc = symbol_location(SYMBOLS, "DisplayEffectiveness")
    base = loc.address
    project = angr.Project(
        rom_window(ROM, loc.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": base,
        },
    )
    project.hook(base, LoadDamageMultiplier(), length=3)
    project.hook(base + 3, Sm83AndImmediate(0x7f, base + 5), length=2)
    project.hook(base + 5, Sm83CpImmediate(0x0a, base + 7), length=2)
    project.hook(base + 7, BranchZ(DONE, base + 8), length=1)
    project.hook(base + 8, LoadHL(0x7b8e, base + 11), length=3)
    project.hook(base + 11, BranchNC(base + 16, base + 13), length=2)
    project.hook(base + 13, LoadHL(0x7b93, base + 16), length=3)
    project.hook(base + 16, Boundary(), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, inputs)
    state.globals["damage_multipliers"] = inputs["damage_multipliers"]
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=3)
    assert len(manager.found) == 3
    return [Endpoint(**assembly_registers(end), constraints=tuple(end.solver.constraints)) for end in manager.found]


def _native(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_display_effectiveness")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["damage_multipliers"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 3
    return [
        Endpoint(**native_registers(end, NATIVE_STATE), constraints=tuple(end.solver.constraints))
        for end in manager.deadended
    ]


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
def test_display_effectiveness_pathwise_equivalence() -> None:
    inputs = symbolic_registers("de")
    inputs["damage_multipliers"] = claripy.BVS("de_damage_multipliers", 8)
    assert_pathwise_equivalent(
        _assembly(inputs),
        _native(inputs),
        ("a", "f", "b", "c", "d", "e", "h", "l"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_display_effectiveness_exact_linked_body() -> None:
    loc = symbol_location(SYMBOLS, "DisplayEffectiveness")
    assert linked_bytes(ROM, loc, 19) == bytes.fromhex("fa5bd0e67ffe0ac8218e7b300321937bc3493c")
