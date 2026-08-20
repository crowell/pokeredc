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
from verification.harness.rom import rom_window, symbol_location
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


class CallBoundary(angr.SimProcedure):
    def __init__(self, continuation: int, marker: str | None = None):
        super().__init__()
        self.continuation = continuation
        self.marker = marker

    def run(self) -> None:
        if self.marker is not None:
            self.state.globals[self.marker] = claripy.BVV(1, 8)
        self.jump(self.continuation)


class PopSavedEntry(angr.SimProcedure):
    def run(self) -> None:
        self.state.regs.h = self.state.globals["saved_entry_h"]
        self.state.regs.l = self.state.globals["saved_entry_l"]
        self.jump(self.addr + 1)


class LoadFetchedSpecies(angr.SimProcedure):
    def run(self) -> None:
        self.state.regs.a = self.state.globals["fetched_species"]
        self.jump(self.addr + 1)


class StoreField(angr.SimProcedure):
    def __init__(self, field: str, continuation: int):
        super().__init__()
        self.field = field
        self.continuation = continuation

    def run(self) -> None:
        self.state.globals[self.field] = self.state.regs.a
        self.jump(self.continuation)


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
    base = location.address + 0xE1
    project.hook(base + 3, CallBoundary(base + 6, "evolved_text_called"), length=3)
    project.hook(base + 6, PopSavedEntry(), length=1)
    project.hook(base + 7, LoadFetchedSpecies(), length=1)
    project.hook(base + 8, StoreField("cur_species", base + 0x0B), length=3)
    project.hook(base + 0x0B, StoreField("loaded_mon_species", base + 0x0E), length=3)
    project.hook(base + 0x0E, StoreField("evo_new_species", base + 0x11), length=3)
    project.hook(base + 0x13, StoreField("name_list_type", base + 0x16), length=3)
    project.hook(base + 0x18, StoreField("predef_bank", base + 0x1B), length=3)
    project.hook(base + 0x1B, CallBoundary(DONE), length=3)
    state = project.factory.blank_state(addr=base)
    _setup(state, values)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored
    return [_endpoint(end) for end in manager.found]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_evolution_success_species_transition")
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
def test_evolution_success_species_transition_pathwise_equivalence() -> None:
    values = _inputs("success_species")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "memory"),
    )
