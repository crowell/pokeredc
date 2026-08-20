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


class Boundary(angr.SimProcedure):
    def __init__(self, continuation: int, marker: str | None = None):
        super().__init__()
        self.continuation = continuation
        self.marker = marker

    def run(self) -> None:
        if self.marker is not None:
            self.state.globals[self.marker] = claripy.BVV(1, 8)
        self.jump(self.continuation)


class LoadField(angr.SimProcedure):
    def __init__(self, field: str, continuation: int):
        super().__init__()
        self.field = field
        self.continuation = continuation

    def run(self) -> None:
        self.state.regs.a = self.state.globals[self.field]
        self.jump(self.continuation)


class StoreField(angr.SimProcedure):
    def __init__(self, field: str, continuation: int):
        super().__init__()
        self.field = field
        self.continuation = continuation

    def run(self) -> None:
        self.state.globals[self.field] = self.state.regs.a
        self.jump(self.continuation)


class LoadFetched(angr.SimProcedure):
    def run(self) -> None:
        self.state.regs.a = self.state.globals["fetched_species"]
        self.jump(self.addr + 1)


class PopSavedEntry(angr.SimProcedure):
    def run(self) -> None:
        self.state.regs.h = self.state.globals["saved_entry_h"]
        self.state.regs.l = self.state.globals["saved_entry_l"]
        self.jump(self.addr + 1)


class SaveAF(angr.SimProcedure):
    def __init__(self, continuation: int):
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:
        self.state.globals["stack_saved_pokedex_num"] = self.state.regs.a
        self.state.globals["stack_saved_pokedex_f"] = self.state.regs.f
        self.jump(self.continuation)


class RestoreAF(angr.SimProcedure):
    def __init__(self, continuation: int):
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:
        self.state.regs.a = self.state.globals["stack_saved_pokedex_num"]
        self.state.regs.f = self.state.globals["stack_saved_pokedex_f"]
        self.jump(self.continuation)


class FinalPartyPointer(angr.SimProcedure):
    def run(self) -> None:
        which = self.state.globals["which_pokemon"]
        base = claripy.BVV(0xD16B, 16)
        offset = claripy.ZeroExt(8, which) * claripy.BVV(44, 16)
        pointer = base + offset
        low = pointer[7:0]
        high = pointer[15:8]
        low_wide = claripy.ZeroExt(1, base & 0x0FFF) + claripy.ZeroExt(1, offset & 0x0FFF)
        wide = claripy.ZeroExt(1, base) + claripy.ZeroExt(1, offset)
        carry = claripy.UGT(wide, 0xFFFF)
        half = claripy.UGT(low_wide, 0x0FFF)
        z = self.state.globals["cur_species"] == 1
        flags = claripy.If(z, claripy.BVV(0x80, 8), claripy.BVV(0, 8))
        flags |= claripy.If(half, claripy.BVV(0x20, 8), claripy.BVV(0, 8))
        flags |= claripy.If(carry, claripy.BVV(0x10, 8), claripy.BVV(0, 8))
        self.state.regs.a = which
        self.state.regs.b = 0
        self.state.regs.c = 44
        self.state.regs.d = 0xD0
        self.state.regs.e = 0xB8
        self.state.regs.h = high
        self.state.regs.l = low
        self.state.regs.f = sm83_flags_to_z80(flags)
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
    q = location.address
    project.hook(q + 0xE4, Boundary(q + 0xE7, "evolved_text_called"), length=3)
    project.hook(q + 0xE7, PopSavedEntry(), length=1)
    project.hook(q + 0xE8, LoadFetched(), length=1)
    project.hook(q + 0xE9, StoreField("cur_species", q + 0xEC), length=3)
    project.hook(q + 0xEC, StoreField("loaded_mon_species", q + 0xEF), length=3)
    project.hook(q + 0xEF, StoreField("evo_new_species", q + 0xF2), length=3)
    project.hook(q + 0xF4, StoreField("name_list_type", q + 0xF7), length=3)
    project.hook(q + 0xF9, StoreField("predef_bank", q + 0xFC), length=3)
    project.hook(q + 0xFC, Boundary(q + 0xFF), length=3)
    project.hook(q + 0x103, Boundary(q + 0x106, "into_text_called"), length=3)
    project.hook(q + 0x108, Boundary(q + 0x10B), length=3)
    project.hook(q + 0x10B, Boundary(q + 0x10E), length=3)
    project.hook(q + 0x110, Boundary(q + 0x113), length=3)
    project.hook(q + 0x113, Boundary(q + 0x116, "clear_screen_called"), length=3)
    project.hook(q + 0x116, Boundary(q + 0x119, "rename_called"), length=3)
    project.hook(q + 0x119, LoadField("pokedex_num", q + 0x11C), length=3)
    project.hook(q + 0x11C, SaveAF(q + 0x11D), length=1)
    project.hook(q + 0x11D, LoadField("cur_species", q + 0x120), length=3)
    project.hook(q + 0x120, StoreField("pokedex_num", q + 0x123), length=3)
    project.hook(q + 0x125, Boundary(q + 0x128), length=3)
    project.hook(q + 0x128, LoadField("pokedex_num", q + 0x12B), length=3)
    project.hook(q + 0x142, StoreField("pokedex_num", q + 0x145), length=3)
    project.hook(q + 0x132, Boundary(q + 0x135), length=3)
    project.hook(q + 0x138, Boundary(q + 0x13B), length=3)
    project.hook(q + 0x13B, LoadField("cur_species", q + 0x13E), length=3)
    project.hook(q + 0x13E, StoreField("mon_h_index", q + 0x141), length=3)
    project.hook(q + 0x141, RestoreAF(q + 0x142), length=1)
    project.hook(q + 0x14D, Boundary(q + 0x150, "calc_stats_called"), length=3)
    project.hook(q + 0x150, LoadField("which_pokemon", q + 0x153), length=3)
    project.hook(q + 0x159, FinalPartyPointer(), length=3)
    state = project.factory.blank_state(addr=q + 0xE1)
    _setup(state, values)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored
    return [_endpoint(end) for end in manager.found]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_evolution_success_transition")
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
def test_evolution_success_transition_pathwise_equivalence() -> None:
    values = _inputs("success_transition")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "memory"),
    )
