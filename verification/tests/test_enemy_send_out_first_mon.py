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
from verification.harness.sm83_shims import Sm83StoreAAtHlIncrement, Sm83StoreAImmediate

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
DONE = 0xEFFF
STATS = 0xD065


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
    status0: claripy.ast.BV
    status1: claripy.ast.BV
    status2: claripy.ast.BV
    status3: claripy.ast.BV
    status4: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class XorA(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x40, 8)
        self.jump(self.state.addr + 1)


class SetupHL(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = claripy.BVV(0xD0, 8)
        self.state.regs.l = claripy.BVV(0x65, 8)
        self.jump(self.state.addr + 3)


class StoreAAtHL(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(self.state.regs.hl, self.state.regs.a)
        self.jump(self.state.addr + 1)


class Boundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.successors.add_successor(
            self.state.copy(), DONE, claripy.BoolV(True), "Ijk_Boring"
        )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "EnemySendOutFirstMon")
    base = location.address
    project = angr.Project(
        rom_window(ROM, location.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": base,
        },
    )
    project.hook(base, XorA(), length=1)
    project.hook(base + 1, SetupHL(), length=3)
    for offset, next_offset in ((4, 5), (5, 6), (6, 7), (7, 8)):
        project.hook(offset + base, Sm83StoreAAtHlIncrement(base + next_offset), length=1)
    project.hook(base + 8, StoreAAtHL(), length=1)
    project.hook(base + 9, Boundary(), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    for address in range(STATS, STATS + 5):
        state.memory.store(address, claripy.BVS(f"enemy_send_out_first_status_{address}", 8))
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored
    return [
        Endpoint(
            **assembly_registers(end),
            status0=end.memory.load(STATS, 1),
            status1=end.memory.load(STATS + 1, 1),
            status2=end.memory.load(STATS + 2, 1),
            status3=end.memory.load(STATS + 3, 1),
            status4=end.memory.load(STATS + 4, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_enemy_send_out_first_mon")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    for offset, name in enumerate(("status0", "status1", "status2", "status3", "status4"), 8):
        state.memory.store(NATIVE_STATE + offset, claripy.BVS(f"native_{name}", 8))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            status0=end.memory.load(NATIVE_STATE + 8, 1),
            status1=end.memory.load(NATIVE_STATE + 9, 1),
            status2=end.memory.load(NATIVE_STATE + 10, 1),
            status3=end.memory.load(NATIVE_STATE + 11, 1),
            status4=end.memory.load(NATIVE_STATE + 12, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_enemy_send_out_first_mon_entry_pathwise_equivalence() -> None:
    values = symbolic_registers("enemy_send_out_first_mon")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "status0", "status1", "status2", "status3", "status4"),
    )
