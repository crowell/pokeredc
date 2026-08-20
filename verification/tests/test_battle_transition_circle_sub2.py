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
from verification.harness.sm83_shims import Sm83LoadAAtHlIncrement, Sm83StoreAImmediate

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
DONE = 0xEFFF
QY = 0xCD3D
QX = 0xCD3E
TABLE = 0x6000


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
    quadrant_y: claripy.ast.BV
    quadrant_x: claripy.ast.BV
    data_e: claripy.ast.BV
    data_d: claripy.ast.BV
    target_low: claripy.ast.BV
    target_high: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class LoadHAtHL(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = self.state.memory.load(self.state.regs.hl, 1)
        self.jump(self.state.addr + 1)


class CopyAToL(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.l = self.state.regs.a
        self.jump(self.state.addr + 1)


class Boundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.successors.add_successor(
            self.state.copy(), DONE, claripy.BoolV(True), "Ijk_Boring"
        )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "BattleTransition_Circle_Sub2")
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
    project.hook(base, Sm83StoreAImmediate(QY, base + 3), length=3)
    project.hook(base + 3, Sm83LoadAAtHlIncrement(base + 4), length=1)
    project.hook(base + 4, Sm83StoreAImmediate(QX, base + 7), length=3)
    project.hook(base + 7, Sm83LoadAAtHlIncrement(base + 8), length=1)
    project.hook(base + 9, Sm83LoadAAtHlIncrement(base + 10), length=1)
    project.hook(base + 11, Sm83LoadAAtHlIncrement(base + 12), length=1)
    project.hook(base + 12, LoadHAtHL(), length=1)
    project.hook(base + 13, CopyAToL(), length=1)
    project.hook(base + 14, Boundary(), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.regs.h = claripy.BVV(0x60, 8)
    state.regs.l = claripy.BVV(0, 8)
    state.memory.store(TABLE, values["quadrant_x"])
    state.memory.store(TABLE + 1, values["data_e"])
    state.memory.store(TABLE + 2, values["data_d"])
    state.memory.store(TABLE + 3, values["target_low"])
    state.memory.store(TABLE + 4, values["target_high"])
    state.memory.store(QY, claripy.BVV(0, 8))
    state.memory.store(QX, claripy.BVV(0, 8))
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored
    return [
        Endpoint(
            **assembly_registers(end),
            quadrant_y=end.memory.load(QY, 1),
            quadrant_x=end.memory.load(QX, 1),
            data_e=end.regs.e,
            data_d=end.regs.d,
            target_low=end.regs.l,
            target_high=end.regs.h,
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_battle_transition_circle_sub2")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    fields = {
        8: "a",
        9: "quadrant_x",
        10: "data_e",
        11: "data_d",
        12: "target_low",
        13: "target_high",
    }
    for offset, name in fields.items():
        state.memory.store(NATIVE_STATE + offset, values[name])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            quadrant_y=end.memory.load(NATIVE_STATE + 8, 1),
            quadrant_x=end.memory.load(NATIVE_STATE + 9, 1),
            data_e=end.memory.load(NATIVE_STATE + 10, 1),
            data_d=end.memory.load(NATIVE_STATE + 11, 1),
            target_low=end.memory.load(NATIVE_STATE + 12, 1),
            target_high=end.memory.load(NATIVE_STATE + 13, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_battle_transition_circle_sub2_pathwise_equivalence() -> None:
    values = symbolic_registers("battle_transition_circle_sub2")
    values["quadrant_x"] = claripy.BVS("battle_transition_circle_sub2_quadrant_x", 8)
    values["data_e"] = claripy.BVS("battle_transition_circle_sub2_data_e", 8)
    values["data_d"] = claripy.BVS("battle_transition_circle_sub2_data_d", 8)
    values["target_low"] = claripy.BVS("battle_transition_circle_sub2_target_low", 8)
    values["target_high"] = claripy.BVS("battle_transition_circle_sub2_target_high", 8)
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "quadrant_y", "quadrant_x", "data_e", "data_d", "target_low", "target_high"),
    )
