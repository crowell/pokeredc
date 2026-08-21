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
from verification.harness.sm83_shims import Sm83StoreAHighImmediate, Sm83StoreAImmediate

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
DONE = 0xEFFF
SIZE = 0xCD6C
BASE_TILE = 0xFF8B


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
    downscaled_size: claripy.ast.BV
    base_tile_id: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class SetupHL(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = claripy.BVV(0xC4, 8)
        self.state.regs.l = claripy.BVV(0x2F, 8)
        self.jump(self.state.addr + 3)


class LoadBC55(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.b = claripy.BVV(5, 8)
        self.state.regs.c = claripy.BVV(5, 8)
        self.jump(self.state.addr + 3)


class XorA(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x40, 8)
        self.jump(self.state.addr + 1)


class SkipInitialCallee(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(self.state.addr + 9)


class Boundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.successors.add_successor(
            self.state.copy(), DONE, claripy.BoolV(True), "Ijk_Boring"
        )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "AnimateRetreatingPlayerMon")
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
    project.hook(base, SkipInitialCallee(), length=9)
    project.hook(base + 9, SetupHL(), length=3)
    project.hook(base + 12, LoadBC55(), length=3)
    project.hook(base + 15, XorA(), length=1)
    project.hook(base + 16, Sm83StoreAImmediate(SIZE, base + 19), length=3)
    project.hook(base + 19, Sm83StoreAHighImmediate(0x8B, base + 21), length=2)
    project.hook(base + 21, Boundary(), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.memory.store(SIZE, values["downscaled_size"])
    state.memory.store(BASE_TILE, values["base_tile_id"])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored
    return [
        Endpoint(
            **assembly_registers(end),
            downscaled_size=end.memory.load(SIZE, 1),
            base_tile_id=end.memory.load(BASE_TILE, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_animate_retreating_player_mon")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, values["downscaled_size"])
    state.memory.store(NATIVE_STATE + 9, values["base_tile_id"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            downscaled_size=end.memory.load(NATIVE_STATE + 8, 1),
            base_tile_id=end.memory.load(NATIVE_STATE + 9, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_animate_retreating_player_mon_entry_pathwise_equivalence() -> None:
    values = symbolic_registers("animate_retreating_player_mon")
    values["downscaled_size"] = claripy.BVS("animate_retreating_player_mon_size", 8)
    values["base_tile_id"] = claripy.BVS("animate_retreating_player_mon_base_tile", 8)
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "downscaled_size", "base_tile_id"),
    )
