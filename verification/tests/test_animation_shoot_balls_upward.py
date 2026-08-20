from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS, assembly_registers, native_registers, set_assembly_registers, store_native_registers, symbolic_registers
from verification.harness.rom import rom_window, symbol_location

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF
TILESET = 0xD09F
BASE_Y = 0xD082
SHADOW_OAM = 0xC300

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
    y: claripy.ast.BV
    tileset: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]

class XorA(angr.SimProcedure):
    def run(self) -> None:
        self.inhibit_autoret = True
        state = self.state.copy()
        state.regs.a = claripy.BVV(0, 8)
        state.regs.f = claripy.BVV(0x40, 8)
        self.successors.add_successor(state, self.addr + 1, claripy.BoolV(True), "Ijk_Boring")

class StoreA(angr.SimProcedure):
    def __init__(self, address: int, next_address: int) -> None:
        super().__init__(); self.address = address; self.next_address = next_address
    def run(self) -> None:
        self.inhibit_autoret = True
        state = self.state.copy()
        state.memory.store(self.address, state.regs.a)
        self.successors.add_successor(state, self.next_address, claripy.BoolV(True), "Ijk_Boring")

class SkipCall(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__(); self.next_address = next_address
    def run(self) -> None:
        self.inhibit_autoret = True
        state = self.state.copy()
        state.regs.sp = state.regs.sp + 2
        self.successors.add_successor(state, self.next_address, claripy.BoolV(True), "Ijk_Boring")

class LoadHL(angr.SimProcedure):
    def run(self) -> None:
        self.inhibit_autoret = True
        state = self.state.copy()
        state.regs.h = claripy.BVV(0xC3, 8); state.regs.l = claripy.BVV(0, 8)
        self.successors.add_successor(state, self.addr + 3, claripy.BoolV(True), "Ijk_Boring")

class LoadY(angr.SimProcedure):
    def run(self) -> None:
        self.inhibit_autoret = True
        state = self.state.copy(); state.regs.a = state.memory.load(BASE_Y, 1)
        self.successors.add_successor(state, self.addr + 3, claripy.BoolV(True), "Ijk_Boring")

class Boundary(angr.SimProcedure):
    def run(self) -> None:
        self.inhibit_autoret = True
        self.successors.add_successor(self.state.copy(), DONE, claripy.BoolV(True), "Ijk_Boring")

def _endpoint(state: angr.SimState, base: int, assembly: bool) -> Endpoint:
    return Endpoint(**(assembly_registers(state) if assembly else native_registers(state, NATIVE_STATE)), y=state.memory.load(base + BASE_Y, 1), tileset=state.memory.load(base + TILESET, 1), constraints=tuple(state.solver.constraints))

def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "_AnimationShootBallsUpward")
    loader = symbol_location(SYMBOLS, "LoadMoveAnimationTiles")
    boundary = symbol_location(SYMBOLS, "BattleAnimWriteOAMEntry")
    project = angr.Project(rom_window(ROM, location.bank), auto_load_libs=False, rebase_granularity=0x100, main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":location.address})
    project.hook(location.address + 1, XorA(), length=1)
    project.hook(location.address + 2, StoreA(TILESET, location.address + 5), length=3)
    project.hook(loader.address, SkipCall(location.address + 8), length=1)
    project.hook(location.address + 11, LoadHL(), length=3)
    project.hook(location.address + 15, LoadY(), length=3)
    project.hook(boundary.address, Boundary(), length=1)
    state = project.factory.blank_state(addr=location.address); set_assembly_registers(state, values); state.memory.store(BASE_Y, values["y"]); state.memory.store(TILESET, values["tileset"])
    manager = project.factory.simulation_manager(state); manager.explore(find=DONE, num_find=1); assert not manager.errored
    return [_endpoint(end, 0, True) for end in manager.found]

def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False); function = project.loader.find_symbol("port_animation_shoot_balls_upward"); assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY); store_native_registers(state, NATIVE_STATE, values); state.memory.store(NATIVE_MEMORY + BASE_Y, values["y"]); state.memory.store(NATIVE_MEMORY + TILESET, values["tileset"])
    manager = project.factory.simulation_manager(state); manager.run(); assert not manager.errored
    return [_endpoint(end, NATIVE_MEMORY, False) for end in manager.deadended]

@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_animation_shoot_balls_upward_entry_pathwise_equivalence() -> None:
    values = symbolic_registers("animation_shoot_balls_upward")
    values["y"] = claripy.BVS("shoot_balls_y", 8); values["tileset"] = claripy.BVS("shoot_balls_tileset", 8)
    assert_pathwise_equivalent(_assembly(values), _native(values), (*REGISTERS, "y", "tileset"))
