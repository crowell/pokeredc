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
W_BASE_COORD_X = 0xD081
W_BASE_COORD_Y = 0xD082
W_SHADOW_OAM = 0xC300

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
    base_x: claripy.ast.BV
    base_y: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]
class LoadAConst(angr.SimProcedure):
    def __init__(self, value: int, next_address: int) -> None:
        super().__init__()
        self.value = value
        self.next_address = next_address

    def run(self) -> None:
        self.inhibit_autoret = True
        state = self.state.copy()
        state.regs.a = claripy.BVV(self.value, 8)
        state.regs.f = claripy.BVV(0, 8)
        self.successors.add_successor(state, self.next_address, claripy.BoolV(True), "Ijk_Boring")

class LoadAMemory(angr.SimProcedure):
    def __init__(self, address: int, next_address: int) -> None:
        super().__init__()
        self.address = address
        self.next_address = next_address

    def run(self) -> None:
        self.inhibit_autoret = True
        state = self.state.copy()
        state.regs.a = state.memory.load(self.address, 1)
        self.successors.add_successor(state, self.next_address, claripy.BoolV(True), "Ijk_Boring")

class StoreA(angr.SimProcedure):
    def __init__(self, address: int, next_address: int) -> None:
        super().__init__()
        self.address = address
        self.next_address = next_address

    def run(self) -> None:
        self.inhibit_autoret = True
        state = self.state.copy()
        state.memory.store(self.address, state.regs.a)
        self.successors.add_successor(state, self.next_address, claripy.BoolV(True), "Ijk_Boring")

class LoadShadowOAMPointer(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address
    def run(self) -> None:
        self.inhibit_autoret = True
        state = self.state.copy()
        state.regs.h = claripy.BVV(0xC3, 8)
        state.regs.l = claripy.BVV(0, 8)
        self.successors.add_successor(state, self.next_address, claripy.BoolV(True), "Ijk_Boring")

class ContinuationBoundary(angr.SimProcedure):
    def run(self) -> None:
        self.inhibit_autoret = True
        self.successors.add_successor(self.state.copy(), DONE, claripy.BoolV(True), "Ijk_Boring")

def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "ShakeEnemyHUD_WritePlayerMonPicOAM")
    continuation = symbol_location(SYMBOLS, "BattleAnimWriteOAMEntry")
    project = angr.Project(rom_window(ROM, location.bank), auto_load_libs=False, rebase_granularity=0x100, main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0, "entry_point": location.address})
    project.hook(location.address, LoadAConst(0x10, location.address + 2), length=2)
    project.hook(location.address + 2, StoreA(W_BASE_COORD_X, location.address + 5), length=3)
    project.hook(location.address + 5, LoadAConst(0x30, location.address + 7), length=2)
    project.hook(location.address + 7, StoreA(W_BASE_COORD_Y, location.address + 10), length=3)
    project.hook(location.address + 10, LoadShadowOAMPointer(location.address + 13), length=3)
    project.hook(location.address + 17, LoadAMemory(W_BASE_COORD_Y, location.address + 20), length=3)
    project.hook(continuation.address, ContinuationBoundary(), length=1)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.memory.store(W_BASE_COORD_X, values["base_x"])
    state.memory.store(W_BASE_COORD_Y, values["base_y"])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored
    return [Endpoint(**assembly_registers(end), base_x=end.memory.load(W_BASE_COORD_X, 1), base_y=end.memory.load(W_BASE_COORD_Y, 1), constraints=tuple(end.solver.constraints)) for end in manager.found]

def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_shake_enemy_hud_write_player_mon_pic_oam")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_MEMORY + W_BASE_COORD_X, values["base_x"])
    state.memory.store(NATIVE_MEMORY + W_BASE_COORD_Y, values["base_y"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [Endpoint(**native_registers(end, NATIVE_STATE), base_x=end.memory.load(NATIVE_MEMORY + W_BASE_COORD_X, 1), base_y=end.memory.load(NATIVE_MEMORY + W_BASE_COORD_Y, 1), constraints=tuple(end.solver.constraints)) for end in manager.deadended]

@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_shake_enemy_hud_write_player_mon_pic_oam_entry_pathwise_equivalence() -> None:
    values = symbolic_registers("shake_enemy_hud_oam")
    values["base_x"] = claripy.BVS("shake_enemy_hud_base_x", 8)
    values["base_y"] = claripy.BVS("shake_enemy_hud_base_y", 8)
    assert_pathwise_equivalent(_assembly(values), _native(values), (*REGISTERS, "base_x", "base_y"))
