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
W_BATTLE_MON_SPECIES = 0xD014
W_ENEMY_MON_SPECIES = 0xCFE5
W_CHANGE_MON_PIC_ENEMY_TURN_SPECIES = 0xCEE9
W_CHANGE_MON_PIC_PLAYER_TURN_SPECIES = 0xCEEA

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
    player: claripy.ast.BV
    enemy: claripy.ast.BV
    out_player: claripy.ast.BV
    out_enemy: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]

class LoadMemoryA(angr.SimProcedure):
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

class ContinuationBoundary(angr.SimProcedure):
    def run(self) -> None:
        self.inhibit_autoret = True
        self.successors.add_successor(self.state.copy(), DONE, claripy.BoolV(True), "Ijk_Boring")

def _endpoint(state: angr.SimState, memory_base: int, register_base: int, assembly: bool) -> Endpoint:
    return Endpoint(**(assembly_registers(state) if assembly else native_registers(state, register_base)), player=state.memory.load(memory_base + W_BATTLE_MON_SPECIES, 1), enemy=state.memory.load(memory_base + W_ENEMY_MON_SPECIES, 1), out_player=state.memory.load(memory_base + W_CHANGE_MON_PIC_PLAYER_TURN_SPECIES, 1), out_enemy=state.memory.load(memory_base + W_CHANGE_MON_PIC_ENEMY_TURN_SPECIES, 1), constraints=tuple(state.solver.constraints))

def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "AnimationFlashMonPic")
    continuation = symbol_location(SYMBOLS, "ChangeMonPic")
    project = angr.Project(rom_window(ROM, location.bank), auto_load_libs=False, rebase_granularity=0x100, main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":location.address})
    project.hook(location.address, LoadMemoryA(W_BATTLE_MON_SPECIES, location.address + 3), length=3)
    project.hook(location.address + 3, StoreA(W_CHANGE_MON_PIC_PLAYER_TURN_SPECIES, location.address + 6), length=3)
    project.hook(location.address + 6, LoadMemoryA(W_ENEMY_MON_SPECIES, location.address + 9), length=3)
    project.hook(location.address + 9, StoreA(W_CHANGE_MON_PIC_ENEMY_TURN_SPECIES, location.address + 12), length=3)
    project.hook(continuation.address, ContinuationBoundary(), length=1)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    for addr,key in ((W_BATTLE_MON_SPECIES,"player"),(W_ENEMY_MON_SPECIES,"enemy")):
        state.memory.store(addr, values[key])
    manager = project.factory.simulation_manager(state); manager.explore(find=DONE, num_find=1)
    assert not manager.errored
    return [_endpoint(end, 0, 0, True) for end in manager.found]

def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False); function = project.loader.find_symbol("port_animation_flash_mon_pic"); assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY); store_native_registers(state, NATIVE_STATE, values)
    for addr,key in ((W_BATTLE_MON_SPECIES,"player"),(W_ENEMY_MON_SPECIES,"enemy")):
        state.memory.store(NATIVE_MEMORY + addr, values[key])
    manager = project.factory.simulation_manager(state); manager.run(); assert not manager.errored
    return [_endpoint(end, NATIVE_MEMORY, NATIVE_STATE, False) for end in manager.deadended]

@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_animation_flash_mon_pic_entry_pathwise_equivalence() -> None:
    values = symbolic_registers("animation_flash_mon_pic")
    values["player"] = claripy.BVS("flash_mon_player_species", 8)
    values["enemy"] = claripy.BVS("flash_mon_enemy_species", 8)
    assert_pathwise_equivalent(_assembly(values), _native(values), (*REGISTERS, "player", "enemy", "out_player", "out_enemy"))
