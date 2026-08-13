from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS, assembly_registers, native_registers, set_assembly_registers, store_native_registers, symbolic_registers
from verification.harness.rom import linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import Sm83LoadAHighImmediate, Sm83LoadAImmediate

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification" / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
CASES = (
    ("GetPlayerAnimationType", "wPlayerMoveEffect", "PlayPlayerMoveAnimation", "port_get_player_animation_type", bytes.fromhex("a73e0428023e05")),
    ("GetEnemyAnimationType", "wEnemyMoveEffect", "PlayEnemyMoveAnimation", "port_get_enemy_animation_type", bytes.fromhex("a73e0128083e021804")),
)


@dataclass(frozen=True)
class Endpoint:
    a: claripy.ast.BV; f: claripy.ast.BV; b: claripy.ast.BV; c: claripy.ast.BV
    d: claripy.ast.BV; e: claripy.ast.BV; h: claripy.ast.BV; l: claripy.ast.BV
    effect: claripy.ast.BV; continuation: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def assembly(symbol: str, memory_symbol: str, tail_symbol: str, inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, symbol)
    memory = symbol_location(SYMBOLS, memory_symbol).address
    tail = symbol_location(SYMBOLS, tail_symbol).address
    project = angr.Project(rom_window(ROM, location.bank), auto_load_libs=False, rebase_granularity=0x100, main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0, "entry_point": location.address})
    project.hook(location.address, Sm83LoadAImmediate(memory, location.address + 3), length=3)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    state.memory.store(memory, inputs["effect"])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=tail, num_find=2)
    assert not manager.errored and manager.found
    return [Endpoint(**assembly_registers(end), effect=end.memory.load(memory, 1), continuation=claripy.BVV(1, 8), constraints=tuple(end.solver.constraints)) for end in manager.found]


def native(c_symbol: str, inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(c_symbol)
    assert function
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["effect"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and manager.deadended
    return [Endpoint(**native_registers(end, NATIVE_STATE), effect=end.memory.load(NATIVE_STATE + 8, 1), continuation=claripy.BVV(1, 8), constraints=tuple(end.solver.constraints)) for end in manager.deadended]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.parametrize("symbol,memory_symbol,tail_symbol,c_symbol,_suffix", CASES)
def test_animation_type_entry_equivalence(symbol: str, memory_symbol: str, tail_symbol: str, c_symbol: str, _suffix: bytes) -> None:
    inputs = symbolic_registers(symbol.lower())
    inputs["effect"] = claripy.BVS(f"{symbol}_effect", 8)
    assert_pathwise_equivalent(assembly(symbol, memory_symbol, tail_symbol, inputs), native(c_symbol, inputs), (*REGISTERS, "effect", "continuation"))


@pytest.mark.parametrize("symbol,memory_symbol,_tail_symbol,_c_symbol,suffix", CASES)
def test_animation_type_entry_exact_body(symbol: str, memory_symbol: str, _tail_symbol: str, _c_symbol: str, suffix: bytes) -> None:
    location = symbol_location(SYMBOLS, symbol)
    memory = symbol_location(SYMBOLS, memory_symbol).address
    expected = bytes((0xfa, memory & 0xff, memory >> 8)) + suffix
    assert linked_bytes(ROM, location, len(expected)) == expected


def hide_assembly(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "AnimationHideMonPic")
    memory = symbol_location(SYMBOLS, "hWhoseTurn").address
    tail = symbol_location(SYMBOLS, "ClearMonPicFromTileMap").address
    project = angr.Project(rom_window(ROM, location.bank), auto_load_libs=False, rebase_granularity=0x100, main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0, "entry_point": location.address})
    project.hook(location.address, Sm83LoadAHighImmediate(memory, location.address + 2), length=2)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    state.memory.store(memory, inputs["effect"])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=tail, num_find=2)
    assert not manager.errored and manager.found
    return [Endpoint(**assembly_registers(end), effect=end.memory.load(memory, 1), continuation=claripy.BVV(1, 8), constraints=tuple(end.solver.constraints)) for end in manager.found]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
def test_animation_hide_mon_pic_entry_equivalence() -> None:
    inputs = symbolic_registers("animation_hide_mon_pic")
    inputs["effect"] = claripy.BVS("hide_mon_whose_turn", 8)
    assert_pathwise_equivalent(hide_assembly(inputs), native("port_animation_hide_mon_pic", inputs), (*REGISTERS, "effect", "continuation"))


def test_animation_hide_mon_pic_entry_exact_body() -> None:
    location = symbol_location(SYMBOLS, "AnimationHideMonPic")
    memory = symbol_location(SYMBOLS, "hWhoseTurn").address
    expected = bytes((0xf0, memory & 0xff)) + bytes.fromhex("a728043e0c18023e65")
    assert linked_bytes(ROM, location, len(expected)) == expected
