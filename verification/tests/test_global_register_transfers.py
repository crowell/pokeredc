from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS, assembly_registers, native_registers, set_assembly_registers, store_native_registers, symbolic_registers
from verification.harness.rom import collect_returns, linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import Sm83AndImmediate, Sm83BitRegister, Sm83LoadAImmediate, Sm83StoreAImmediate

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
STACK = 0xD000
RETURN = 0xFFFF
NATIVE_STATE = 0x100000

CASES = (
    ("GetPartyMonName2", "port_get_party_mon_name2", ("wWhichPokemon",)),
    ("SetMapTextPointer", "port_set_map_text_pointer", ("wCurMapTextPtr", "wCurMapTextPtr+1", "hSavedMapTextPtr", "hSavedMapTextPtr+1")),
    ("SaveEndBattleTextPointers", "port_save_end_battle_text_pointers", ("hLoadedROMBank", "wEndBattleTextRomBank", "wEndBattleWinTextPointer", "wEndBattleWinTextPointer+1", "wEndBattleLoseTextPointer", "wEndBattleLoseTextPointer+1")),
    ("GetSavedEndBattleTextPointer", "port_get_saved_end_battle_text_pointer", ("wBattleResult", "wEndBattleWinTextPointer", "wEndBattleWinTextPointer+1", "wEndBattleLoseTextPointer", "wEndBattleLoseTextPointer+1")),
    ("GetPredefRegisters", "port_get_predef_registers", ("wPredefHL", "wPredefHL+1", "wPredefDE", "wPredefDE+1", "wPredefBC", "wPredefBC+1")),
    ("ResetSpriteBufferPointers", "port_reset_sprite_buffer_pointers", ("wSpriteLoadFlags", "wSpriteOutputPtr", "wSpriteOutputPtr+1", "wSpriteOutputPtrCached", "wSpriteOutputPtrCached+1")),
)


def address(name: str) -> int:
    if name.endswith("+1"):
        return symbol_location(SYMBOLS, name[:-2]).address + 1
    return symbol_location(SYMBOLS, name).address


@dataclass(frozen=True)
class Endpoint:
    a: claripy.ast.BV; f: claripy.ast.BV; b: claripy.ast.BV; c: claripy.ast.BV
    d: claripy.ast.BV; e: claripy.ast.BV; h: claripy.ast.BV; l: claripy.ast.BV
    memory: claripy.ast.BV; continuation: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def assembly(symbol: str, names: tuple[str, ...], inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, symbol)
    addresses = tuple(address(name) for name in names)
    project = angr.Project(rom_window(ROM, location.bank), auto_load_libs=False, rebase_granularity=0x100, main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0, "entry_point": location.address})
    hooks: list[tuple[int, type[angr.SimProcedure], int, int]] = []
    tail = None
    if symbol == "GetPartyMonName2":
        hooks = [(0, Sm83LoadAImmediate, addresses[0], 3)]
        tail = symbol_location(SYMBOLS, "GetPartyMonName").address
    elif symbol == "SetMapTextPointer":
        for offset, index, size in ((0, 0, 3), (3, 2, 2), (5, 1, 3), (8, 3, 2), (11, 0, 3), (15, 1, 3)):
            hooks.append((offset, Sm83LoadAImmediate if offset in (0, 5) else Sm83StoreAImmediate, addresses[index], offset + size))
    elif symbol == "SaveEndBattleTextPointers":
        for offset, index, size in ((0, 0, 2), (2, 1, 3), (6, 2, 3), (10, 3, 3), (14, 4, 3), (18, 5, 3)):
            hooks.append((offset, Sm83LoadAImmediate if offset == 0 else Sm83StoreAImmediate, addresses[index], offset + size))
    elif symbol == "GetSavedEndBattleTextPointer":
        for offset, index in ((0, 0), (6, 1), (10, 2), (15, 3), (19, 4)):
            hooks.append((offset, Sm83LoadAImmediate, addresses[index], offset + 3))
        project.hook(location.address + 3, Sm83AndImmediate(0xFF, location.address + 4), length=1)
    elif symbol == "GetPredefRegisters":
        for offset, index in ((0, 0), (4, 1), (8, 2), (12, 3), (16, 4), (20, 5)):
            hooks.append((offset, Sm83LoadAImmediate, addresses[index], offset + 3))
    else:
        hooks.append((0, Sm83LoadAImmediate, addresses[0], 3))
        project.hook(location.address + 3, Sm83BitRegister(0, "a", location.address + 5), length=2)
        for offset, index in ((22, 1), (26, 2), (30, 3), (34, 4)):
            hooks.append((offset, Sm83StoreAImmediate, addresses[index], offset + 3))
    for offset, procedure, target, next_offset in hooks:
        project.hook(location.address + offset, procedure(target, location.address + next_offset), length=next_offset - offset)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    for index, target in enumerate(addresses):
        state.memory.store(target, inputs[f"memory{index}"])
    if tail is None:
        state.regs.sp = STACK
        state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
        ends = collect_returns(project, state, RETURN)
    else:
        manager = project.factory.simulation_manager(state)
        manager.explore(find=tail)
        assert not manager.errored and len(manager.found) == 1
        ends = manager.found
    return [Endpoint(**assembly_registers(end), memory=claripy.Concat(*(end.memory.load(target, 1) for target in addresses)), continuation=claripy.BVV(1, 8), constraints=tuple(end.solver.constraints)) for end in ends]


def native(c_symbol: str, count: int, inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(c_symbol)
    assert function
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    for index in range(count):
        state.memory.store(NATIVE_STATE + 8 + index, inputs[f"memory{index}"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and manager.deadended
    return [Endpoint(**native_registers(end, NATIVE_STATE), memory=end.memory.load(NATIVE_STATE + 8, count), continuation=claripy.BVV(1, 8), constraints=tuple(end.solver.constraints)) for end in manager.deadended]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.parametrize("symbol,c_symbol,names", CASES)
def test_equivalence(symbol: str, c_symbol: str, names: tuple[str, ...]) -> None:
    inputs = symbolic_registers(symbol.lower())
    for index in range(len(names)):
        inputs[f"memory{index}"] = claripy.BVS(f"{symbol}_memory{index}", 8)
    assert_pathwise_equivalent(assembly(symbol, names, inputs), native(c_symbol, len(names), inputs), (*REGISTERS, "memory", "continuation"))


def test_exact_bodies() -> None:
    bodies = {
        "GetPartyMonName2": "fa92cf21b5d2",
        "SetMapTextPointer": "fa6cd3e0ecfa6dd3e0ed7dea6cd37cea6dd3c9",
        "SaveEndBattleTextPointers": "f0b8ea92d07cea8cd07dea8dd07aea8ed07bea8fd0c9",
        "GetSavedEndBattleTextPointer": "fa0bcfa72009fa8cd067fa8dd06fc9fa8ed067fa8fd06fc9",
        "GetPredefRegisters": "fa4fcc67fa50cc6ffa51cc57fa52cc5ffa53cc47fa54cc4fc9",
        "ResetSpriteBufferPointers": "faa8d0cb4720081188a12110a318061110a32188a17deaadd07ceaaed07beaafd07aeab0d0c9",
    }
    for symbol, body in bodies.items():
        expected = bytes.fromhex(body)
        assert linked_bytes(ROM, symbol_location(SYMBOLS, symbol), len(expected)) == expected
