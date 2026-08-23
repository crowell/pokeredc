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
from verification.harness.rom import linked_bytes, rom_window, symbol_location


ROOT = Path(__file__).resolve().parents[2]
VERIFY = ROOT / "verification"
NATIVE_ELF = VERIFY / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000

PORTS = (
    (
        "CopyToStringBuffer",
        "CopyString",
        "port_copy_to_string_buffer",
        bytes.fromhex("214bcf"),
    ),
    (
        "RunDefaultPaletteCommand",
        "RunPaletteCommand",
        "port_run_default_palette_command",
        bytes.fromhex("06ff"),
    ),
    (
        "GetPointerWithinSpriteStateData1",
        "_GetPointerWithinSpriteStateData",
        "port_get_pointer_within_sprite_state_data1",
        bytes.fromhex("26c11802"),
    ),
    (
        "GetPointerWithinSpriteStateData2",
        "_GetPointerWithinSpriteStateData",
        "port_get_pointer_within_sprite_state_data2",
        bytes.fromhex("26c2"),
    ),
    (
        "IsSpriteInFrontOfPlayer",
        "IsSpriteInFrontOfPlayer2",
        "port_is_sprite_in_front_of_player",
        bytes.fromhex("1610"),
    ),
    (
        "ChangeFacingDirection",
        "TryWalking",
        "port_change_facing_direction",
        bytes.fromhex("110000"),
    ),
    (
        "IntroCopyTiles",
        "CopyTileIDsFromList_ZeroBaseTileID",
        "port_intro_copy_tiles",
        bytes.fromhex("2139c4"),
    ),
    ("AIUsePotion", "AIRecoverHP", "port_ai_use_potion", bytes.fromhex("3e140614180a")),
    ("AIUseSuperPotion", "AIRecoverHP", "port_ai_use_super_potion", bytes.fromhex("3e1306321804")),
    ("AIUseHyperPotion", "AIRecoverHP", "port_ai_use_hyper_potion", bytes.fromhex("3e1206c8")),
    ("AIUseXAttack", "AIIncreaseStat", "port_ai_use_x_attack", bytes.fromhex("060a3e411810")),
    ("AIUseXDefend", "AIIncreaseStat", "port_ai_use_x_defend", bytes.fromhex("060b3e42180a")),
    ("AIUseXSpeed", "AIIncreaseStat", "port_ai_use_x_speed", bytes.fromhex("060c3e431804")),
    ("AIUseXSpecial", "AIIncreaseStat", "port_ai_use_x_special", bytes.fromhex("060d3e44")),
    ("GetSpriteScreenYPointer", "GetSpriteScreenXYPointerCommon", "port_get_sprite_screen_y_pointer", bytes.fromhex("3e04471803")),
    ("GetSpriteScreenXPointer", "GetSpriteScreenXYPointerCommon", "port_get_sprite_screen_x_pointer", bytes.fromhex("3e0647")),
)


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
    continuation: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _assembly(symbol: str, tail_symbol: str, inputs: dict[str, claripy.ast.BV]) -> Endpoint:
    location = symbol_location(SYMBOLS, symbol)
    tail = symbol_location(SYMBOLS, tail_symbol).address
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
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=tail)
    assert not manager.errored
    assert len(manager.found) == 1
    end = manager.found[0]
    return Endpoint(
        **assembly_registers(end),
        continuation=claripy.BVV(1, 8),
        constraints=tuple(end.solver.constraints),
    )


def _native(c_symbol: str, inputs: dict[str, claripy.ast.BV]) -> Endpoint:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(c_symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    end = manager.deadended[0]
    return Endpoint(
        **native_registers(end, NATIVE_STATE),
        continuation=claripy.BVV(1, 8),
        constraints=tuple(end.solver.constraints),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("symbol,tail_symbol,c_symbol,_code", PORTS)
def test_register_tail_entry_symbolic_equivalence(
    symbol: str, tail_symbol: str, c_symbol: str, _code: bytes
) -> None:
    inputs = symbolic_registers(symbol.lower())
    assert_pathwise_equivalent(
        [_assembly(symbol, tail_symbol, inputs)],
        [_native(c_symbol, inputs)],
        (*REGISTERS, "continuation"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("symbol,_tail_symbol,_c_symbol,code", PORTS)
def test_register_tail_entry_exact_linked_body(
    symbol: str, _tail_symbol: str, _c_symbol: str, code: bytes
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, len(code)) == code
