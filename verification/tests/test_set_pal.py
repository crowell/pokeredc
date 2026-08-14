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
from verification.harness.rom import (
    collect_returns,
    linked_bytes,
    rom_window,
    symbol_location,
)


ROOT = Path(__file__).resolve().parents[2]
VERIFY = ROOT / "verification"
NATIVE_ELF = VERIFY / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
GB_STACK = 0xD000
GB_RETURN = 0xFFFF
NATIVE_STATE = 0x100000

PORTS = (
    ("SetPal_BattleBlack", "port_set_pal_battle_black"),
    ("SetPal_TownMap", "port_set_pal_town_map"),
    ("SetPal_PartyMenu", "port_set_pal_party_menu"),
    ("SetPal_Slots", "port_set_pal_slots"),
    ("SetPal_TitleScreen", "port_set_pal_title_screen"),
    ("SetPal_Generic", "port_set_pal_generic"),
    ("SetPal_NidorinoIntro", "port_set_pal_nidorino_intro"),
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
    constraints: tuple[claripy.ast.Bool, ...]


def _assembly(symbol: str, inputs: dict[str, claripy.ast.BV]) -> Endpoint:
    location = symbol_location(SYMBOLS, symbol)
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
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    assert len(returned) == 1
    end = returned[0]
    return Endpoint(
        **assembly_registers(end), constraints=tuple(end.solver.constraints)
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
        constraints=tuple(end.solver.constraints),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("symbol,c_symbol", PORTS)
def test_set_pal_symbolic_equivalence(symbol: str, c_symbol: str) -> None:
    inputs = symbolic_registers(symbol.lower())
    assert_pathwise_equivalent(
        [_assembly(symbol, inputs)], [_native(c_symbol, inputs)], REGISTERS
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "packet_hl", "packet_de"),
    [
        ("SetPal_BattleBlack", "PalPacket_Black", "BlkPacket_Battle"),
        ("SetPal_TownMap", "PalPacket_TownMap", "BlkPacket_WholeScreen"),
        ("SetPal_PartyMenu", "PalPacket_PartyMenu", "wPartyMenuBlkPacket"),
        ("SetPal_Slots", "PalPacket_Slots", "BlkPacket_Slots"),
        ("SetPal_TitleScreen", "PalPacket_Titlescreen", "BlkPacket_Titlescreen"),
        ("SetPal_Generic", "PalPacket_Generic", "BlkPacket_WholeScreen"),
        ("SetPal_NidorinoIntro", "PalPacket_NidorinoIntro", "BlkPacket_NidorinoIntro"),
    ],
)
def test_set_pal_exact_linked_body(
    symbol: str, packet_hl: str, packet_de: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    hl_addr = symbol_location(SYMBOLS, packet_hl).address
    de_addr = symbol_location(SYMBOLS, packet_de).address
    # ld hl, <hl>; ld de, <de>; ret
    expected = bytes(
        (
            0x21,
            hl_addr & 0xFF,
            hl_addr >> 8,
            0x11,
            de_addr & 0xFF,
            de_addr >> 8,
            0xC9,
        )
    )
    assert linked_bytes(ROM, location, 7) == expected
