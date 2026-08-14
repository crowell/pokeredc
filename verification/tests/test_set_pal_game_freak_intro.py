from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.rom import (
    collect_returns,
    linked_bytes,
    rom_window,
    sm83_flags_to_z80,
    symbol_location,
    z80_flags_to_sm83,
)
from verification.harness.sm83_shims import Sm83StoreAImmediate


ROOT = Path(__file__).resolve().parents[2]
VERIFY = ROOT / "verification"
NATIVE_ELF = VERIFY / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
GB_STACK = 0xD000
GB_RETURN = 0xFFFF
NATIVE_STATE = 0x100000
REGISTERS = ("a", "f", "b", "c", "d", "e", "h", "l")


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
    default_palette_command: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _assembly_endpoint(symbol: str, inputs: dict[str, claripy.ast.BV]) -> Endpoint:
    location = symbol_location(SYMBOLS, symbol)
    default_palette_command = symbol_location(
        SYMBOLS, "wDefaultPaletteCommand"
    ).address
    # The single absolute store `ld [wDefaultPaletteCommand], a` (opcode EA) is
    # not decoded by the Z80 P-code engine, so model it explicitly. It sits at
    # offset 8 of the 12-byte body (ld hl; ld de; ld a; ld [a16],a; ret).
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
    project.hook(
        location.address + 8,
        Sm83StoreAImmediate(
            address=default_palette_command,
            next_address=location.address + 11,
        ),
        length=3,
    )
    state = project.factory.blank_state(addr=location.address)
    for register in REGISTERS:
        value = inputs[register]
        if register == "f":
            value = sm83_flags_to_z80(value)
        setattr(state.regs, register, value)
    state.memory.store(default_palette_command, inputs["default_palette_command"])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    assert len(returned) == 1
    end = returned[0]
    return Endpoint(
        a=end.regs.a,
        f=z80_flags_to_sm83(end.regs.f),
        b=end.regs.b,
        c=end.regs.c,
        d=end.regs.d,
        e=end.regs.e,
        h=end.regs.h,
        l=end.regs.l,
        default_palette_command=end.memory.load(default_palette_command, 1),
        constraints=tuple(end.solver.constraints),
    )


def _native_endpoint(c_symbol: str, inputs: dict[str, claripy.ast.BV]) -> Endpoint:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(c_symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    for offset, register in enumerate(REGISTERS):
        state.memory.store(NATIVE_STATE + offset, inputs[register])
    state.memory.store(NATIVE_STATE + 8, inputs["default_palette_command"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    end = manager.deadended[0]
    values = {
        register: end.memory.load(NATIVE_STATE + offset, 1)
        for offset, register in enumerate(REGISTERS)
    }
    return Endpoint(
        **values,
        default_palette_command=end.memory.load(NATIVE_STATE + 8, 1),
        constraints=tuple(end.solver.constraints),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_set_pal_game_freak_intro_symbolic_equivalence() -> None:
    inputs = {
        name: (
            claripy.Concat(claripy.BVS("gfi_flags", 4), claripy.BVV(0, 4))
            if name == "f"
            else claripy.BVS(f"gfi_{name}", 8)
        )
        for name in (*REGISTERS, "default_palette_command")
    }
    assert_pathwise_equivalent(
        [_assembly_endpoint("SetPal_GameFreakIntro", inputs)],
        [_native_endpoint("port_set_pal_game_freak_intro", inputs)],
        (*REGISTERS, "default_palette_command"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_set_pal_game_freak_intro_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "SetPal_GameFreakIntro")
    hl_addr = symbol_location(SYMBOLS, "PalPacket_GameFreakIntro").address
    de_addr = symbol_location(SYMBOLS, "BlkPacket_GameFreakIntro").address
    command_addr = symbol_location(SYMBOLS, "wDefaultPaletteCommand").address
    assert linked_bytes(ROM, location, 12) == bytes(
        (
            0x21,
            hl_addr & 0xFF,
            hl_addr >> 8,
            0x11,
            de_addr & 0xFF,
            de_addr >> 8,
            0x3E,
            0x08,  # SET_PAL_GENERIC
            0xEA,
            command_addr & 0xFF,
            command_addr >> 8,
            0xC9,
        )
    )
