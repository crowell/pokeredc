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
    safari_zone_game_over: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _assembly_endpoint(symbol: str, inputs: dict[str, claripy.ast.BV]) -> Endpoint:
    location = symbol_location(SYMBOLS, symbol)
    game_over = symbol_location(SYMBOLS, "wSafariZoneGameOver").address
    # The absolute store `ld [wSafariZoneGameOver], a` (opcode EA) is not
    # decoded by the Z80 P-code engine, so model it explicitly. It sits at
    # offset 1 of the 5-byte body (xor a; ld [a16],a; ret).
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
        location.address + 1,
        Sm83StoreAImmediate(address=game_over, next_address=location.address + 4),
        length=3,
    )
    state = project.factory.blank_state(addr=location.address)
    for register in REGISTERS:
        value = inputs[register]
        if register == "f":
            value = sm83_flags_to_z80(value)
        setattr(state.regs, register, value)
    state.memory.store(game_over, inputs["safari_zone_game_over"])
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
        safari_zone_game_over=end.memory.load(game_over, 1),
        constraints=tuple(end.solver.constraints),
    )


def _native_endpoint(c_symbol: str, inputs: dict[str, claripy.ast.BV]) -> Endpoint:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(c_symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    for offset, register in enumerate(REGISTERS):
        state.memory.store(NATIVE_STATE + offset, inputs[register])
    state.memory.store(NATIVE_STATE + 8, inputs["safari_zone_game_over"])
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
        safari_zone_game_over=end.memory.load(NATIVE_STATE + 8, 1),
        constraints=tuple(end.solver.constraints),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_safari_zone_game_still_going_symbolic_equivalence() -> None:
    inputs = {
        name: (
            claripy.Concat(claripy.BVS("sz_flags", 4), claripy.BVV(0, 4))
            if name == "f"
            else claripy.BVS(f"sz_{name}", 8)
        )
        for name in (*REGISTERS, "safari_zone_game_over")
    }
    assert_pathwise_equivalent(
        [_assembly_endpoint("SafariZoneGameStillGoing", inputs)],
        [_native_endpoint("port_safari_zone_game_still_going", inputs)],
        (*REGISTERS, "safari_zone_game_over"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_safari_zone_game_still_going_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "SafariZoneGameStillGoing")
    game_over = symbol_location(SYMBOLS, "wSafariZoneGameOver").address
    # xor a; ld [wSafariZoneGameOver], a; ret
    assert linked_bytes(ROM, location, 5) == bytes(
        (0xAF, 0xEA, game_over & 0xFF, game_over >> 8, 0xC9)
    )
