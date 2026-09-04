"""Proof for AnimateIntroNidorino's table loop and frame updates."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import assembly_registers, native_registers, set_assembly_registers, store_native_registers
from verification.harness.rom import collect_returns, linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import Sm83StoreAImmediate

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF
TABLE = 0x5910
H_VBLANK_OCCURRED = 0xFFD6
H_SCX = 0xFFAE
H_FRAMECOUNTER = 0xFFD5
H_JOY5 = 0xFFB6
W_BASE_COORD_X = 0xD081
W_BASE_COORD_Y = 0xD082
W_INTRO_NIDORINO_BASE_TILE = 0xD09F
W_SHADOW_OAM = 0xC300
OAM_SIZE = 144
STACK = 0x9000
EXPECTED = bytes.fromhex("1afe50c8ea82d0131aea81d0d50e24cdae570e05cd3937d11318e5")


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
    oam: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def return_from_call(state: angr.SimState) -> int:
    stack = state.solver.eval(state.regs.sp)
    target = state.solver.eval(state.memory.load(stack, 2, endness="Iend_LE"))
    state.regs.sp = claripy.BVV((stack + 2) & 0xFFFF, 16)
    return target


class UpdateIntroNidorinoOAM(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        state = self.state
        base_tile = state.memory.load(W_INTRO_NIDORINO_BASE_TILE, 1)
        for index in range(36):
            offset = W_SHADOW_OAM + index * 4
            state.memory.store(
                offset,
                state.memory.load(W_BASE_COORD_Y, 1) + state.memory.load(offset, 1),
            )
            state.memory.store(
                offset + 1,
                state.memory.load(W_BASE_COORD_X, 1) + state.memory.load(offset + 1, 1),
            )
            state.memory.store(offset + 2, base_tile + index)
        state.regs.a = base_tile + 35
        state.regs.f = claripy.BVV(0xC0, 8)
        state.regs.c = claripy.BVV(0, 8)
        state.regs.d = base_tile + 36
        state.regs.h = claripy.BVV(0xC3, 8)
        state.regs.l = claripy.BVV(0x90, 8)
        self.jump(return_from_call(state))


class DelayFrames(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x50, 8)
        self.state.regs.c = claripy.BVV(0, 8)
        self.jump(return_from_call(self.state))


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_animate_intro_nidorino_pathwise_equivalence() -> None:
    location = symbol_location(SYMBOLS, "AnimateIntroNidorino")
    project = angr.Project(
        rom_window(ROM, location.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0, "entry_point": location.address},
    )
    project.hook(symbol_location(SYMBOLS, "UpdateIntroNidorinoOAM").address, UpdateIntroNidorinoOAM(), length=1)
    project.hook(location.address + 4, Sm83StoreAImmediate(W_BASE_COORD_Y, location.address + 7), length=3)
    project.hook(location.address + 9, Sm83StoreAImmediate(W_BASE_COORD_X, location.address + 12), length=3)
    project.hook(symbol_location(SYMBOLS, "DelayFrames").address, DelayFrames(), length=1)
    state = project.factory.blank_state(addr=location.address)
    values = {
        "a": claripy.BVV(0x12, 8),
        "f": claripy.BVV(0x10, 8),
        "b": claripy.BVV(0x34, 8),
        "c": claripy.BVV(0x56, 8),
        "d": claripy.BVV(TABLE >> 8, 8),
        "e": claripy.BVV(TABLE, 8),
        "h": claripy.BVV(0x78, 8),
        "l": claripy.BVV(0x9A, 8),
    }
    set_assembly_registers(state, values)
    state.memory.store(W_INTRO_NIDORINO_BASE_TILE, claripy.BVV(0x40, 8))
    state.memory.store(W_SHADOW_OAM, claripy.BVV(0, OAM_SIZE * 8), endness="Iend_BE")
    state.memory.store(STACK, claripy.BVV(DONE, 16), endness="Iend_LE")
    state.regs.sp = STACK
    assembly = collect_returns(project, state, DONE)
    assembly_endpoints = [
        Endpoint(
            **assembly_registers(end),
            base_x=end.memory.load(W_BASE_COORD_X, 1),
            base_y=end.memory.load(W_BASE_COORD_Y, 1),
            oam=end.memory.load(W_SHADOW_OAM, OAM_SIZE),
            constraints=tuple(end.solver.constraints),
        )
        for end in assembly
    ]

    native = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = native.loader.find_symbol("port_animate_intro_nidorino")
    assert function is not None
    native_state = native.factory.call_state(
        function.rebased_addr,
        NATIVE_STATE,
        NATIVE_MEMORY,
        NATIVE_MEMORY + TABLE,
    )
    store_native_registers(native_state, NATIVE_STATE, values)
    native_state.memory.store(NATIVE_MEMORY + W_INTRO_NIDORINO_BASE_TILE, claripy.BVV(0x40, 8))
    native_state.memory.store(NATIVE_MEMORY + W_SHADOW_OAM, claripy.BVV(0, OAM_SIZE * 8), endness="Iend_BE")
    table = bytes.fromhex("0000fe02ff020102020250")
    native_state.memory.store(NATIVE_MEMORY + TABLE, claripy.BVV(table))
    for address in (H_VBLANK_OCCURRED, H_SCX, H_FRAMECOUNTER, H_JOY5):
        native_state.memory.store(NATIVE_MEMORY + address, claripy.BVV(0, 8))
    manager = native.factory.simulation_manager(native_state)
    manager.run()
    assert not manager.errored
    native_endpoints = [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            base_x=end.memory.load(NATIVE_MEMORY + W_BASE_COORD_X, 1),
            base_y=end.memory.load(NATIVE_MEMORY + W_BASE_COORD_Y, 1),
            oam=end.memory.load(NATIVE_MEMORY + W_SHADOW_OAM, OAM_SIZE),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]
    assert_pathwise_equivalent(
        assembly_endpoints,
        native_endpoints,
        ("a", "f", "b", "c", "d", "e", "h", "l", "base_x", "base_y", "oam"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_animate_intro_nidorino_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "AnimateIntroNidorino")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
