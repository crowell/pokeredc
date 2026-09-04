"""Proof for PlayIntroScene's setup and first-interruption path."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
    assembly_registers,
    native_registers,
    set_assembly_registers,
    store_native_registers,
)
from verification.harness.rom import (
    collect_returns,
    linked_bytes,
    rom_window,
    sm83_flags_to_z80,
    symbol_location,
)
from verification.harness.sm83_shims import (
    Sm83CpImmediate,
    Sm83IncRegister,
    Sm83LoadABytePreserveF,
    Sm83LoadAFromRegister,
    Sm83LoadAHighImmediate,
    Sm83StoreAHighImmediate,
    Sm83StoreAImmediate,
    Sm83XorA,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0x9000
DONE = 0xEFFF
RUN_PALETTE_COMMAND = 0x3DEF
INTRO_COPY_TILES = 0x583F
INIT_INTRO_NIDORINO_OAM = 0x57C7
UPDATE_INTRO_NIDORINO_OAM = 0x57AE
CHECK_FOR_USER_INTERRUPTION = 0x12F8
H_JOY_HELD = 0xFFB4
H_JOY_PRESSED = 0xFFB3
H_JOY5 = 0xFFB5
H_JOY6 = 0xFFB6
H_JOY7 = 0xFFB7
W_INTRO_NIDORINO_BASE_TILE = 0xD09F
H_FRAMECOUNTER = 0xFFD5
H_SCX = 0xFFAE
H_VBLANK_OCCURRED = 0xFFD6
W_ON_SGB = 0xCF1B
W_BASE_COORD_X = 0xD081
W_BASE_COORD_Y = 0xD082
W_SHADOW_OAM = 0xC300
OAM_SIZE = 144
EXPECTED = bytes.fromhex(
    "0607cdef3d3ee4e047e048e049afe0ae0603cd3f583e00ea81d03e50ea82d0010606cdc75711ff28cd0e58d8"
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
    scx: claripy.ast.BV
    base_x: claripy.ast.BV
    base_y: claripy.ast.BV
    bgp: claripy.ast.BV
    obp0: claripy.ast.BV
    obp1: claripy.ast.BV
    joy_held: claripy.ast.BV
    joy5: claripy.ast.BV
    frame_counter: claripy.ast.BV
    oam: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def return_from_call(state: angr.SimState) -> int:
    stack = state.solver.eval(state.regs.sp)
    target = state.solver.eval(state.memory.load(stack, 2, endness="Iend_LE"))
    state.regs.sp = claripy.BVV((stack + 2) & 0xFFFF, 16)
    return target


class RunPaletteCommand(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0xA0, 8))
        self.jump(return_from_call(self.state))


class IntroCopyTiles(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = claripy.BVV(0xC4, 8)
        self.state.regs.l = claripy.BVV(0x39, 8)
        self.jump(return_from_call(self.state))


class InitIntroNidorinoOAM(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        state = self.state
        base_y = state.memory.load(W_BASE_COORD_Y, 1)
        base_x = state.memory.load(W_BASE_COORD_X, 1)
        for column in range(6):
            for row in range(6):
                index = column * 6 + row
                offset = W_SHADOW_OAM + index * 4
                state.memory.store(offset, base_y + 8 * (row + 1))
                state.memory.store(offset + 1, base_x + 8 * column)
                state.memory.store(offset + 2, claripy.BVV(index, 8))
                state.memory.store(offset + 3, claripy.BVV(0x80, 8))
        state.memory.store(W_BASE_COORD_X, base_x + 48)
        state.regs.a = claripy.BVV(0x30, 8)
        state.regs.f = sm83_flags_to_z80(claripy.BVV(0xC0, 8))
        state.regs.b = claripy.BVV(0, 8)
        state.regs.c = claripy.BVV(6, 8)
        state.regs.d = claripy.BVV(36, 8)
        state.regs.e = base_y + 48
        state.regs.h = claripy.BVV(0xC3, 8)
        state.regs.l = claripy.BVV(0x90, 8)
        self.jump(return_from_call(state))


class UpdateIntroNidorinoOAM(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        state = self.state
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
            state.memory.store(offset + 2, claripy.BVV(index, 8))
        state.regs.a = claripy.BVV(35, 8)
        state.regs.f = sm83_flags_to_z80(claripy.BVV(0xC0, 8))
        state.regs.c = claripy.BVV(0, 8)
        state.regs.d = claripy.BVV(36, 8)
        state.regs.h = claripy.BVV(0xC3, 8)
        state.regs.l = claripy.BVV(0x90, 8)
        self.jump(return_from_call(state))


class CheckForUserInterruption(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        state = self.state
        state.memory.store(H_JOY5, claripy.BVV(0, 8))
        state.memory.store(H_FRAMECOUNTER, claripy.BVV(5, 8))
        state.regs.a = claripy.BVV(0x46, 8)
        state.regs.f = sm83_flags_to_z80(claripy.BVV(0x90, 8))
        self.jump(return_from_call(state))


class Jump(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__()
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.jump(self.target)


class BranchOnCarry(angr.SimProcedure):
    def __init__(self, taken: int, fallthrough: int) -> None:
        super().__init__()
        self.taken = taken
        self.fallthrough = fallthrough

    def run(self) -> None:  # type: ignore[override]
        target = self.taken if self.state.solver.is_true((self.state.regs.f & 0x10) != 0) else self.fallthrough
        self.jump(target)


class ReturnAfterMove(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(DONE)


def _endpoint(state: angr.SimState, base: int) -> Endpoint:
    registers = assembly_registers(state) if base == 0 else native_registers(state, NATIVE_STATE)
    return Endpoint(
        **registers,
        scx=state.memory.load(base + H_SCX, 1),
        base_x=state.memory.load(base + W_BASE_COORD_X, 1),
        base_y=state.memory.load(base + W_BASE_COORD_Y, 1),
        bgp=state.memory.load(base + 0xFF47, 1),
        obp0=state.memory.load(base + 0xFF48, 1),
        obp1=state.memory.load(base + 0xFF49, 1),
        joy_held=state.memory.load(base + H_JOY_HELD, 1),
        joy5=state.memory.load(base + H_JOY5, 1),
        frame_counter=state.memory.load(base + H_FRAMECOUNTER, 1),
        oam=state.memory.load(base + W_SHADOW_OAM, OAM_SIZE),
        constraints=tuple(state.solver.constraints),
    )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "PlayIntroScene")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
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
    move = symbol_location(SYMBOLS, "IntroMoveMon")
    project.hook(location.address + 5, Sm83LoadABytePreserveF(location.address + 6, location.address + 7), length=2)
    project.hook(location.address + 7, Sm83StoreAHighImmediate(0x47, location.address + 9), length=2)
    project.hook(location.address + 9, Sm83StoreAHighImmediate(0x48, location.address + 11), length=2)
    project.hook(location.address + 11, Sm83StoreAHighImmediate(0x49, location.address + 13), length=2)
    project.hook(location.address + 13, Sm83XorA(location.address + 14), length=1)
    project.hook(location.address + 14, Sm83StoreAHighImmediate(H_SCX & 0xFF, location.address + 16), length=2)
    project.hook(location.address + 21, Sm83LoadABytePreserveF(location.address + 22, location.address + 23), length=2)
    project.hook(location.address + 23, Sm83StoreAImmediate(W_BASE_COORD_X, location.address + 26), length=3)
    project.hook(location.address + 26, Sm83LoadABytePreserveF(location.address + 27, location.address + 28), length=2)
    project.hook(location.address + 28, Sm83StoreAImmediate(W_BASE_COORD_Y, location.address + 31), length=3)
    project.hook(RUN_PALETTE_COMMAND, RunPaletteCommand(), length=1)
    project.hook(INTRO_COPY_TILES, IntroCopyTiles(), length=1)
    project.hook(INIT_INTRO_NIDORINO_OAM, InitIntroNidorinoOAM(), length=1)
    project.hook(UPDATE_INTRO_NIDORINO_OAM, UpdateIntroNidorinoOAM(), length=1)
    project.hook(CHECK_FOR_USER_INTERRUPTION, CheckForUserInterruption(), length=1)
    project.hook(move.address, Sm83LoadAFromRegister("e", move.address + 1), length=1)
    project.hook(move.address + 1, Sm83CpImmediate(0xFF, move.address + 3), length=2)
    project.hook(move.address + 3, Jump(move.address + 0x0F), length=2)
    project.hook(move.address + 0x12, Sm83StoreAImmediate(W_BASE_COORD_X, move.address + 0x15), length=3)
    project.hook(move.address + 0x15, Sm83XorA(move.address + 0x16), length=1)
    project.hook(move.address + 0x16, Sm83StoreAImmediate(W_BASE_COORD_Y, move.address + 0x19), length=3)
    project.hook(
        move.address + 0x1F,
        Sm83LoadAHighImmediate(H_SCX & 0xFF, move.address + 0x21),
        length=2,
    )
    project.hook(move.address + 0x21, Sm83IncRegister("a", move.address + 0x22), length=1)
    project.hook(move.address + 0x22, Sm83IncRegister("a", move.address + 0x23), length=1)
    project.hook(move.address + 0x23, Sm83StoreAHighImmediate(H_SCX & 0xFF, move.address + 0x25), length=2)
    project.hook(move.address + 0x2E, BranchOnCarry(DONE, move.address + 0x30), length=2)
    project.hook(move.address + 0x30, ReturnAfterMove(), length=1)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    for address in (W_ON_SGB, H_JOY_PRESSED, H_JOY6, H_JOY7, H_VBLANK_OCCURRED, H_FRAMECOUNTER):
        state.memory.store(address, claripy.BVV(0, 8))
    state.memory.store(H_JOY_HELD, claripy.BVV(0x46, 8))
    state.memory.store(H_JOY5, claripy.BVV(0, 8))
    state.memory.store(H_SCX, claripy.BVV(0, 8))
    state.memory.store(W_BASE_COORD_X, claripy.BVV(0, 8))
    state.memory.store(W_BASE_COORD_Y, claripy.BVV(0, 8))
    state.memory.store(W_SHADOW_OAM, claripy.BVV(0, OAM_SIZE * 8), endness="Iend_BE")
    state.memory.store(W_INTRO_NIDORINO_BASE_TILE, claripy.BVV(0, 8))
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(DONE, 16), endness="Iend_LE")
    returned = collect_returns(project, state, DONE)
    return [_endpoint(end, 0) for end in returned]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_play_intro_scene")
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr,
        NATIVE_STATE,
        NATIVE_MEMORY,
    )
    store_native_registers(state, NATIVE_STATE, values)
    for address in (W_ON_SGB, H_JOY_PRESSED, H_JOY6, H_JOY7, H_VBLANK_OCCURRED, H_FRAMECOUNTER):
        state.memory.store(NATIVE_MEMORY + address, claripy.BVV(0, 8))
    state.memory.store(NATIVE_MEMORY + H_JOY_HELD, claripy.BVV(0x46, 8))
    state.memory.store(NATIVE_MEMORY + H_JOY5, claripy.BVV(0, 8))
    state.memory.store(NATIVE_MEMORY + H_SCX, claripy.BVV(0, 8))
    state.memory.store(NATIVE_MEMORY + W_BASE_COORD_X, claripy.BVV(0, 8))
    state.memory.store(NATIVE_MEMORY + W_BASE_COORD_Y, claripy.BVV(0, 8))
    state.memory.store(NATIVE_MEMORY + W_SHADOW_OAM, claripy.BVV(0, OAM_SIZE * 8), endness="Iend_BE")
    state.memory.store(NATIVE_MEMORY + W_INTRO_NIDORINO_BASE_TILE, claripy.BVV(0, 8))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [_endpoint(end, NATIVE_MEMORY) for end in manager.deadended]


def test_play_intro_scene_first_interruption_pathwise_equivalence() -> None:
    values = {
        "a": claripy.BVV(0x11, 8),
        "f": claripy.BVV(0x22, 8),
        "b": claripy.BVV(0x33, 8),
        "c": claripy.BVV(0x44, 8),
        "d": claripy.BVV(0x55, 8),
        "e": claripy.BVV(0x66, 8),
        "h": claripy.BVV(0x77, 8),
        "l": claripy.BVV(0x88, 8),
    }
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (
            "a", "f", "b", "c", "d", "e", "h", "l", "scx", "base_x", "base_y",
            "bgp", "obp0", "obp1", "joy_held", "joy5", "frame_counter", "oam",
        ),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_play_intro_scene_exact_linked_prefix() -> None:
    location = symbol_location(SYMBOLS, "PlayIntroScene")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
