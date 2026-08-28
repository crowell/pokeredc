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
    linked_bytes,
    rom_window,
    sm83_flags_to_z80,
    symbol_location,
)
from verification.harness.sm83_shims import (
    Sm83AndRegister,
    Sm83BitRegister,
    Sm83CpImmediate,
    Sm83CpRegister,
    Sm83LoadAAtHlIncrement,
    Sm83LoadAHighImmediate,
    Sm83LoadAImmediate,
    Sm83StoreAImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xEFFF

W_Y = 0xD361
W_X = 0xD362
W_MOVEMENT_FLAGS = 0xD736
W_CUR_MAP_TILESET = 0xD367
W_FACING = 0xC109
W_TILE_IN_FRONT = 0xCFC6
W_TILEMAP = 0xC3A0
W_JOY_IGNORE = 0xCD6B
W_SIMULATED_END = 0xCCD3
W_SIMULATED_INDEX = 0xCD38
W_STATUS_FLAGS5 = 0xD730
W_OVERRIDE_SIMULATED = 0xCCD0
W_MOVEMENT_BYTE1 = 0xC230
H_JOY_HELD = 0xFFB4
H_LOADED_ROM_BANK = 0xFFB8
H_SAVED_ROM_BANK = 0xFFB9
R_ROMB = 0x2000
AUTO = 0xFFBA
BANK_TEMP = 0xFF8B
COPY_SOURCE = 0xFFCC
COPY_DEST = 0xFFCE
COPY_SIZE = 0xFFCB
VBLANK_OCCURRED = 0xFFD6
SHADOW_OAM = 0xC390
W_NEW_SOUND_ID = 0xC0EE
W_AUDIO_ROM_BANK = 0xC0EF
W_AUDIO_SAVED_ROM_BANK = 0xC0F0
W_CHANNEL_SOUND_IDS = 0xC026
W_AUDIO_FADE_OUT_CONTROL = 0xCFC7
W_AUDIO_FADE_RELOAD = 0xCFC8
W_AUDIO_FADE_COUNTER = 0xCFC9
W_LAST_MUSIC_SOUND_ID = 0xCFCA
W_LOW_HEALTH_ALARM = 0xD083

MEMORY_FIELDS = (
    W_Y, W_X, W_MOVEMENT_FLAGS, W_CUR_MAP_TILESET, W_FACING,
    W_TILE_IN_FRONT, W_JOY_IGNORE, W_SIMULATED_END, W_SIMULATED_END + 1,
    W_SIMULATED_INDEX, W_STATUS_FLAGS5, W_OVERRIDE_SIMULATED,
    W_MOVEMENT_BYTE1, H_JOY_HELD, AUTO, H_LOADED_ROM_BANK, H_SAVED_ROM_BANK,
    BANK_TEMP, R_ROMB, COPY_SOURCE, COPY_SOURCE + 1, COPY_DEST,
    COPY_DEST + 1, COPY_SIZE, VBLANK_OCCURRED, SHADOW_OAM,
    W_NEW_SOUND_ID, W_AUDIO_ROM_BANK, W_AUDIO_SAVED_ROM_BANK,
    W_CHANNEL_SOUND_IDS, W_CHANNEL_SOUND_IDS + 1, W_CHANNEL_SOUND_IDS + 2,
    W_CHANNEL_SOUND_IDS + 3, W_AUDIO_FADE_OUT_CONTROL,
    W_AUDIO_FADE_RELOAD, W_AUDIO_FADE_COUNTER, W_LAST_MUSIC_SOUND_ID,
    W_LOW_HEALTH_ALARM,
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
    memory: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _return_from_call(procedure: angr.SimProcedure) -> None:
    target = procedure.state.memory.load(
        procedure.state.regs.sp, 2, endness="Iend_LE"
    )
    procedure.state.regs.sp = procedure.state.regs.sp + 2
    procedure.jump(target)


class GetTileBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        m = self.state.memory
        y = m.load(W_Y, 1)
        x = m.load(W_X, 1)
        facing = m.load(W_FACING, 1)
        self.state.regs.d = y
        self.state.regs.e = x
        down = W_TILEMAP + 8 + 11 * 20
        up = W_TILEMAP + 8 + 7 * 20
        left = W_TILEMAP + 6 + 9 * 20
        right = W_TILEMAP + 10 + 9 * 20
        tile = claripy.If(
            facing == 0,
            m.load(down, 1),
            claripy.If(
                facing == 4,
                m.load(up, 1),
                claripy.If(
                    facing == 8,
                    m.load(left, 1),
                    claripy.If(facing == 12, m.load(right, 1), facing),
                ),
            ),
        )
        self.state.regs.a = tile
        self.state.regs.c = tile
        m.store(W_TILE_IN_FRONT, tile)
        self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0, 8))
        _return_from_call(self)


class StartSimulationBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        m = self.state.memory
        m.store(W_OVERRIDE_SIMULATED, claripy.BVV(0, 8))
        m.store(W_MOVEMENT_BYTE1, claripy.BVV(0, 8))
        status = m.load(W_STATUS_FLAGS5, 1) | claripy.BVV(0x80, 8)
        m.store(W_STATUS_FLAGS5, status)
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x40, 8)
        self.state.regs.h = claripy.BVV(0xD7, 8)
        self.state.regs.l = claripy.BVV(0x30, 8)
        _return_from_call(self)


class CopyVideoBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        m = self.state.memory
        saved_auto = m.load(AUTO, 1)
        saved_bank = m.load(H_LOADED_ROM_BANK, 1)
        saved_f = self.state.regs.f
        m.store(AUTO, claripy.BVV(0, 8))
        m.store(BANK_TEMP, saved_bank)
        m.store(H_LOADED_ROM_BANK, self.state.regs.b)
        m.store(R_ROMB, self.state.regs.b)
        m.store(COPY_SOURCE, self.state.regs.e)
        m.store(COPY_SOURCE + 1, self.state.regs.d)
        m.store(COPY_DEST, self.state.regs.l)
        m.store(COPY_DEST + 1, self.state.regs.h)
        m.store(COPY_SIZE, self.state.regs.c)
        m.store(VBLANK_OCCURRED, claripy.BVV(0, 8))
        m.store(H_LOADED_ROM_BANK, saved_bank)
        m.store(R_ROMB, saved_bank)
        m.store(AUTO, saved_auto)
        self.state.regs.a = saved_auto
        self.state.regs.f = saved_f
        _return_from_call(self)


class WriteOAMBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        values = (
            0x54, 0x48, 0xFF, 0x10,
            0x54, 0x50, 0xFF, 0x30,
            0x5C, 0x48, 0xFF, 0x50,
            0x5C, 0x50, 0xFF, 0x70,
        )
        for index, value in enumerate(values):
            self.state.memory.store(SHADOW_OAM + index, claripy.BVV(value, 8))
        self.state.regs.a = claripy.BVV(0x70, 8)
        self.state.regs.f = claripy.BVV(0x10, 8)  # raw Z80 H flag
        self.state.regs.b = claripy.BVV(0x5C, 8)
        self.state.regs.c = claripy.BVV(0x50, 8)
        self.state.regs.d = claripy.BVV(0x67, 8)
        self.state.regs.e = claripy.BVV(0x18, 8)
        self.state.regs.h = claripy.BVV(0xC3, 8)
        self.state.regs.l = claripy.BVV(0xA0, 8)
        _return_from_call(self)


class PlaySoundBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        m = self.state.memory
        new = m.load(W_NEW_SOUND_ID, 1)
        fade = m.load(W_AUDIO_FADE_OUT_CONTROL, 1)
        last = m.load(W_LAST_MUSIC_SOUND_ID, 1)
        sound = self.state.regs.a

        def emit(condition: claripy.ast.Bool, kind: str) -> None:
            state = self.state.copy()
            sm = state.memory
            if kind != "return":
                for index in range(4):
                    sm.store(
                        W_CHANNEL_SOUND_IDS + index,
                        claripy.If(new != 0, claripy.BVV(0, 8),
                                   sm.load(W_CHANNEL_SOUND_IDS + index, 1)),
                    )
                sm.store(W_NEW_SOUND_ID, claripy.BVV(0, 8))
            if kind == "queue":
                sm.store(W_LAST_MUSIC_SOUND_ID, sound)
                sm.store(W_AUDIO_FADE_RELOAD, fade)
                sm.store(W_AUDIO_FADE_COUNTER, fade)
                sm.store(W_AUDIO_FADE_OUT_CONTROL, sound)
            elif kind in ("start", "immediate"):
                loaded = sm.load(H_LOADED_ROM_BANK, 1)
                sm.store(H_SAVED_ROM_BANK, loaded)
                sm.store(H_LOADED_ROM_BANK, loaded)
                sm.store(R_ROMB, loaded)
                if kind == "immediate":
                    sm.store(W_AUDIO_FADE_OUT_CONTROL, claripy.BVV(0, 8))
            state.add_constraints(condition)
            target = state.memory.load(state.regs.sp, 2, endness="Iend_LE")
            state.regs.sp = state.regs.sp + 2
            self.successors.add_successor(
                state, target, claripy.BoolV(True), "Ijk_Boring"
            )

        emit(claripy.And(fade != 0, new == 0), "return")
        emit(claripy.And(fade != 0, new != 0, last != 0xFF), "queue")
        emit(claripy.And(fade != 0, new != 0, last == 0xFF), "immediate")
        emit(fade == 0, "start")


class NativeDelayFrame(angr.SimProcedure):
    def run(self, delay_state: claripy.ast.BV, _observations: claripy.ast.BV) -> None:
        self.state.memory.store(delay_state, claripy.BVV(0, 8))
        self.state.memory.store(delay_state + 1, claripy.BVV(0x20, 8))
        self.state.memory.store(delay_state + 8, claripy.BVV(0, 8))


class LoadAAtHL(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self.state.regs.hl, 1)
        self.jump(self.addr + 1)


def _setup(state: angr.SimState, base: int, values: dict[str, claripy.ast.BV],
           *, facing: int, standing: int, front: int, joy: int,
           movement: int, tileset: int) -> None:
    for address, field in zip(MEMORY_FIELDS, (
        "y", "x", "movement", "tileset", "facing", "tile", "joy_ignore",
        "sim_end", "sim_end_high", "sim_index", "status", "override",
        "movement_byte", "joy", "auto", "loaded_bank", "saved_bank",
        "bank_temp", "romb", "copy_source", "copy_source_high",
        "copy_dest", "copy_dest_high", "copy_size", "vblank", "oam0",
        "new_sound", "audio_bank", "audio_saved", "channel0", "channel1",
        "channel2", "channel3", "fade", "fade_reload", "fade_counter",
        "last_music", "low_health",
    )):
        state.memory.store(base + address, values[field])
    state.memory.store(base + W_Y, claripy.BVV(10, 8))
    state.memory.store(base + W_X, claripy.BVV(10, 8))
    state.memory.store(base + W_MOVEMENT_FLAGS, claripy.BVV(movement, 8))
    state.memory.store(base + W_CUR_MAP_TILESET, claripy.BVV(tileset, 8))
    state.memory.store(base + W_FACING, claripy.BVV(facing, 8))
    state.memory.store(base + H_JOY_HELD, claripy.BVV(joy, 8))
    state.memory.store(base + W_TILEMAP + 9 * 20 + 8, claripy.BVV(standing, 8))
    for address in (
        W_TILEMAP + 8 + 11 * 20, W_TILEMAP + 8 + 7 * 20,
        W_TILEMAP + 6 + 9 * 20, W_TILEMAP + 10 + 9 * 20,
    ):
        state.memory.store(base + address, claripy.BVV(front, 8))
    for index in range(16):
        state.memory.store(base + SHADOW_OAM + index, values[f"oam{index}"])


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    parts = []
    for address in MEMORY_FIELDS:
        if address == SHADOW_OAM:
            parts.append(state.memory.load(base + SHADOW_OAM, 16))
        elif address in (W_TILEMAP + 9 * 20 + 8,):
            parts.append(state.memory.load(base + address, 1))
        else:
            parts.append(state.memory.load(base + address, 1))
    return claripy.Concat(*parts)


def _endpoint(state: angr.SimState, *, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    return Endpoint(
        **(native_registers(state, NATIVE_STATE) if native else assembly_registers(state)),
        memory=_memory(state, base),
        constraints=tuple(state.solver.constraints),
    )


def _values(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    fields = (
        "y", "x", "movement", "tileset", "facing", "tile", "joy_ignore",
        "sim_end", "sim_end_high", "sim_index", "status", "override",
        "movement_byte", "joy", "auto", "loaded_bank", "saved_bank",
        "bank_temp", "romb", "copy_source", "copy_source_high", "copy_dest",
        "copy_dest_high", "copy_size", "vblank", "new_sound", "audio_bank",
        "audio_saved", "channel0", "channel1", "channel2", "channel3",
        "fade", "fade_reload", "fade_counter", "last_music", "low_health",
    )
    for field in fields:
        values[field] = claripy.BVS(f"{prefix}_{field}", 8)
    for index in range(16):
        values[f"oam{index}"] = claripy.BVS(f"{prefix}_oam{index}", 8)
    return values


def _assembly(values: dict[str, claripy.ast.BV], **case: int) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "HandleLedges")
    table = symbol_location(SYMBOLS, "LedgeTiles")
    body = linked_bytes(ROM, location, table.address - location.address)
    assert len(body) == 93
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    project.hook(0x3E6D, GetTileBoundary(), length=3)
    project.hook(0x3486, StartSimulationBoundary(), length=3)
    project.hook(0x1886, CopyVideoBoundary(), length=3)
    project.hook(0x3A97, WriteOAMBoundary(), length=3)
    project.hook(0x23B1, PlaySoundBoundary(), length=3)
    q = location.address
    project.hook(q + 0x00, Sm83LoadAImmediate(W_MOVEMENT_FLAGS, q + 0x03), length=3)
    project.hook(q + 3, Sm83BitRegister(6, "a", q + 5), length=2)
    project.hook(q + 0x06, Sm83LoadAImmediate(W_CUR_MAP_TILESET, q + 0x09), length=3)
    project.hook(q + 9, Sm83AndRegister("a", q + 10), length=1)
    project.hook(q + 0x10, Sm83LoadAImmediate(W_FACING, q + 0x13), length=3)
    project.hook(q + 0x14, Sm83LoadAImmediate(W_TILEMAP + 9 * 20 + 8, q + 0x17), length=3)
    project.hook(q + 0x18, Sm83LoadAImmediate(W_TILE_IN_FRONT, q + 0x1B), length=3)
    project.hook(q + 0x20, Sm83CpImmediate(0xFF, q + 0x22), length=2)
    project.hook(q + 0x23, Sm83CpRegister("b", q + 0x24), length=1)
    project.hook(q + 0x27, Sm83CpRegister("c", q + 0x28), length=1)
    project.hook(q + 0x2B, Sm83CpRegister("d", q + 0x2C), length=1)
    project.hook(q + 0x37, Sm83LoadAHighImmediate(0xB4, q + 0x39), length=2)
    project.hook(q + 0x39, Sm83AndRegister("e", q + 0x3A), length=1)
    project.hook(q + 0x1F, Sm83LoadAAtHlIncrement(q + 0x20), length=1)
    project.hook(q + 0x26, Sm83LoadAAtHlIncrement(q + 0x27), length=1)
    project.hook(q + 0x2A, Sm83LoadAAtHlIncrement(q + 0x2B), length=1)
    project.hook(q + 0x2E, LoadAAtHL(), length=1)
    project.hook(q + 0x3D, Sm83StoreAImmediate(W_JOY_IGNORE, q + 0x40), length=3)
    project.hook(q + 0x49, Sm83StoreAImmediate(W_SIMULATED_END, q + 0x4C), length=3)
    project.hook(q + 0x4C, Sm83StoreAImmediate(W_SIMULATED_END + 1, q + 0x4F), length=3)
    project.hook(q + 0x51, Sm83StoreAImmediate(W_SIMULATED_INDEX, q + 0x54), length=3)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    _setup(
        state, 0, values, facing=case["facing"], standing=case["standing"],
        front=case["front"], joy=case["joy"], movement=case["movement"],
        tileset=case["tileset"],
    )
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN, num_find=16)
    assert not manager.errored and manager.found
    return [_endpoint(end, native=False) for end in manager.found]


def _native(values: dict[str, claripy.ast.BV], **case: int) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_handle_ledges")
    delay = project.loader.find_symbol("port_delay_frame")
    assert function is not None and delay is not None
    project.hook(delay.rebased_addr, NativeDelayFrame())
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup(
        state, NATIVE_MEMORY, values, facing=case["facing"],
        standing=case["standing"], front=case["front"], joy=case["joy"],
        movement=case["movement"], tileset=case["tileset"],
    )
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and manager.deadended
    return [_endpoint(end, native=True) for end in manager.deadended]


CASES = (
    dict(facing=0, standing=0x2C, front=0x37, joy=0x80, movement=0, tileset=0),
    dict(facing=0, standing=0x39, front=0x36, joy=0x80, movement=0, tileset=0),
    dict(facing=0, standing=0x39, front=0x37, joy=0x80, movement=0, tileset=0),
    dict(facing=8, standing=0x2C, front=0x27, joy=0x20, movement=0, tileset=0),
    dict(facing=8, standing=0x39, front=0x27, joy=0x20, movement=0, tileset=0),
    dict(facing=12, standing=0x2C, front=0x0D, joy=0x10, movement=0, tileset=0),
    dict(facing=12, standing=0x2C, front=0x1D, joy=0x10, movement=0, tileset=0),
    dict(facing=12, standing=0x39, front=0x0D, joy=0x10, movement=0, tileset=0),
    dict(facing=0, standing=0x2C, front=0x37, joy=0, movement=0, tileset=0),
    dict(facing=4, standing=0x2C, front=0x37, joy=0, movement=0, tileset=0),
    dict(facing=0, standing=0x2C, front=0x37, joy=0x80, movement=0x40, tileset=0),
    dict(facing=0, standing=0x2C, front=0x37, joy=0x80, movement=0, tileset=1),
    dict(facing=0, standing=0x2C, front=0x37, joy=0x80, movement=0, tileset=0,
         new_sound=0, fade=1, last_music=0),
    dict(facing=0, standing=0x2C, front=0x37, joy=0x80, movement=0, tileset=0,
         new_sound=2, fade=1, last_music=3),
    dict(facing=0, standing=0x2C, front=0x37, joy=0x80, movement=0, tileset=0,
         new_sound=2, fade=1, last_music=0xFF),
)


@pytest.mark.skipif(
    not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),
    reason="build artifacts missing",
)
@pytest.mark.parametrize("case", CASES)
def test_handle_ledges_pathwise_equivalence(case: dict[str, int]) -> None:
    values = _values(f"handle_ledges_{case['facing']}_{case['standing']}_{case['front']}_{case['joy']}_{case['movement']}_{case['tileset']}")
    # Caller registers are overwritten before each observable branch.  Keep
    # them concrete so the linked SM83 loop remains solver-friendly; audio
    # branch coverage is supplied by explicit cases below.
    for register in REGISTERS:
        values[register] = claripy.BVV(0, 8)
    for name, value in tuple(values.items()):
        if name not in REGISTERS:
            values[name] = claripy.BVV(0, 8)
    values["new_sound"] = claripy.BVV(case.get("new_sound", 0), 8)
    values["fade"] = claripy.BVV(case.get("fade", 0), 8)
    values["last_music"] = claripy.BVV(case.get("last_music", 0), 8)
    assert_pathwise_equivalent(
        _assembly(values, **case), _native(values, **case), (*REGISTERS, "memory")
    )
