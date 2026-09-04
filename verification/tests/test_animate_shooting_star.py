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
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
DONE = 0xEFFF
R_OBP0 = 0xFF48
R_OBP1 = 0xFF49
H_JOYPRESSED = 0xFFB3
H_JOYHELD = 0xFFB4
H_JOY5 = 0xFFB5
H_JOY6 = 0xFFB6
H_JOY7 = 0xFFB7
H_SAVED_ROM_BANK = 0xFFB9
H_LOADED_ROM_BANK = 0xFFB8
H_FRAMECOUNTER = 0xFFD5
H_VBLANK_OCCURRED = 0xFFD6
W_SHADOW_OAM = 0xC300
W_MOVE_COUNT = 0xCD3D
W_NEW_SOUND_ID = 0xC0EE
W_AUDIO_ROM_BANK = 0xC0EF
W_AUDIO_SAVED_ROM_BANK = 0xC0F0
W_FADE_CONTROL = 0xCFC7
W_FADE_RELOAD = 0xCFC8
W_FADE_COUNTER = 0xCFC9
W_LAST_MUSIC_SOUND_ID = 0xCFCA
W_CHANNEL_SOUND_IDS = 0xC026
R_ROMB = 0x2000
EXPECTED = bytes.fromhex(
    "cd00403ec2cdb1232100c30104a0e5c57ec604227ec6fc2223230d20f3"
    "0e01cdf812c1e1d87efe50200218e2b820df2100c30e0411040036a0190d"
    "20fa06032148ffcb0ecb0e0e0acdf812d80520f01100c33e18f521ee40"
    "010400cdb500f13d20f2afea3dcd21f2400e062a5f2a57c5e52150c30e04"
    "1afeff281622131a221323230d20f1fa3dcdfe182805c606ea3dcdcd1f41"
    "f52110c31100c3015000cdb500f1e1c1d80d20c3a7c9"
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

def return_from_call(state: angr.SimState) -> int:
    stack = state.solver.eval(state.regs.sp)
    target = state.solver.eval(state.memory.load(stack, 2, endness="Iend_LE"))
    state.regs.sp = claripy.BVV((stack + 2) & 0xFFFF, 16)
    return target


class LoadGraphicsSummary(angr.SimProcedure):
    def __init__(self, logo: bytes, star: bytes, next_address: int | None = None) -> None:
        super().__init__()
        self.logo = logo
        self.star = star
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        state = self.state
        next_address = self.next_address
        if next_address is None:
            next_address = return_from_call(state)
        state.memory.store(R_OBP0, claripy.BVV(0xF9, 8))
        state.memory.store(R_OBP1, claripy.BVV(0xA4, 8))
        state.memory.store(0xC360, claripy.BVV(self.logo))
        state.memory.store(W_SHADOW_OAM, claripy.BVV(self.star))
        state.regs.a = claripy.BVV(0, 8)
        state.regs.f = claripy.BVV(0x40, 8)
        state.regs.b = claripy.BVV(0, 8)
        state.regs.c = claripy.BVV(0, 8)
        state.regs.d = claripy.BVV(0xC3, 8)
        state.regs.e = claripy.BVV(0x10, 8)
        state.regs.h = claripy.BVV(0x41, 8)
        state.regs.l = claripy.BVV(0x90, 8)
        self.jump(next_address)

class PlaySoundSummary(angr.SimProcedure):
    def __init__(self, next_address: int | None = None) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        if self.next_address is not None:
            self.jump(self.next_address)
        else:
            self.jump(return_from_call(self.state))


class CheckSummary(angr.SimProcedure):
    def __init__(self, mode: str) -> None:
        super().__init__()
        self.mode = mode

    def run(self) -> None:  # type: ignore[override]
        state = self.state
        for i in range(4):
            y = W_SHADOW_OAM + i * 4
            state.memory.store(y, state.memory.load(y, 1) + 4)
            state.memory.store(y + 1, state.memory.load(y + 1, 1) - 4)
        state.memory.store(H_VBLANK_OCCURRED, claripy.BVV(0, 8))
        if self.mode == "held":
            state.memory.store(H_JOY5, claripy.BVV(0x46, 8))
            state.memory.store(H_FRAMECOUNTER, claripy.BVV(5, 8))
            state.regs.a = claripy.BVV(0x46, 8)
            state.regs.f = claripy.BVV(0x41, 8)
            state.regs.h = claripy.BVV(0xC3, 8)
            state.regs.l = claripy.BVV(0, 8)
            state.regs.c = claripy.BVV(4, 8)
            self.jump(DONE)
            return
        if self.mode == "button":
            state.memory.store(H_JOY5, claripy.BVV(1, 8))
            state.memory.store(H_FRAMECOUNTER, claripy.BVV(30, 8))
            state.regs.a = claripy.BVV(1, 8)
            state.regs.f = claripy.BVV(0x01, 8)
            state.regs.h = claripy.BVV(0xC3, 8)
            state.regs.l = claripy.BVV(0, 8)
            state.regs.c = claripy.BVV(4, 8)
            self.jump(DONE)
            return
        state.memory.store(H_JOY5, claripy.BVV(0, 8))
        state.memory.store(H_FRAMECOUNTER, claripy.BVV(5, 8))
        state.regs.a = claripy.BVV(0, 8)
        state.regs.f = claripy.BVV(0x50, 8)
        state.regs.c = claripy.BVV(0, 8)
        self.jump(return_from_call(state))

class CopyDataSummary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        state = self.state
        next_address = return_from_call(state)
        source = state.solver.eval(state.regs.h.concat(state.regs.l))
        destination = state.solver.eval(state.regs.d.concat(state.regs.e))
        size = state.solver.eval(state.regs.b.concat(state.regs.c))
        data = state.memory.load(source, size)
        state.memory.store(destination, data)
        state.regs.h = claripy.BVV((source + size) & 0xFFFF, 16)
        state.regs.d = claripy.BVV((destination + size) & 0xFFFF, 16)
        state.regs.b = claripy.BVV(0, 16)
        state.regs.a = claripy.BVV(0, 8)
        state.regs.f = claripy.BVV(0x40, 8)
        self.jump(next_address)
class MoveDownSummary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        state = self.state
        next_address = return_from_call(state)
        count = state.solver.eval(state.memory.load(W_MOVE_COUNT, 1))
        for _ in range(8):
            cursor = W_SHADOW_OAM + 23 * 4
            for _ in range(count):
                state.memory.store(cursor, state.memory.load(cursor, 1) + 1)
                cursor = (cursor - 4) & 0xFFFF
            state.memory.store(R_OBP1, state.memory.load(R_OBP1, 1) ^ 0xA0)
            state.memory.store(H_VBLANK_OCCURRED, claripy.BVV(0, 8))
            state.memory.store(H_JOY5, claripy.BVV(0, 8))
            state.memory.store(H_FRAMECOUNTER, claripy.BVV(5, 8))
        state.regs.a = claripy.BVV(0, 8)
        state.regs.f = claripy.BVV(0x42, 8)
        state.regs.b = claripy.BVV(0, 8)
        state.regs.c = claripy.BVV(0, 8)
        state.regs.h = claripy.BVV((cursor >> 8) & 0xFF, 8)
        state.regs.l = claripy.BVV(cursor & 0xFF, 8)
        self.jump(next_address)

class ReturnCarry(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        carry = int(self.state.solver.eval(self.state.regs.f & 0x01)) != 0
        self.jump(DONE if carry else self.next_address)


class ReturnDone(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(DONE)


def _inputs(mode: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(f"animate_{mode}")
    values.update(
        joy_pressed=claripy.BVV(0x01 if mode == "button" else 0, 8),
        joy_held=claripy.BVV(0x46 if mode == "held" else 0, 8),
        joy5=claripy.BVV(0, 8),
        joy6=claripy.BVV(1, 8),
        joy7=claripy.BVV(1 if mode != "button" else 0, 8),
        frame=claripy.BVV(0, 8),
        vblank=claripy.BVV(0, 8),
        oam=claripy.BVS(f"animate_{mode}_oam", 0x100 * 8),
    )
    return values


def _setup(state: angr.SimState, base: int, values: dict[str, claripy.ast.BV]) -> None:
    for address, name in (
        (H_JOYPRESSED, "joy_pressed"), (H_JOYHELD, "joy_held"),
        (H_JOY5, "joy5"), (H_JOY6, "joy6"), (H_JOY7, "joy7"),
        (H_FRAMECOUNTER, "frame"), (H_VBLANK_OCCURRED, "vblank"),
    ):
        state.memory.store(base + address, values[name])
    state.memory.store(base + W_SHADOW_OAM, values["oam"])
    for address in (
        W_MOVE_COUNT, W_NEW_SOUND_ID, W_AUDIO_ROM_BANK, W_AUDIO_SAVED_ROM_BANK,
        W_FADE_CONTROL, W_FADE_RELOAD, W_FADE_COUNTER, W_LAST_MUSIC_SOUND_ID,
        H_SAVED_ROM_BANK, H_LOADED_ROM_BANK, R_ROMB,
    ):
        state.memory.store(base + address, claripy.BVV(0, 8))
    state.memory.store(base + R_OBP0, claripy.BVS("animate_obp0", 8))
    state.memory.store(base + R_OBP1, claripy.BVS("animate_obp1", 8))
    state.memory.store(base + W_CHANNEL_SOUND_IDS, claripy.BVV(0, 32))
    for symbol, size in (
        ("GameFreakLogoOAMData", 0x40), ("GameFreakShootingStarOAMData", 0x10),
        ("SmallStarsOAM", 4), ("SmallStarsWaveCoordsPointerTable", 12),
        ("SmallStarsWave1Coords", 8), ("SmallStarsWave2Coords", 8),
        ("SmallStarsWave3Coords", 8), ("SmallStarsWave4Coords", 8),
        ("SmallStarsEmptyWave", 1),
    ):
        location = symbol_location(SYMBOLS, symbol)
        state.memory.store(base + location.address,
                           claripy.BVV(linked_bytes(ROM, location, size)))


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    addresses = (
        R_OBP0, R_OBP1, W_MOVE_COUNT, H_JOY5, H_FRAMECOUNTER,
        H_VBLANK_OCCURRED, W_NEW_SOUND_ID, W_AUDIO_ROM_BANK,
        W_AUDIO_SAVED_ROM_BANK, W_FADE_CONTROL, W_FADE_RELOAD,
        W_FADE_COUNTER, W_LAST_MUSIC_SOUND_ID, H_SAVED_ROM_BANK,
        H_LOADED_ROM_BANK, R_ROMB, W_CHANNEL_SOUND_IDS,
    )
    return claripy.Concat(
        *(state.memory.load(base + address, 1) for address in addresses),
        state.memory.load(base + W_SHADOW_OAM, 0x100),
    )


def _assembly(values: dict[str, claripy.ast.BV], mode: str) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "AnimateShootingStar")
    end_data = symbol_location(SYMBOLS, "SmallStarsOAM")
    assert linked_bytes(ROM, location, end_data.address - location.address) == EXPECTED
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    base = location.address
    project.hook(
        base,
        LoadGraphicsSummary(
            linked_bytes(ROM, symbol_location(SYMBOLS, "GameFreakLogoOAMData"), 0x40),
            linked_bytes(ROM, symbol_location(SYMBOLS, "GameFreakShootingStarOAMData"), 0x10),
            base + 0x03),
        length=3)
    project.hook(base + 0x05, PlaySoundSummary(base + 0x08), length=3)
    project.hook(symbol_location(SYMBOLS, "CheckForUserInterruption").address,
                 CheckSummary(mode), length=1)
    project.hook(0x2322, CheckSummary(mode), length=1)
    project.hook(symbol_location(SYMBOLS, "CopyData").address,
                 CopyDataSummary(), length=1)
    project.hook(symbol_location(SYMBOLS, "MoveDownSmallStars").address,
                 MoveDownSummary(), length=1)
    project.hook(base + 0x24, ReturnCarry(base + 0x25), length=1)
    project.hook(base + 0x4B, ReturnCarry(base + 0x4C), length=1)
    project.hook(base + 0xA4, ReturnCarry(base + 0xA5), length=1)
    project.hook(base + 0xA9, ReturnDone(), length=1)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _setup(state, 0, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(DONE, 16), endness="Iend_LE")
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=4)
    assert not manager.errored
    assert len(manager.found) == 1
    end = manager.found[0]
    return [Endpoint(**assembly_registers(end), memory=_memory(end, 0),
                      constraints=tuple(end.solver.constraints))]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_animate_shooting_star")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, NATIVE_MEMORY, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    end = manager.deadended[0]
    return [Endpoint(**native_registers(end, NATIVE_STATE), memory=_memory(end, NATIVE_MEMORY),
                      constraints=tuple(end.solver.constraints))]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("mode", ("held", "button"))
def test_animate_shooting_star_pathwise_equivalence(mode: str) -> None:
    values = _inputs(mode)
    assert_pathwise_equivalent(_assembly(values, mode), _native(values), (*REGISTERS, "memory"))
