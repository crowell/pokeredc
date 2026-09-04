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
H_AUTO_BG_TRANSFER_ENABLED = 0xFFBA
H_LOADED_ROM_BANK = 0xFFB8
H_ROM_BANK_TEMP = 0xFF8B
R_ROMB = 0x2000
H_VBLANK_COPY_SOURCE = 0xFFC7
H_VBLANK_COPY_DEST = 0xFFC9
H_VBLANK_COPY_SIZE = 0xFFC6
H_VBLANK_OCCURRED = 0xFFD6
R_OBP0 = 0xFF48
R_OBP1 = 0xFF49
W_SHADOW_OAM = 0xC300
W_SHADOW_OAM_SPRITE24 = W_SHADOW_OAM + 24 * 4
EXPECTED = bytes.fromhex(
    "3ef9e0483ea4e049111e4721008a01011ecd4818111e482110"
    "8a01011ecd481811904121208a01011ccd48182140411160c3"
    "014000cdb5002180411100c3011000c3b500"
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

class LoadAImmediate(angr.SimProcedure):
    def __init__(self, value: int, next_address: int) -> None:
        super().__init__()
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(self.value, 8)
        self.jump(self.next_address)


class StoreAImmediate(angr.SimProcedure):
    def __init__(self, address: int, next_address: int) -> None:
        super().__init__()
        self.address = address
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(self.address, self.state.regs.a)
        self.jump(self.next_address)


class LoadPairImmediate(angr.SimProcedure):
    def __init__(self, pair: str, value: int, next_address: int) -> None:
        super().__init__()
        self.pair = pair
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.pair, claripy.BVV(self.value, 16))
        self.jump(self.next_address)


class CopyVideoDataSummary(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        state = self.state
        saved_auto = state.memory.load(H_AUTO_BG_TRANSFER_ENABLED, 1)
        saved_bank = state.memory.load(H_LOADED_ROM_BANK, 1)
        state.memory.store(H_AUTO_BG_TRANSFER_ENABLED, claripy.BVV(0, 8))
        state.memory.store(H_ROM_BANK_TEMP, saved_bank)
        state.memory.store(H_LOADED_ROM_BANK, state.regs.b)
        state.memory.store(R_ROMB, state.regs.b)
        state.memory.store(H_VBLANK_COPY_SOURCE, state.regs.e)
        state.memory.store(H_VBLANK_COPY_SOURCE + 1, state.regs.d)
        state.memory.store(H_VBLANK_COPY_DEST, state.regs.l)
        state.memory.store(H_VBLANK_COPY_DEST + 1, state.regs.h)
        state.memory.store(H_VBLANK_COPY_SIZE, state.regs.c)
        state.memory.store(H_VBLANK_OCCURRED, claripy.BVV(0, 8))
        state.memory.store(H_LOADED_ROM_BANK, saved_bank)
        state.memory.store(R_ROMB, saved_bank)
        state.memory.store(H_AUTO_BG_TRANSFER_ENABLED, saved_auto)
        state.regs.a = saved_auto
        self.jump(self.next_address)


class CopyDataSummary(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        state = self.state
        length = int(state.solver.eval(claripy.Concat(state.regs.b, state.regs.c)))
        source = int(state.solver.eval(state.regs.hl))
        destination = int(state.solver.eval(state.regs.de))
        for offset in range(length):
            state.memory.store(
                destination + offset,
                state.memory.load(source + offset, 1),
            )
        state.regs.hl = state.regs.hl + length
        state.regs.de = state.regs.de + length
        state.regs.b = claripy.BVV(0, 8)
        state.regs.c = claripy.BVV(0, 8)
        state.regs.a = claripy.BVV(0, 8)
        state.regs.f = claripy.BVV(0x40, 8)
        self.jump(self.next_address)


def _inputs() -> dict[str, claripy.ast.BV]:
    values = symbolic_registers("load_shooting_star_graphics")
    for name in (
        "auto",
        "loaded_bank",
        "rom_temp",
        "romb",
        "vblank_source_low",
        "vblank_source_high",
        "vblank_dest_low",
        "vblank_dest_high",
        "vblank_size",
        "vblank_occurred",
        "obp0",
        "obp1",
    ):
        values[name] = claripy.BVS(f"load_shooting_{name}", 8)
    values["oam"] = claripy.BVS("load_shooting_oam", 0x100 * 8)
    return values


def _setup(state: angr.SimState, base: int, values: dict[str, claripy.ast.BV]) -> None:
    state.memory.store(base + H_AUTO_BG_TRANSFER_ENABLED, values["auto"])
    state.memory.store(base + H_LOADED_ROM_BANK, values["loaded_bank"])
    state.memory.store(base + H_ROM_BANK_TEMP, values["rom_temp"])
    state.memory.store(base + R_ROMB, values["romb"])
    state.memory.store(base + H_VBLANK_COPY_SOURCE, values["vblank_source_low"])
    state.memory.store(base + H_VBLANK_COPY_SOURCE + 1, values["vblank_source_high"])
    state.memory.store(base + H_VBLANK_COPY_DEST, values["vblank_dest_low"])
    state.memory.store(base + H_VBLANK_COPY_DEST + 1, values["vblank_dest_high"])
    state.memory.store(base + H_VBLANK_COPY_SIZE, values["vblank_size"])
    state.memory.store(base + H_VBLANK_OCCURRED, values["vblank_occurred"])
    state.memory.store(base + R_OBP0, values["obp0"])
    state.memory.store(base + R_OBP1, values["obp1"])
    state.memory.store(base + W_SHADOW_OAM, values["oam"])
    for symbol, size in (
        ("GameFreakLogoOAMData", 0x40),
        ("GameFreakShootingStarOAMData", 0x10),
    ):
        location = symbol_location(SYMBOLS, symbol)
        state.memory.store(
            base + location.address,
            claripy.BVV(linked_bytes(ROM, location, size)),
        )


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        *(state.memory.load(base + address, 1) for address in (
            H_AUTO_BG_TRANSFER_ENABLED,
            H_LOADED_ROM_BANK,
            H_ROM_BANK_TEMP,
            R_ROMB,
            H_VBLANK_COPY_SOURCE,
            H_VBLANK_COPY_SOURCE + 1,
            H_VBLANK_COPY_DEST,
            H_VBLANK_COPY_DEST + 1,
            H_VBLANK_COPY_SIZE,
            H_VBLANK_OCCURRED,
            R_OBP0,
            R_OBP1,
        )),
        state.memory.load(base + W_SHADOW_OAM, 0x100),
    )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "LoadShootingStarGraphics")
    continuation = symbol_location(SYMBOLS, "AnimateShootingStar")
    assert continuation.address > location.address
    assert linked_bytes(ROM, location, continuation.address - location.address) == EXPECTED
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
    base = location.address
    copy_video = symbol_location(SYMBOLS, "CopyVideoData")
    copy_data = symbol_location(SYMBOLS, "CopyData")
    assert copy_video.bank == 0
    assert copy_data.bank == 0
    for offset, value, next_offset in ((0x00, 0xF9, 0x02), (0x04, 0xA4, 0x06)):
        project.hook(base + offset, LoadAImmediate(value, base + next_offset), length=2)
    for offset, address, next_offset in ((0x02, R_OBP0, 0x04), (0x06, R_OBP1, 0x08)):
        project.hook(base + offset, StoreAImmediate(address, base + next_offset), length=2)
    for offset, pair, value, next_offset in (
        (0x08, "de", 0x471E, 0x0B), (0x0B, "hl", 0x8A00, 0x0E),
        (0x0E, "bc", 0x1E01, 0x11), (0x14, "de", 0x481E, 0x17),
        (0x17, "hl", 0x8A10, 0x1A), (0x1A, "bc", 0x1E01, 0x1D),
        (0x20, "de", 0x4190, 0x23), (0x23, "hl", 0x8A20, 0x26),
        (0x26, "bc", 0x1C01, 0x29), (0x2C, "hl", 0x4140, 0x2F),
        (0x2F, "de", 0xC360, 0x32), (0x32, "bc", 0x0040, 0x35),
        (0x38, "hl", 0x4180, 0x3B), (0x3B, "de", 0xC300, 0x3E),
        (0x3E, "bc", 0x0010, 0x41),
    ):
        project.hook(
            base + offset,
            LoadPairImmediate(pair, value, base + next_offset),
            length=3,
        )
    for offset, next_offset in ((0x11, 0x14), (0x1D, 0x20), (0x29, 0x2C)):
        project.hook(base + offset, CopyVideoDataSummary(base + next_offset), length=3)
    project.hook(base + 0x35, CopyDataSummary(base + 0x38), length=3)
    project.hook(copy_data.address, CopyDataSummary(DONE), length=3)
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
    return [
        Endpoint(
            **assembly_registers(end),
            memory=_memory(end, 0),
            constraints=tuple(end.solver.constraints),
        )
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_load_shooting_star_graphics")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, NATIVE_MEMORY, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    end = manager.deadended[0]
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=_memory(end, NATIVE_MEMORY),
            constraints=tuple(end.solver.constraints),
        )
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_load_shooting_star_graphics_pathwise_equivalence() -> None:
    values = _inputs()
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "memory"),
    )
