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
from verification.harness.rom import collect_returns, linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import Sm83LoadAImmediate, Sm83StoreAImmediate

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
DONE = 0xEFFF
FRAME = 0xC500
DESTINATION = 0xC300
W_BASE_COORD_X = 0xD081
W_BASE_COORD_Y = 0xD082
W_FB_TILE_COUNTER = 0xD084
W_NUM_FB_TILES = 0xD089
W_SUBANIM_TRANSFORM = 0xD08B
W_ANIMATION_ID = 0xD07C
W_SUBANIM_FRAME_DELAY = 0xD086
W_FB_DEST_ADDR = 0xD09C
W_FB_MODE = 0xD09E
W_SHADOW_OAM = 0xC300
FIELDS = (
    "base_x",
    "base_y",
    "tile_counter",
    "num_tiles",
    "transform",
    "dest_high",
    "dest_low",
    "mode",
    "animation_id",
    "frame_delay",
    "frame_y",
    "frame_x",
    "frame_tile",
    "frame_flags",
)

class LoadFramePointer(angr.SimProcedure):
    def __init__(self, high: bool, next_address: int) -> None:
        super().__init__()
        self.high = high
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        if self.high:
            self.state.regs.h = self.state.regs.b
            self.state.regs.hl = claripy.Concat(
                self.state.regs.b, self.state.regs.hl[7:0]
            )
        else:
            self.state.regs.l = self.state.regs.c
            self.state.regs.hl = claripy.Concat(
                self.state.regs.hl[15:8], self.state.regs.c
            )
        self.jump(self.next_address)
class LoadAIncrementHL(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self.state.regs.hl, 1)
        self.state.regs.hl = self.state.regs.hl + 1
        self.state.regs.h = self.state.regs.hl[15:8]
        self.state.regs.l = self.state.regs.hl[7:0]
        self.jump(self.next_address)


class IncrementPair(angr.SimProcedure):
    def __init__(self, pair: str, next_address: int) -> None:
        super().__init__()
        self.pair = pair
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        value = getattr(self.state.regs, self.pair) + 1
        setattr(self.state.regs, self.pair, value)
        high, low = self.pair
        setattr(self.state.regs, high, value[15:8])
        setattr(self.state.regs, low, value[7:0])
        self.jump(self.next_address)


class StoreAAtDE(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(self.state.regs.de, self.state.regs.a)
        self.jump(self.next_address)
class LoadBFromA(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.b = self.state.regs.a
        self.jump(self.next_address)
class AddAAtHL(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        left = self.state.regs.a
        right = self.state.memory.load(self.state.regs.hl, 1)
        result = left + right
        flags = claripy.If(result == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        flags |= claripy.If(
            (left & 0x0F) + (right & 0x0F) > 0x0F,
            claripy.BVV(0x10, 8),
            claripy.BVV(0, 8),
        )
        flags |= claripy.If(
            claripy.ZeroExt(1, left) + claripy.ZeroExt(1, right) > 0xFF,
            claripy.BVV(0x01, 8),
            claripy.BVV(0, 8),
        )
        self.state.regs.a = result
        self.state.regs.f = flags
        self.jump(self.next_address)

class SubAFromB(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        left = self.state.regs.a
        right = self.state.regs.b
        result = left - right
        flags = claripy.BVV(0x02, 8)
        flags |= claripy.If(result == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        flags |= claripy.If(
            (left & 0x0F) < (right & 0x0F),
            claripy.BVV(0x10, 8),
            claripy.BVV(0, 8),
        )
        flags |= claripy.If(left.ULT(right), claripy.BVV(0x01, 8), claripy.BVV(0, 8))
        self.state.regs.a = result
        self.state.regs.f = flags
        self.jump(self.next_address)
class DelayFramesSummary(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.c = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x02, 8)
        self.jump(self.next_address)
class AnimationCleanSummary(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(
            W_SHADOW_OAM,
            claripy.BVV(0, 160 * 8),
            endness="Iend_BE",
        )
        self.jump(self.next_address)
class CpImmediate(angr.SimProcedure):
    def __init__(self, immediate: int, next_address: int) -> None:
        super().__init__()
        self.immediate = claripy.BVV(immediate, 8)
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        left = self.state.regs.a
        right = self.immediate
        flags = claripy.BVV(0x02, 8)
        flags |= claripy.If(left == right, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        flags |= claripy.If(
            (left & 0x0F) < (right & 0x0F),
            claripy.BVV(0x10, 8),
            claripy.BVV(0, 8),
        )
        flags |= claripy.If(left.ULT(right), claripy.BVV(0x01, 8), claripy.BVV(0, 8))
        self.state.regs.f = flags
        self.jump(self.next_address)
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



def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for field in FIELDS:
        values[field] = claripy.BVS(f"{prefix}_{field}", 8)
    return values


def _store_memory(state: angr.SimState, base: int, values: dict[str, claripy.ast.BV]) -> None:
    state.memory.store(base + W_BASE_COORD_X, values["base_x"])
    state.memory.store(base + W_BASE_COORD_Y, values["base_y"])
    state.memory.store(base + W_FB_TILE_COUNTER, values["tile_counter"])
    state.memory.store(base + W_NUM_FB_TILES, values["num_tiles"])
    state.memory.store(base + W_SUBANIM_TRANSFORM, values["transform"])
    state.memory.store(base + W_FB_DEST_ADDR, values["dest_high"])
    state.memory.store(base + W_FB_DEST_ADDR + 1, values["dest_low"])
    state.memory.store(base + W_FB_MODE, values["mode"])
    state.memory.store(base + W_ANIMATION_ID, values["animation_id"])
    state.memory.store(base + W_SUBANIM_FRAME_DELAY, values["frame_delay"])
    state.memory.store(base + FRAME, claripy.BVV(1, 8))
    state.memory.store(base + FRAME + 1, values["frame_y"])
    state.memory.store(base + FRAME + 2, values["frame_x"])
    state.memory.store(base + FRAME + 3, values["frame_tile"])
    state.memory.store(base + FRAME + 4, values["frame_flags"])


def _memory_endpoint(state: angr.SimState, base: int) -> claripy.ast.BV:
    addresses = (
        W_BASE_COORD_X,
        W_BASE_COORD_Y,
        W_FB_TILE_COUNTER,
        W_NUM_FB_TILES,
        W_SUBANIM_TRANSFORM,
        W_FB_DEST_ADDR,
        W_FB_DEST_ADDR + 1,
        W_FB_MODE,
        W_ANIMATION_ID,
        W_SUBANIM_FRAME_DELAY,
        FRAME,
        FRAME + 1,
        FRAME + 2,
        FRAME + 3,
        FRAME + 4,
        DESTINATION,
        DESTINATION + 1,
        DESTINATION + 2,
        DESTINATION + 3,
    )
    return claripy.Concat(*(state.memory.load(base + address, 1) for address in addresses))


def _assembly(values: dict[str, claripy.ast.BV], mode: int = 2) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "DrawFrameBlock")
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
    delay = symbol_location(SYMBOLS, "DelayFrames")
    project.hook(delay.address, DelayFramesSummary(location.address + 0xC7))
    clean = symbol_location(SYMBOLS, "AnimationCleanOAM")
    project.hook(clean.address, AnimationCleanSummary(location.address + 0xDC))
    code = linked_bytes(ROM, location, 0xF1)
    project.hook(
        location.address + 0x00,
        LoadFramePointer(False, location.address + 0x01),
        length=1,
    )
    project.hook(
        location.address + 0x01,
        LoadFramePointer(True, location.address + 0x02),
        length=1,
    )
    for offset in range(len(code) - 2):
        opcode = code[offset]
        address = code[offset + 1] | (code[offset + 2] << 8)
        if code[offset + 2] == 0xD0 and opcode == 0xFA:
            project.hook(
                location.address + offset,
                Sm83LoadAImmediate(address, location.address + offset + 3),
                length=3,
            )
        elif code[offset + 2] == 0xD0 and opcode == 0xEA:
            project.hook(
                location.address + offset,
                Sm83StoreAImmediate(address, location.address + offset + 3),
                length=3,
            )
        elif opcode == 0xFE:
            project.hook(
                location.address + offset,
                CpImmediate(code[offset + 1], location.address + offset + 2),
                length=2,
            )
        elif opcode == 0x2A:
            project.hook(
                location.address + offset,
                LoadAIncrementHL(location.address + offset + 1),
                length=1,
            )
        elif opcode == 0x23:
            project.hook(
                location.address + offset,
                IncrementPair("hl", location.address + offset + 1),
                length=1,
            )
        elif opcode == 0x13:
            project.hook(
                location.address + offset,
                IncrementPair("de", location.address + offset + 1),
                length=1,
            )
        elif opcode == 0x12:
            project.hook(
                location.address + offset,
                StoreAAtDE(location.address + offset + 1),
                length=1,
            )
        elif opcode == 0x86:
            project.hook(
                location.address + offset,
                AddAAtHL(location.address + offset + 1),
                length=1,
            )
        elif opcode == 0x90:
            project.hook(
                location.address + offset,
                SubAFromB(location.address + offset + 1),
                length=1,
            )
        elif opcode == 0x47:
            project.hook(
                location.address + offset,
                LoadBFromA(location.address + offset + 1),
                length=1,
            )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.regs.bc = claripy.BVV(FRAME, 16)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(DONE, 16), endness="Iend_LE")
    _store_memory(state, 0, values)
    state.solver.add(values["mode"] == mode)
    returned = collect_returns(project, state, DONE)
    return [
        Endpoint(**assembly_registers(end), memory=_memory_endpoint(end, 0), constraints=tuple(end.solver.constraints))
        for end in returned
    ]


def _native(values: dict[str, claripy.ast.BV], mode: int = 2) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_draw_frame_block")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, claripy.BVV(FRAME, 16), endness="Iend_LE")
    _store_memory(state, NATIVE_MEMORY, values)
    state.solver.add(values["mode"] == mode)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=_memory_endpoint(end, NATIVE_MEMORY),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.parametrize("transform", [0, 1, 2, 3])
@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_draw_frame_block_mode02_each_transformation_pathwise_equivalence(
    transform: int,
) -> None:
    values = _inputs(f"draw_frame_block_{transform}")
    for register in REGISTERS:
        values[register] = claripy.BVV(0, 8)
    values["mode"] = claripy.BVV(2, 8)
    values["dest_high"] = claripy.BVV(DESTINATION >> 8, 8)
    values["dest_low"] = claripy.BVV(DESTINATION & 0xFF, 8)
    values["transform"] = claripy.BVV(transform, 8)
    values["b"] = claripy.BVV(FRAME >> 8, 8)
    values["c"] = claripy.BVV(FRAME & 0xFF, 8)
    assert_pathwise_equivalent(_assembly(values), _native(values), (*REGISTERS, "memory"))
@pytest.mark.parametrize("mode", [3, 4])
@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_draw_frame_block_delay_modes_pathwise_equivalence(mode: int) -> None:
    values = _inputs(f"draw_frame_block_mode_{mode}")
    for register in REGISTERS:
        values[register] = claripy.BVV(0, 8)
    values["mode"] = claripy.BVV(mode, 8)
    values["animation_id"] = claripy.BVV(0, 8)
    values["frame_delay"] = claripy.BVV(1, 8)
    values["dest_high"] = claripy.BVV(DESTINATION >> 8, 8)
    values["dest_low"] = claripy.BVV(DESTINATION & 0xFF, 8)
    values["transform"] = claripy.BVV(0, 8)
    values["b"] = claripy.BVV(FRAME >> 8, 8)
    values["c"] = claripy.BVV(FRAME & 0xFF, 8)
    assert_pathwise_equivalent(
        _assembly(values, mode), _native(values, mode), (*REGISTERS, "memory")
    )
@pytest.mark.parametrize("mode", [0, 1])
@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_draw_frame_block_cleanup_modes_pathwise_equivalence(mode: int) -> None:
    values = _inputs(f"draw_frame_block_cleanup_{mode}")
    for register in REGISTERS:
        values[register] = claripy.BVV(0, 8)
    values["mode"] = claripy.BVV(mode, 8)
    values["animation_id"] = claripy.BVV(0, 8)
    values["frame_delay"] = claripy.BVV(1, 8)
    values["dest_high"] = claripy.BVV(DESTINATION >> 8, 8)
    values["dest_low"] = claripy.BVV(DESTINATION & 0xFF, 8)
    values["transform"] = claripy.BVV(0, 8)
    values["b"] = claripy.BVV(FRAME >> 8, 8)
    values["c"] = claripy.BVV(FRAME & 0xFF, 8)
    assert_pathwise_equivalent(
        _assembly(values, mode), _native(values, mode), (*REGISTERS, "memory")
    )
@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_draw_frame_block_growl_skips_oam_cleanup() -> None:
    values = _inputs("draw_frame_block_growl")
    for register in REGISTERS:
        values[register] = claripy.BVV(0, 8)
    values["mode"] = claripy.BVV(0, 8)
    values["animation_id"] = claripy.BVV(0x2D, 8)
    values["frame_delay"] = claripy.BVV(1, 8)
    values["dest_high"] = claripy.BVV(DESTINATION >> 8, 8)
    values["dest_low"] = claripy.BVV(DESTINATION & 0xFF, 8)
    values["transform"] = claripy.BVV(0, 8)
    values["b"] = claripy.BVV(FRAME >> 8, 8)
    values["c"] = claripy.BVV(FRAME & 0xFF, 8)
    assert_pathwise_equivalent(
        _assembly(values, 0), _native(values, 0), (*REGISTERS, "memory")
    )
