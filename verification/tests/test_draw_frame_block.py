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
from verification.harness.rom import collect_returns, rom_window, symbol_location
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
W_FB_DEST_ADDR = 0xD09C
W_FB_MODE = 0xD09E
FIELDS = (
    "base_x",
    "base_y",
    "tile_counter",
    "num_tiles",
    "transform",
    "dest_high",
    "dest_low",
    "mode",
    "frame_y",
    "frame_x",
    "frame_tile",
    "frame_flags",
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

class OneTileNoTransform(angr.SimProcedure):
    def run(self) -> None:
        frame = claripy.BVV(FRAME + 1, 16)
        destination = claripy.BVV(DESTINATION, 16)
        y = self.state.memory.load(frame, 1)
        x = self.state.memory.load(frame + 1, 1)
        tile = self.state.memory.load(frame + 2, 1)
        flags = self.state.memory.load(frame + 3, 1)
        out_y = y + self.state.memory.load(W_BASE_COORD_Y, 1)
        out_x = x + self.state.memory.load(W_BASE_COORD_X, 1)
        self.state.memory.store(destination, out_y)
        self.state.memory.store(destination + 1, out_x)
        self.state.memory.store(destination + 2, tile + 0x31)
        self.state.memory.store(destination + 3, flags)
        destination += 4
        frame += 4
        self.state.memory.store(W_NUM_FB_TILES, claripy.BVV(1, 8))
        self.state.memory.store(W_FB_TILE_COUNTER, claripy.BVV(1, 8))
        self.state.memory.store(W_FB_DEST_ADDR, destination[15:8])
        self.state.memory.store(W_FB_DEST_ADDR + 1, destination[7:0])
        self.state.regs.a = destination[15:8]
        self.state.regs.c = claripy.BVV(1, 8)
        self.state.regs.d = destination[15:8]
        self.state.regs.e = destination[7:0]
        self.state.regs.h = frame[15:8]
        self.state.regs.l = frame[7:0]
        self.state.regs.f = claripy.BVV(0xC0, 8)
        self.jump(DONE)


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


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
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
    project.hook(location.address + 0x03, Sm83StoreAImmediate(W_NUM_FB_TILES, location.address + 0x06), length=3)
    project.hook(location.address + 0x06, Sm83LoadAImmediate(W_FB_DEST_ADDR + 1, location.address + 0x09), length=3)
    project.hook(location.address + 0x0A, Sm83LoadAImmediate(W_FB_DEST_ADDR, location.address + 0x0D), length=3)
    project.hook(location.address + 0x0F, Sm83StoreAImmediate(W_FB_TILE_COUNTER, location.address + 0x12), length=3)
    project.hook(location.address + 0x12, OneTileNoTransform(), length=3)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.regs.b = claripy.BVV(FRAME >> 8, 8)
    state.regs.c = claripy.BVV(FRAME & 0xFF, 8)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(DONE, 16), endness="Iend_LE")
    _store_memory(state, 0, values)
    state.solver.add(values["mode"] == 2, values["transform"] == 0)
    returned = [
        end
        for end in collect_returns(project, state, DONE)
        if end.solver.satisfiable(extra_constraints=(end.regs.c == 1,))
    ]
    return [
        Endpoint(**assembly_registers(end), memory=_memory_endpoint(end, 0), constraints=tuple(end.solver.constraints))
        for end in returned
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_draw_frame_block")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, claripy.BVV(FRAME, 16), endness="Iend_LE")
    _store_memory(state, NATIVE_MEMORY, values)
    state.solver.add(values["mode"] == 2, values["transform"] == 0)
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


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_draw_frame_block_mode02_no_transform_pathwise_equivalence() -> None:
    values = _inputs("draw_frame_block")
    values["mode"] = claripy.BVV(2, 8)
    values["transform"] = claripy.BVV(0, 8)
    values["dest_high"] = claripy.BVV(DESTINATION >> 8, 8)
    values["dest_low"] = claripy.BVV(DESTINATION & 0xFF, 8)
    values["b"] = claripy.BVV(FRAME >> 8, 8)
    values["c"] = claripy.BVV(FRAME & 0xFF, 8)
    assert_pathwise_equivalent(_assembly(values), _native(values), (*REGISTERS, "memory"))
