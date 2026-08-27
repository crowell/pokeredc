from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS, assembly_registers, native_registers, set_assembly_registers, store_native_registers, symbolic_registers
from verification.harness.rom import linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import Sm83LoadAHighImmediate, Sm83LoadAImmediate, Sm83StoreAHighImmediate

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF
W_MAP = 0xC6E8
W_MAP_END = 0xCBFC
W_BACKGROUND = 0xD3AD
W_HEIGHT = 0xD368
W_WIDTH = 0xD369
W_DATA_PTR = 0xD36A
CONNECTIONS = (0xD371, 0xD37C, 0xD387, 0xD392)
H_STRIDE = 0xFF8B
H_WIDTH = 0xFF8C


@dataclass(frozen=True)
class Endpoint:
    a: claripy.ast.BV; f: claripy.ast.BV; b: claripy.ast.BV; c: claripy.ast.BV
    d: claripy.ast.BV; e: claripy.ast.BV; h: claripy.ast.BV; l: claripy.ast.BV
    map0: claripy.ast.BV; map1: claripy.ast.BV; map2: claripy.ast.BV; map3: claripy.ast.BV
    map4: claripy.ast.BV; map5: claripy.ast.BV; map6: claripy.ast.BV; map7: claripy.ast.BV
    map8: claripy.ast.BV; map9: claripy.ast.BV; map10: claripy.ast.BV; map11: claripy.ast.BV
    map12: claripy.ast.BV; stride: claripy.ast.BV; width: claripy.ast.BV
    data: claripy.ast.BV; constraints: tuple[claripy.ast.Bool, ...]


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]: return symbolic_registers(prefix)


def _setup(state: angr.SimState, base: int) -> None:
    state.memory.store(base + W_BACKGROUND, claripy.BVV(0xEE, 8))
    state.memory.store(base + W_HEIGHT, claripy.BVV(3, 8))
    state.memory.store(base + W_WIDTH, claripy.BVV(4, 8))
    state.memory.store(base + W_DATA_PTR, claripy.BVV(0x9000, 16), endness="Iend_LE")
    for i in range(12): state.memory.store(base + 0x9000 + i, claripy.BVV(0x40 + i, 8))
    for address in CONNECTIONS: state.memory.store(base + address, claripy.BVV(0xFF, 8))
    for address in range(W_MAP, W_MAP_END): state.memory.store(base + address, claripy.BVV(0x11, 8))


def _memory_fields(state: angr.SimState, base: int) -> dict[str, claripy.ast.BV]:
    return {
        **{f"map{i}": state.memory.load(base + W_MAP + i * 100, 100) for i in range(13)},
        "stride": state.memory.load(base + H_STRIDE, 1),
        "width": state.memory.load(base + H_WIDTH, 1),
        "data": state.memory.load(base + W_DATA_PTR, 2, endness="Iend_LE"),
    }


class BackgroundFill(angr.SimProcedure):
    """Summarize the fixed 0x514-byte background-fill loop."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        background = self.state.regs.d
        for address in range(W_MAP, W_MAP_END):
            self.state.memory.store(address, background)
        self.state.regs.h = claripy.BVV(W_MAP_END >> 8, 8)
        self.state.regs.l = claripy.BVV(W_MAP_END & 0xFF, 8)
        self.state.regs.b = claripy.BVV(0, 8)
        self.state.regs.c = claripy.BVV(0, 8)
        self.jump(self.next_address)


class ReturnSummary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(DONE)


class DisabledConnectionBranch(angr.SimProcedure):
    """Model the SM83 ``cp $ff; jr z`` sequence for a disabled link.

    The p-code backend does not currently propagate the flags produced by this
    pair reliably.  The test setup fixes each connection byte to ``$ff``, so
    this shim only summarizes that deterministic branch and leaves the rest of
    ``LoadTileBlockMap`` as the linked instructions under test.
    """

    def __init__(self, target: int) -> None:
        super().__init__()
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0xFF, 8)
        self.state.regs.f = claripy.BVV(0x42, 8)  # Z|N in the p-code/Z80 flag layout
        self.jump(self.target)


class LoadAAtDeIncrement(angr.SimProcedure):
    """Implement the SM83 ``ld a,[de]; inc de`` pair used by the row copy."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self.state.regs.de, 1)
        self.state.regs.de = self.state.regs.de + 1
        self.jump(self.next_address)


class MoveAToRegister(angr.SimProcedure):
    """Implement an 8-bit ``ld r,a`` register transfer."""

    def __init__(self, register: str, next_address: int) -> None:
        super().__init__()
        self.register = register
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.register, self.state.regs.a)
        self.jump(self.next_address)


class StoreAAtHlIncrement(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(self.state.regs.hl, self.state.regs.a)
        self.state.regs.hl = self.state.regs.hl + 1
        self.jump(self.next_address)


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    loc = symbol_location(SYMBOLS, "LoadTileBlockMap")
    end = symbol_location(SYMBOLS, "LoadNorthSouthConnectionsTileMap")
    body = linked_bytes(ROM, loc, end.address - loc.address)
    assert len(body) == end.address - loc.address
    assert body[:16] == bytes.fromhex("21e8c6faadd3570114057a220b79b020")
    assert body[-9:] == bytes.fromhex("fa98d3e08bcd020bc9")
    project = angr.Project(rom_window(ROM, loc.bank), auto_load_libs=False, rebase_granularity=0x100, main_opts={"backend":"blob", "arch":ArchPcode("z80:LE:16:default"), "base_addr":0, "entry_point":loc.address})
    project.hook(loc.address + 0x0A, BackgroundFill(loc.address + 0x11), length=7)
    # The Z80 p-code backend lacks the SM83 LDH opcodes used for the map
    # stride/width shadow registers.  Hook each individual instruction while
    # retaining the surrounding linked body.
    for offset, high_offset in ((0x17, 0x8C), (0x1B, 0x8B), (0x33, 0x8C),
                                (0x3D, 0x8B), (0x64, 0x8B), (0x69, 0x8C),
                                (0x8B, 0x8B), (0x90, 0x8C), (0xB6, 0x8B),
                                (0xDC, 0x8B)):
        opcode = body[offset]
        shim = (Sm83StoreAHighImmediate if opcode == 0xE0 else Sm83LoadAHighImmediate)
        project.hook(loc.address + offset, shim(high_offset, loc.address + offset + 2), length=2)
    # Likewise model the absolute ``ld a,[nn]`` reads explicitly; this keeps
    # the p-code execution focused on the data-copy instructions and avoids
    # backend gaps around the 16-bit blob address space.
    for offset in (0x03, 0x14, 0x26, 0x2A, 0x2E, 0x47, 0x51, 0x55,
                   0x59, 0x5D, 0x61, 0x66, 0x6E, 0x78, 0x7C, 0x80, 0x84,
                   0x88, 0x8D, 0x95, 0x9F, 0xA3, 0xA7, 0xAB, 0xAF, 0xB3,
                   0xBB, 0xC5, 0xC9, 0xCD, 0xD1, 0xD5, 0xD9):
        assert body[offset] == 0xFA
        address = body[offset + 1] | (body[offset + 2] << 8)
        project.hook(loc.address + offset, Sm83LoadAImmediate(address, loc.address + offset + 3), length=3)
    # See DisabledConnectionBranch: all four links are $ff in _setup.
    for offset, target in ((0x4A, 0x6E), (0x71, 0x95), (0x98, 0xBB), (0xBE, 0xE1)):
        project.hook(loc.address + offset, DisabledConnectionBranch(loc.address + target), length=3)
    project.hook(loc.address + 0x36, LoadAAtDeIncrement(loc.address + 0x38), length=2)
    project.hook(loc.address + 0x38, StoreAAtHlIncrement(loc.address + 0x39), length=1)
    project.hook(loc.address + 0x1F, MoveAToRegister("c", loc.address + 0x20), length=1)
    project.hook(loc.address + 0x31, MoveAToRegister("b", loc.address + 0x32), length=1)
    project.hook(loc.address + 0x35, MoveAToRegister("c", loc.address + 0x36), length=1)
    project.hook(end.address - 1, ReturnSummary(), length=1)
    state = project.factory.blank_state(addr=loc.address); set_assembly_registers(state, values); _setup(state, 0)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state); manager.explore(find=DONE, num_find=2)
    assert not manager.errored and len(manager.found) == 1
    return [Endpoint(**assembly_registers(x), **_memory_fields(x, 0), constraints=tuple(x.solver.constraints)) for x in manager.found]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_load_tile_block_map"); assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values); _setup(state, NATIVE_MEMORY)
    manager = project.factory.simulation_manager(state); manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [Endpoint(**native_registers(x, NATIVE_STATE), **_memory_fields(x, NATIVE_MEMORY), constraints=tuple(x.solver.constraints)) for x in manager.deadended]


@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_load_tile_block_map_current_map_pathwise_equivalence() -> None:
    values = _inputs("load_tile_block_map")
    assert_pathwise_equivalent(_assembly(values), _native(values), (*REGISTERS, *(f"map{i}" for i in range(13)), "stride", "width", "data"))
