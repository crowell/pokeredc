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
DONE = 0xEFFF
W_WHICH_BATTLE_ANIM_TILESET = 0xD09F
W_TEMP_TILESET_NUM_TILES = 0xD07D
H_AUTO_BG_TRANSFER_ENABLED = 0xFFBA
EXPECTED = bytes.fromhex(
    "fa9fd0878721f2415f1600192aea7dd02a5f7e57211083061efa7dd04f"
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
    num_tiles: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class LoadAAbsolute(angr.SimProcedure):
    def __init__(self, address: int, next_address: int) -> None:
        super().__init__()
        self.address = address
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self.address, 1)
        self.jump(self.next_address)


class AddA(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        left = self.state.regs.a
        wide = claripy.ZeroExt(1, left) + claripy.ZeroExt(1, left)
        self.state.regs.a = wide[7:0]
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)
        )
        self.state.regs.f |= claripy.If(
            (left & 0x0F) + (left & 0x0F) > 0x0F,
            claripy.BVV(0x10, 8),
            claripy.BVV(0, 8),
        )
        self.state.regs.f |= claripy.ZeroExt(7, wide[8])
        self.jump(self.addr + 1)
class StoreAAbsolute(angr.SimProcedure):
    def __init__(self, address: int, next_address: int) -> None:
        super().__init__()
        self.address = address
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(self.address, self.state.regs.a)
        self.jump(self.next_address)


class AddHLDE(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        left = self.state.regs.hl
        right = self.state.regs.de
        result = left + right
        flags = self.state.regs.f & 0x42
        flags |= claripy.If(
            (left & 0x0FFF) + (right & 0x0FFF) > 0x0FFF,
            claripy.BVV(0x10, 8),
            claripy.BVV(0, 8),
        )
        flags |= claripy.If(
            claripy.ZeroExt(1, left) + claripy.ZeroExt(1, right) > 0xFFFF,
            claripy.BVV(1, 8),
            claripy.BVV(0, 8),
        )
        self.state.regs.hl = result
        self.state.regs.f = flags
        self.jump(self.addr + 1)


class LoadAAtHLIncrement(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self.state.regs.hl, 1)
        self.state.regs.hl = self.state.regs.hl + 1
        self.jump(self.addr + 1)


class LoadAAtHL(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self.state.regs.hl, 1)
        self.jump(self.addr + 1)


class CopyVideoDataSummary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(H_AUTO_BG_TRANSFER_ENABLED, 1)
        self.state.regs.c = self.state.regs.c & 7
        self.state.regs.f = self.state.globals["copy_flags"]
        self.jump(DONE)


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    return symbolic_registers(prefix)


def _setup(state: angr.SimState, base: int, tileset: int) -> None:
    state.memory.store(base + W_WHICH_BATTLE_ANIM_TILESET, claripy.BVV(tileset, 8))
    state.memory.store(base + H_AUTO_BG_TRANSFER_ENABLED, claripy.BVV(0, 8))


def _endpoint(state: angr.SimState, base: int, native: bool) -> Endpoint:
    registers = native_registers(state, NATIVE_STATE) if native else assembly_registers(state)
    return Endpoint(
        **registers,
        num_tiles=state.memory.load(base + W_TEMP_TILESET_NUM_TILES, 1),
        constraints=tuple(state.solver.constraints),
    )


def _assembly(values: dict[str, claripy.ast.BV], tileset: int) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "LoadMoveAnimationTiles")
    assert location.bank == 0x1E
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
    body = linked_bytes(ROM, location, len(EXPECTED))
    for offset, opcode in enumerate(body):
        address = base + offset
        if opcode == 0xFA:
            target = body[offset + 1] | (body[offset + 2] << 8)
            project.hook(address, LoadAAbsolute(target, address + 3), length=3)
        elif opcode == 0xEA:
            target = body[offset + 1] | (body[offset + 2] << 8)
            project.hook(address, StoreAAbsolute(target, address + 3), length=3)
        elif opcode == 0x87:
            project.hook(address, AddA(), length=1)
        elif opcode == 0x19:
            project.hook(address, AddHLDE(), length=1)
        elif opcode == 0x2A:
            project.hook(address, LoadAAtHLIncrement(), length=1)
        elif opcode == 0x7E:
            project.hook(address, LoadAAtHL(), length=1)
    copy = symbol_location(SYMBOLS, "CopyVideoData")
    assert copy.bank == 0
    project.hook(copy.address, CopyVideoDataSummary(), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.globals["copy_flags"] = claripy.BVV(0x40 if tileset == 0 else 0, 8)
    _setup(state, 0, tileset)
    state.memory.store(0xD000, claripy.BVV(DONE, 16), endness="Iend_LE")
    state.regs.sp = 0xD000
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=4)
    assert not manager.errored
    assert len(manager.found) == 1
    return [_endpoint(manager.found[0], 0, False)]


def _native(values: dict[str, claripy.ast.BV], tileset: int) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_load_move_animation_tiles")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, NATIVE_MEMORY, tileset)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    return [_endpoint(manager.deadended[0], NATIVE_MEMORY, True)]


@pytest.mark.parametrize("tileset", (0, 1, 2))
@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_load_move_animation_tiles_pathwise_equivalence(tileset: int) -> None:
    location = symbol_location(SYMBOLS, "LoadMoveAnimationTiles")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    values = _inputs(f"load_move_animation_tiles_{tileset}")
    assert_pathwise_equivalent(
        _assembly(values, tileset),
        _native(values, tileset),
        (*REGISTERS, "num_tiles"),
    )
