from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
    REGISTERS, assembly_registers, native_registers, set_assembly_registers,
    store_native_registers,
)
from verification.harness.rom import linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import (
    Sm83CpImmediate, Sm83LoadAAtHlIncrement, Sm83LoadAImmediate,
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
W_FACING = 0xC109
W_TILEMAP = 0xC3A0
W_TILE_FRONT = 0xCFC6
W_COLLISION_PTR = 0xD530
W_TILE_RESULT = 0xD71C
W_TILESET = 0xD367
W_STANDING = 0xC45C
PAIR_TABLE = 0x0C7E
W_BOULDER_INDEX = 0xD718
W_NUM_SPRITES = 0xD4E1
H_PLAYER_FACING = 0xFFDB
BOULDER_RECORD = 0xC214


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


class LoadHLImmediate(angr.SimProcedure):
    def __init__(self, value: int, next_address: int) -> None:
        super().__init__()
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.hl = claripy.BVV(self.value, 16)
        self.jump(self.next_address)


class LoadHAtHL(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = self.state.memory.load(self.state.regs.hl, 1)
        self.jump(self.next_address)


class LoadLFromA(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.l = self.state.regs.a
        self.jump(self.next_address)


class GetTileTwoStepsBoundary(angr.SimProcedure):
    def __init__(self, next_address: int, tile: int) -> None:
        super().__init__()
        self.next_address = next_address
        self.tile = tile

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(self.tile, 8)
        self.state.regs.c = claripy.BVV(self.tile, 8)
        self.state.regs.d = claripy.BVV(1, 8)
        self.state.regs.e = claripy.BVV(0, 8)
        self.state.regs.hl = claripy.BVV(0xFFDB, 16)
        self.state.memory.store(W_TILE_FRONT, claripy.BVV(self.tile, 8))
        self.state.memory.store(W_TILE_RESULT, claripy.BVV(self.tile, 8))
        self.jump(self.next_address)


class BranchZ(angr.SimProcedure):
    def __init__(self, taken: int, fallthrough: int) -> None:
        super().__init__()
        self.taken = taken
        self.fallthrough = fallthrough

    def run(self) -> None:  # type: ignore[override]
        condition = (self.state.regs.f & 0x40) != 0
        self.inhibit_autoret = True
        self.successors.add_successor(self.state.copy(), self.taken,
                                      condition, "Ijk_Boring")
        self.successors.add_successor(self.state.copy(), self.fallthrough,
                                      claripy.Not(condition), "Ijk_Boring")


class BranchCarry(angr.SimProcedure):
    def __init__(self, taken: int, fallthrough: int) -> None:
        super().__init__()
        self.taken = taken
        self.fallthrough = fallthrough

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        carry = (self.state.regs.f & 0x01) != 0
        self.successors.add_successor(self.state.copy(), self.taken,
                                      carry, "Ijk_Boring")
        self.successors.add_successor(self.state.copy(), self.fallthrough,
                                      claripy.Not(carry), "Ijk_Boring")


class TilePairBoundary(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__()
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        m = self.state.memory
        pointer = self.state.solver.eval(self.state.regs.hl)
        front = self.state.solver.eval(m.load(W_TILE_FRONT, 1))
        tileset = self.state.solver.eval(m.load(W_TILESET, 1))
        standing = self.state.solver.eval(m.load(W_TILEMAP + 9 * 20 + 8, 1))
        m.store(W_STANDING, claripy.BVV(standing, 8))
        while True:
            entry = self.state.solver.eval(m.load(pointer, 1))
            pointer = (pointer + 1) & 0xffff
            if entry == 0xff:
                self.state.regs.a = claripy.BVV(0xff, 8)
                self.state.regs.b = claripy.BVV(tileset, 8)
                self.state.regs.f = claripy.BVV(0x10, 8)
                break
            first = self.state.solver.eval(m.load(pointer, 1))
            second = self.state.solver.eval(m.load((pointer + 1) & 0xffff, 1))
            if entry == tileset and ((standing == first and front == second) or
                                     (standing == second and front == first)):
                pointer = (pointer + 1) & 0xffff
                self.state.regs.a = claripy.BVV(front, 8)
                self.state.regs.b = claripy.BVV(standing, 8)
                self.state.regs.f = claripy.BVV(0x41, 8)
                break
            pointer = (pointer + 2) & 0xffff
        self.state.regs.hl = claripy.BVV(pointer, 16)
        self.jump(self.target)


class BoulderSpritesBoundary(angr.SimProcedure):
    def __init__(self, target: int, collision: bool) -> None:
        super().__init__()
        self.target = target
        self.collision = collision

    def run(self) -> None:  # type: ignore[override]
        # The setup below uses two horizontal sprite records.  These are the
        # exact terminal registers of the independently proven sprite scan.
        self.state.regs.d = claripy.BVV(0, 8)
        self.state.regs.e = claripy.BVV(15, 8)
        self.state.regs.h = claripy.BVV(0xC2, 8)
        self.state.regs.l = claripy.BVV(0x25 if self.collision else 0x15, 8)
        self.state.regs.b = claripy.BVV(21 if self.collision else 20, 8)
        self.state.regs.c = claripy.BVV(1 if self.collision else 0, 8)
        self.state.regs.a = claripy.BVV(0xFF if self.collision else 0, 8)
        # The ROM side exposes Z80 flag positions; the native port stores
        # canonical SM83 flags, and the endpoint adapter maps them back.
        self.state.regs.f = claripy.BVV(0x42 if self.collision else 0x40, 8)
        self.jump(self.target)


class CompareCollisionTile(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        tile = self.state.memory.load(W_TILE_FRONT, 1)
        self.state.regs.c = tile
        self.state.regs.f = claripy.If(
            self.state.regs.a == tile,
            claripy.BVV(0x40, 8),
            claripy.BVV(0x02, 8),
        )
        self.jump(self.next_address)


def _setup(state: angr.SimState, base: int, *, tile: int,
           collision_entry: int, tileset: int = 0,
           standing: int = 0x20, pair_collision: bool = False,
           sprite_collision: bool = False) -> None:
    for address, value in ((W_Y, 0), (W_X, 0), (W_FACING, 0),
                           (W_TILE_FRONT, tile), (W_TILE_RESULT, 0)):
        state.memory.store(base + address, claripy.BVV(value, 8))
    state.memory.store(base + W_COLLISION_PTR,
                       claripy.BVV(0x0700, 16), endness="Iend_LE")
    state.memory.store(base + W_TILEMAP + 13 * 20 + 8,
                       claripy.BVV(tile, 8))
    state.memory.store(base + W_TILEMAP + 9 * 20 + 8,
                       claripy.BVV(standing, 8))
    state.memory.store(base + W_TILESET, claripy.BVV(tileset, 8))
    state.memory.store(base + W_BOULDER_INDEX, claripy.BVV(1, 8))
    state.memory.store(base + W_NUM_SPRITES,
                       claripy.BVV(2 if sprite_collision else 1, 8))
    state.memory.store(base + H_PLAYER_FACING, claripy.BVV(0, 8))
    state.memory.store(base + BOULDER_RECORD, claripy.BVV(10, 8))
    state.memory.store(base + BOULDER_RECORD + 1, claripy.BVV(20, 8))
    state.memory.store(base + BOULDER_RECORD + 0x10,
                       claripy.BVV(10 if sprite_collision else 0, 8))
    state.memory.store(base + BOULDER_RECORD + 0x11,
                       claripy.BVV(21 if sprite_collision else 20, 8))
    state.memory.store(base + 0x0700, claripy.BVV(collision_entry, 8))
    state.memory.store(base + 0x0701, claripy.BVV(0xFF, 8))
    if pair_collision:
        for offset, value in enumerate((tileset, standing, tile, 0xFF)):
            state.memory.store(base + PAIR_TABLE + offset,
                               claripy.BVV(value, 8))
    else:
        state.memory.store(base + PAIR_TABLE, claripy.BVV(0xFF, 8))


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(*(state.memory.load(base + address, 1) for address in (
        W_TILE_FRONT, W_TILE_RESULT,
    )))


def _endpoint(state: angr.SimState, *, native: bool, base: int) -> Endpoint:
    return Endpoint(
        **(native_registers(state, NATIVE_STATE) if native else assembly_registers(state)),
        memory=_memory(state, base), constraints=tuple(state.solver.constraints)
    )


def _assembly(values: dict[str, claripy.ast.BV], *, tile: int,
              collision_entry: int, tileset: int = 0,
              standing: int = 0x20, pair_collision: bool = False,
              sprite_collision: bool = False) -> list[Endpoint]:
    loc = symbol_location(SYMBOLS, "CheckForCollisionWhenPushingBoulder")
    end = symbol_location(SYMBOLS, "CheckForBoulderCollisionWithSprites")
    assert linked_bytes(ROM, loc, end.address - loc.address) == bytes.fromhex(
        "cdbe452130d52a666f2afeff2819b920f8217e0ccd440c3eff380cfa1cd7fe153eff2803cd3646ea1cd7c9"
    )
    project = angr.Project(rom_window(ROM, loc.bank), auto_load_libs=False,
                           rebase_granularity=0x100,
                           main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                                      "base_addr": 0, "entry_point": loc.address})
    q = loc.address
    project.hook(q + 0x00, GetTileTwoStepsBoundary(q + 0x03, tile), length=3)
    project.hook(q + 0x03, LoadHLImmediate(W_COLLISION_PTR, q + 0x06), length=3)
    project.hook(q + 0x06, Sm83LoadAAtHlIncrement(q + 0x07), length=1)
    project.hook(q + 0x07, LoadHAtHL(q + 0x08), length=1)
    project.hook(q + 0x08, LoadLFromA(q + 0x09), length=1)
    project.hook(q + 0x09, Sm83LoadAAtHlIncrement(q + 0x0A), length=1)
    project.hook(q + 0x0A, Sm83CpImmediate(0xFF, q + 0x0C), length=2)
    project.hook(q + 0x0C, BranchZ(q + 0x27, q + 0x0E), length=2)
    project.hook(q + 0x27, Sm83StoreAImmediate(W_TILE_RESULT, q + 0x2A), length=3)
    if collision_entry != 0xFF:
        project.hook(q + 0x0E, CompareCollisionTile(q + 0x0F), length=1)
        project.hook(q + 0x0F, BranchZ(q + 0x11, q + 0x09), length=2)
        project.hook(q + 0x11, LoadHLImmediate(PAIR_TABLE, q + 0x14), length=3)
        project.hook(q + 0x14, TilePairBoundary(q + 0x17), length=3)
        project.hook(q + 0x19, BranchCarry(q + 0x27, q + 0x1B), length=2)
        project.hook(q + 0x1B, Sm83LoadAImmediate(W_TILE_RESULT, q + 0x1E), length=3)
        project.hook(q + 0x1E, Sm83CpImmediate(0x15, q + 0x20), length=2)
        project.hook(q + 0x22, BranchZ(q + 0x27, q + 0x24), length=2)
        project.hook(q + 0x24,
                     BoulderSpritesBoundary(q + 0x27, sprite_collision),
                     length=3)
    state = project.factory.blank_state(addr=loc.address)
    set_assembly_registers(state, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    _setup(state, 0, tile=tile, collision_entry=collision_entry,
           tileset=tileset, standing=standing, pair_collision=pair_collision,
           sprite_collision=sprite_collision)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN, num_find=8)
    assert not manager.errored and manager.found
    return [_endpoint(end_state, native=False, base=0) for end_state in manager.found]


def _native(values: dict[str, claripy.ast.BV], *, tile: int,
            collision_entry: int, tileset: int = 0,
            standing: int = 0x20, pair_collision: bool = False,
            sprite_collision: bool = False) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_check_for_collision_when_pushing_boulder")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, NATIVE_MEMORY, tile=tile, collision_entry=collision_entry,
           tileset=tileset, standing=standing, pair_collision=pair_collision,
           sprite_collision=sprite_collision)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and manager.deadended
    return [_endpoint(end_state, native=True, base=NATIVE_MEMORY)
            for end_state in manager.deadended]


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),
                    reason="build artifacts missing")
@pytest.mark.parametrize("collision_entry, tile, pair_collision, sprite_collision", (
    (0xFF, 0x37, False, False),
    (0x00, 0x37, False, False),
    (0x05, 0x05, True, False),
    (0x15, 0x15, False, False),
    (0x05, 0x05, False, False),
    (0x05, 0x05, False, True),
))
def test_check_for_collision_when_pushing_boulder_pathwise_equivalence(
    collision_entry: int, tile: int, pair_collision: bool,
    sprite_collision: bool,
) -> None:
    values = {register: claripy.BVV(0, 8) for register in REGISTERS}
    assert_pathwise_equivalent(
        _assembly(values, tile=tile, collision_entry=collision_entry,
                  pair_collision=pair_collision,
                  sprite_collision=sprite_collision),
        _native(values, tile=tile, collision_entry=collision_entry,
                pair_collision=pair_collision,
                sprite_collision=sprite_collision),
        (*REGISTERS, "memory"),
    )
