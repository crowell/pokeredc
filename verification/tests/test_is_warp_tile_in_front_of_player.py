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
    Sm83AddHlRegisterPair,
    Sm83AndRegister,
    Sm83CpImmediate,
    Sm83LoadAAtHlIncrement,
    Sm83LoadAImmediate,
    Sm83Scf,
    Sm83SrlRegister,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xDFF0
RETURN = 0xEFFF
W_Y_COORD = 0xD361
W_X_COORD = 0xD362
W_FACING = 0xC109
W_TILE_IN_FRONT = 0xCFC6
W_CUR_MAP = 0xD35E
W_TILE_MAP = 0xC3A0
WARP_TABLE = 0x4477
LISTS = (0x447F, 0x4487, 0x448A, 0x448D)
EXPECTED_BODY = bytes.fromhex(
    "e5d5c5cd8945fa5ed3fe632835fa09c1cb3f4f0600217744092a666ffac6cf110100cdab3dc1d1e1c9"
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


class GetTileAndCoordsBoundary(angr.SimProcedure):
    """Complete transition of the proven GetTileAndCoordsInFrontOfPlayer callee."""

    def __init__(self, target: int) -> None:
        super().__init__()
        self._target = target

    def run(self) -> None:  # type: ignore[override]
        y = self.state.memory.load(W_Y_COORD, 1)
        x = self.state.memory.load(W_X_COORD, 1)
        facing = self.state.memory.load(W_FACING, 1)
        self.state.regs.d = y
        self.state.regs.e = x
        tile_address: int | None = None
        old = y
        if self.state.solver.is_true(facing == 0):
            y = y + 1
            tile_address = W_TILE_MAP + 11 * 20 + 8
            flags = self._inc_flags(old, y)
        elif self.state.solver.is_true(facing == 4):
            y = y - 1
            tile_address = W_TILE_MAP + 7 * 20 + 8
            flags = self._dec_flags(old, y)
        elif self.state.solver.is_true(facing == 8):
            x = x - 1
            tile_address = W_TILE_MAP + 9 * 20 + 6
            flags = self._dec_flags(x + 1, x)
        elif self.state.solver.is_true(facing == 12):
            x = x + 1
            tile_address = W_TILE_MAP + 9 * 20 + 10
            flags = self._inc_flags(x - 1, x)
        else:
            self.state.regs.a = facing
            flags = self._cp_flags(facing, 12)
        self.state.regs.d = y
        self.state.regs.e = x
        if tile_address is not None:
            self.state.regs.a = self.state.memory.load(tile_address, 1)
        self.state.regs.c = self.state.regs.a
        self.state.regs.f = flags
        self.state.memory.store(W_TILE_IN_FRONT, self.state.regs.a)
        self.jump(self._target)

    @staticmethod
    def _inc_flags(old: claripy.ast.BV, result: claripy.ast.BV) -> claripy.ast.BV:
        return sm83_flags_to_z80(
            claripy.If(result == 0, claripy.BVV(0x80, 8), claripy.BVV(0, 8))
            | claripy.If((old & 0x0F) == 0x0F,
                         claripy.BVV(0x20, 8), claripy.BVV(0, 8))
        )

    @staticmethod
    def _dec_flags(old: claripy.ast.BV, result: claripy.ast.BV) -> claripy.ast.BV:
        return sm83_flags_to_z80(
            claripy.BVV(0x40, 8)
            | claripy.If(result == 0, claripy.BVV(0x80, 8), claripy.BVV(0, 8))
            | claripy.If((old & 0x0F) == 0,
                         claripy.BVV(0x20, 8), claripy.BVV(0, 8))
        )

    @staticmethod
    def _cp_flags(left: claripy.ast.BV, right: int) -> claripy.ast.BV:
        result = left - right
        return sm83_flags_to_z80(
            claripy.BVV(0x40, 8)
            | claripy.If(result == 0, claripy.BVV(0x80, 8), claripy.BVV(0, 8))
            | claripy.If((left & 0x0F) < (right & 0x0F),
                         claripy.BVV(0x20, 8), claripy.BVV(0, 8))
            | claripy.If(left.ULT(right),
                         claripy.BVV(0x10, 8), claripy.BVV(0, 8))
        )


class IsInArrayBoundary(angr.SimProcedure):
    """Complete transition of the proven IsInArray callee."""

    def run(self) -> None:  # type: ignore[override]
        pointer = self.state.solver.eval(self.state.regs.hl)
        stride = self.state.solver.eval(self.state.regs.de)
        wanted = self.state.regs.a
        self.state.regs.c = wanted
        count = 0
        while True:
            value = self.state.memory.load(pointer, 1)
            self.state.regs.a = value
            if self.state.solver.is_true(value == 0xFF):
                self.state.regs.b = claripy.BVV(count, 8)
                self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0x20, 8))
                break
            if self.state.solver.is_true(value == wanted):
                self.state.regs.b = claripy.BVV(count, 8)
                self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0x90, 8))
                break
            pointer = (pointer + stride) & 0xFFFF
            count = (count + 1) & 0xFF
        self.state.regs.hl = claripy.BVV(pointer, 16)
        ret = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp += 2
        self.jump(ret)


class LoadHFromHL(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = self.state.memory.load(self.state.regs.hl, 1)
        self.jump(self.state.addr + 1)


class LoadLFromA(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.l = self.state.regs.a
        self.jump(self.state.addr + 1)


class BranchNZ(angr.SimProcedure):
    def __init__(self, taken: int, fallthrough: int) -> None:
        super().__init__()
        self._taken = taken
        self._fallthrough = fallthrough

    def run(self) -> None:  # type: ignore[override]
        z = (self.state.regs.f & 0x40) != 0
        self.inhibit_autoret = True
        self.successors.add_successor(self.state.copy(), self._taken, ~z, "Ijk_Boring")
        self.successors.add_successor(self.state.copy(), self._fallthrough, z, "Ijk_Boring")


def _setup(state: angr.SimState, base: int, *, map_id: int, facing: int,
           tile: int, list_values: tuple[int, ...]) -> None:
    state.memory.store(base + W_CUR_MAP, claripy.BVV(map_id, 8))
    state.memory.store(base + W_FACING, claripy.BVV(facing, 8))
    state.memory.store(base + W_Y_COORD, claripy.BVV(5, 8))
    state.memory.store(base + W_X_COORD, claripy.BVV(6, 8))
    for i in range(360):
        state.memory.store(base + W_TILE_MAP + i, claripy.BVV(0, 8))
    if facing == 0:
        address = W_TILE_MAP + 11 * 20 + 8
    elif facing == 4:
        address = W_TILE_MAP + 7 * 20 + 8
    elif facing == 8:
        address = W_TILE_MAP + 9 * 20 + 6
    elif facing == 12:
        address = W_TILE_MAP + 9 * 20 + 10
    else:
        address = W_TILE_MAP
    state.memory.store(base + address, claripy.BVV(tile, 8))
    for index, pointer in enumerate(LISTS):
        state.memory.store(base + WARP_TABLE + index * 2,
                           claripy.BVV(pointer & 0xFF, 8))
        state.memory.store(base + WARP_TABLE + index * 2 + 1,
                           claripy.BVV(pointer >> 8, 8))
        values = list_values if index == (facing >> 2) else (0xFF,)
        for offset in range(4):
            value = values[offset] if offset < len(values) else 0xFF
            state.memory.store(base + pointer + offset, claripy.BVV(value, 8))


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        state.memory.load(base + W_CUR_MAP, 1),
        state.memory.load(base + W_FACING, 1),
        state.memory.load(base + W_TILE_IN_FRONT, 1),
        *(state.memory.load(base + address, 1) for address in (
            W_TILE_MAP + 11 * 20 + 8,
            W_TILE_MAP + 7 * 20 + 8,
            W_TILE_MAP + 9 * 20 + 6,
            W_TILE_MAP + 9 * 20 + 10,
        )),
        state.memory.load(base + WARP_TABLE, 8),
        *(state.memory.load(base + pointer, 4) for pointer in LISTS),
    )


def _endpoint(state: angr.SimState, *, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    fields = native_registers(state, NATIVE_STATE) if native else assembly_registers(state)
    return Endpoint(**fields, memory=_memory(state, base),
                    constraints=tuple(state.solver.constraints))


def _assembly(values: dict[str, claripy.ast.BV], *, map_id: int, facing: int,
              tile: int, list_values: tuple[int, ...]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "IsWarpTileInFrontOfPlayer")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    b = location.address
    project.hook(b + 3, GetTileAndCoordsBoundary(b + 6), length=3)
    special = symbol_location(SYMBOLS, "IsSSAnneBowWarpTileInFrontOfPlayer").address
    not_special = symbol_location(SYMBOLS, "IsSSAnneBowWarpTileInFrontOfPlayer.notSSAnne5Warp").address
    done = symbol_location(SYMBOLS, "IsWarpTileInFrontOfPlayer.done").address
    project.hook(b + 6, Sm83LoadAImmediate(W_CUR_MAP, b + 9), length=3)
    project.hook(b + 9, Sm83CpImmediate(0x63, b + 11), length=2)
    project.hook(b + 13, Sm83LoadAImmediate(W_FACING, b + 16), length=3)
    project.hook(b + 16, Sm83SrlRegister("a", b + 18), length=1)
    project.hook(b + 24, Sm83AddHlRegisterPair("bc", b + 25), length=1)
    project.hook(b + 25, Sm83LoadAAtHlIncrement(b + 26), length=1)
    project.hook(b + 26, LoadHFromHL(), length=1)
    project.hook(b + 27, LoadLFromA(), length=1)
    project.hook(b + 28, Sm83LoadAImmediate(W_TILE_IN_FRONT, b + 31), length=3)
    project.hook(0x3DAB, IsInArrayBoundary(), length=0x20)
    project.hook(special, Sm83LoadAImmediate(W_TILE_IN_FRONT, special + 3), length=3)
    project.hook(special + 3, Sm83CpImmediate(0x15, special + 5), length=2)
    project.hook(special + 5, BranchNZ(not_special, special + 7), length=2)
    project.hook(special + 7, Sm83Scf(done), length=1)
    project.hook(not_special, Sm83AndRegister("a", done), length=1)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    _setup(state, 0, map_id=map_id, facing=facing, tile=tile,
           list_values=list_values)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN, num_find=2)
    assert not manager.errored and len(manager.found) == 1
    return [_endpoint(end, native=False) for end in manager.found]


def _native(values: dict[str, claripy.ast.BV], *, map_id: int, facing: int,
            tile: int, list_values: tuple[int, ...]) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_is_warp_tile_in_front_of_player")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, NATIVE_MEMORY, map_id=map_id, facing=facing, tile=tile,
           list_values=list_values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [_endpoint(end, native=True) for end in manager.deadended]


@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("map_id,facing,tile,list_values", (
    (0x10, 0, 0x01, (0x01,)),
    (0x10, 4, 0x5C, (0x01, 0x5C)),
    (0x10, 8, 0x22, (0x01,)),
    (0x10, 12, 0x4E, (0x0F, 0x4E)),
    (0x63, 0, 0x15, (0x01,)),
    (0x63, 0, 0x10, (0x01,)),
))
def test_is_warp_tile_in_front_of_player_pathwise_equivalence(
    map_id: int, facing: int, tile: int, list_values: tuple[int, ...],
) -> None:
    values = symbolic_registers(f"warp_front_{map_id}_{facing}")
    assert_pathwise_equivalent(
        _assembly(values, map_id=map_id, facing=facing, tile=tile,
                  list_values=list_values),
        _native(values, map_id=map_id, facing=facing, tile=tile,
                list_values=list_values),
        (*REGISTERS, "memory"),
    )
