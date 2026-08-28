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
    Sm83AddRegister,
    Sm83LoadAAtHlIncrement,
    Sm83LoadAImmediate,
    Sm83ResAtHl,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xEFFF
DOOR_TABLE = 0x662C
DOOR_LIST = 0x7000
WARP_TABLE = 0x44CC
WARP_LIST = 0x7100
W_CUR_MAP_TILESET = 0xD367
STANDING_TILE = 0xC45C
MOVEMENT_FLAGS = 0xD736
EXPECTED_BODY = bytes.fromhex(
    "e5d5c50606210966cdd635381efa67d3874f060021cc44092a666f110100fa5cc4cdab3d30052136d7cb96c1d1e1c9"
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


class DoorTileBoundary(angr.SimProcedure):
    """Complete transition of the proven banked door-tile callee."""

    def __init__(self, target: int) -> None:
        super().__init__()
        self._target = target

    def run(self) -> None:  # type: ignore[override]
        wanted = self.state.solver.eval(
            self.state.memory.load(W_CUR_MAP_TILESET, 1)
        )
        self.state.regs.c = claripy.BVV(wanted, 8)
        table = self.state.solver.eval(self.state.memory.load(DOOR_TABLE, 1))
        if table != wanted:
            self.state.regs.a = claripy.BVV(0xFF, 8)
            self.state.regs.b = claripy.BVV(1, 8)
            self.state.regs.f = claripy.BVV(0, 8)
            self.state.regs.hl = claripy.BVV(DOOR_TABLE + 3, 16)
            self.jump(self._target)
            return

        self.state.regs.a = claripy.BVV(wanted, 8)
        self.state.regs.b = claripy.BVV(0, 8)
        self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0x10, 8))
        self.state.regs.hl = claripy.BVV(DOOR_TABLE, 16)
        low = self.state.memory.load(DOOR_TABLE + 1, 1)
        high = self.state.memory.load(DOOR_TABLE + 2, 1)
        self.state.regs.hl = claripy.Concat(high, low)
        self.state.regs.b = self.state.memory.load(STANDING_TILE, 1)
        while True:
            value = self.state.memory.load(self.state.regs.hl, 1)
            self.state.regs.hl = self.state.regs.hl + 1
            self.state.regs.a = value
            if self.state.solver.is_true(value == 0):
                self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0x80, 8))
                self.jump(self._target)
                return
            if self.state.solver.is_true(value == self.state.regs.b):
                self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0x90, 8))
                self.jump(self._target)
                return


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
        self._return()

    def _return(self) -> None:
        ret = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp += 2
        self.jump(ret)


def _setup(state: angr.SimState, base: int, *, tileset: int,
           door_tileset: int, standing: int, door_values: tuple[int, ...],
           warp_values: tuple[int, ...], movement_flags: int) -> None:
    state.memory.store(base + W_CUR_MAP_TILESET, claripy.BVV(tileset, 8))
    state.memory.store(base + STANDING_TILE, claripy.BVV(standing, 8))
    state.memory.store(base + MOVEMENT_FLAGS, claripy.BVV(movement_flags, 8))
    state.memory.store(base + DOOR_TABLE, claripy.BVV(door_tileset, 8))
    state.memory.store(base + DOOR_TABLE + 1, claripy.BVV(DOOR_LIST & 0xFF, 8))
    state.memory.store(base + DOOR_TABLE + 2, claripy.BVV(DOOR_LIST >> 8, 8))
    state.memory.store(base + DOOR_TABLE + 3, claripy.BVV(0xFF, 8))
    for i in range(4):
        value = door_values[i] if i < len(door_values) else 0
        state.memory.store(base + DOOR_LIST + i, claripy.BVV(value, 8))
    for i in range(48):
        state.memory.store(base + WARP_TABLE + i, claripy.BVV(0, 8))
    pointer = WARP_LIST
    state.memory.store(base + WARP_TABLE + tileset * 2,
                       claripy.BVV(pointer & 0xFF, 8))
    state.memory.store(base + WARP_TABLE + tileset * 2 + 1,
                       claripy.BVV(pointer >> 8, 8))
    for i in range(4):
        value = warp_values[i] if i < len(warp_values) else 0xFF
        state.memory.store(base + WARP_LIST + i, claripy.BVV(value, 8))


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        state.memory.load(base + MOVEMENT_FLAGS, 1),
        state.memory.load(base + DOOR_TABLE, 4),
        state.memory.load(base + DOOR_LIST, 4),
        state.memory.load(base + WARP_TABLE, 48),
        state.memory.load(base + WARP_LIST, 4),
    )


def _endpoint(state: angr.SimState, *, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    fields = native_registers(state, NATIVE_STATE) if native else assembly_registers(state)
    return Endpoint(**fields, memory=_memory(state, base),
                    constraints=tuple(state.solver.constraints))


def _assembly(values: dict[str, claripy.ast.BV], *, tileset: int,
              door_tileset: int, standing: int, door_values: tuple[int, ...],
              warp_values: tuple[int, ...], movement_flags: int) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "IsPlayerStandingOnDoorTileOrWarpTile")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    b = location.address
    project.hook(b + 8, DoorTileBoundary(b + 11), length=3)
    project.hook(b + 13, Sm83LoadAImmediate(W_CUR_MAP_TILESET, b + 16), length=3)
    project.hook(b + 16, Sm83AddRegister("a", b + 17), length=1)
    project.hook(b + 23, Sm83AddHlRegisterPair("bc", b + 24), length=1)
    project.hook(b + 24, Sm83LoadAAtHlIncrement(b + 25), length=1)
    project.hook(b + 25, LoadHFromHL(), length=1)
    project.hook(b + 26, LoadLFromA(), length=1)
    project.hook(b + 30, Sm83LoadAImmediate(STANDING_TILE, b + 33), length=3)
    project.hook(0x3DAB, IsInArrayBoundary(), length=0x20)
    project.hook(b + 41, Sm83ResAtHl(2, b + 43), length=2)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    _setup(state, 0, tileset=tileset, door_tileset=door_tileset,
           standing=standing, door_values=door_values,
           warp_values=warp_values, movement_flags=movement_flags)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN, num_find=1)
    assert not manager.errored and len(manager.found) == 1
    return [_endpoint(end, native=False) for end in manager.found]


def _native(values: dict[str, claripy.ast.BV], *, tileset: int,
            door_tileset: int, standing: int, door_values: tuple[int, ...],
            warp_values: tuple[int, ...], movement_flags: int) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol(
        "port_is_player_standing_on_door_tile_or_warp_tile"
    )
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, NATIVE_MEMORY, tileset=tileset, door_tileset=door_tileset,
           standing=standing, door_values=door_values,
           warp_values=warp_values, movement_flags=movement_flags)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [_endpoint(end, native=True) for end in manager.deadended]


class LoadHFromHL(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = self.state.memory.load(self.state.regs.hl, 1)
        self.jump(self.state.addr + 1)


class LoadLFromA(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.l = self.state.regs.a
        self.jump(self.state.addr + 1)


@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("tileset,door_tileset,standing,door_values,warp_values", (
    (0x05, 0x05, 0x39, (0x39,), (0x1B,)),
    (0x05, 0x05, 0x39, (0x1B,), (0x39,)),
    (0x05, 0x05, 0x39, (0x1B, 0x2C), (0x1B,)),
    (0x05, 0x05, 0x39, (0x1B,), (0x1B, 0x2C)),
    (0x07, 0x05, 0x39, (0x1B,), (0x39,)),
))
def test_is_player_standing_on_door_tile_or_warp_tile_pathwise_equivalence(
    tileset: int, door_tileset: int, standing: int,
    door_values: tuple[int, ...], warp_values: tuple[int, ...],
) -> None:
    values = symbolic_registers(f"door_warp_{tileset}_{len(door_values)}_{len(warp_values)}")
    assert_pathwise_equivalent(
        _assembly(values, tileset=tileset, door_tileset=door_tileset,
                  standing=standing, door_values=door_values,
                  warp_values=warp_values, movement_flags=0xFF),
        _native(values, tileset=tileset, door_tileset=door_tileset,
                standing=standing, door_values=door_values,
                warp_values=warp_values, movement_flags=0xFF),
        (*REGISTERS, "memory"),
    )
