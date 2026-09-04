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
    Sm83CpRegister,
    Sm83LoadAAtHlIncrement,
    Sm83LoadAImmediate,
    Sm83Scf,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xEFFF
DOOR_TILE_ID_POINTERS = 0x662C
W_CUR_MAP_TILESET = 0xD367
STANDING_TILE = 0xC45C
DOOR_LIST = 0x7000
EXPECTED_BODY = bytes.fromhex(
    "d5212c66fa67d3110300cdab3dd13011232a666ffa5cc4472aa72805b820f937c9a7c9"
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
                self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0, 8))
                break
            if self.state.solver.is_true(value == wanted):
                self.state.regs.b = claripy.BVV(count, 8)
                self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0x10, 8))
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


def _setup(state: angr.SimState, base: int, *, tileset: int, table_tileset: int,
           standing: int, list_values: tuple[int, ...]) -> None:
    state.memory.store(base + W_CUR_MAP_TILESET, claripy.BVV(tileset, 8))
    state.memory.store(base + STANDING_TILE, claripy.BVV(standing, 8))
    table = (table_tileset, DOOR_LIST & 0xFF, DOOR_LIST >> 8, 0xFF)
    for i, value in enumerate(table):
        state.memory.store(base + DOOR_TILE_ID_POINTERS + i, claripy.BVV(value, 8))
    for i in range(4):
        value = list_values[i] if i < len(list_values) else 0
        state.memory.store(base + DOOR_LIST + i, claripy.BVV(value, 8))


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        state.memory.load(base + W_CUR_MAP_TILESET, 1),
        state.memory.load(base + STANDING_TILE, 1),
        state.memory.load(base + DOOR_TILE_ID_POINTERS, 4),
        state.memory.load(base + DOOR_LIST, 4),
    )


def _endpoint(state: angr.SimState, *, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    fields = native_registers(state, NATIVE_STATE) if native else assembly_registers(state)
    return Endpoint(**fields, memory=_memory(state, base), constraints=tuple(state.solver.constraints))


def _assembly(values: dict[str, claripy.ast.BV], *, tileset: int,
              table_tileset: int, standing: int,
              list_values: tuple[int, ...]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "IsPlayerStandingOnDoorTile")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    b = location.address
    project.hook(b + 4, Sm83LoadAImmediate(W_CUR_MAP_TILESET, b + 7), length=3)
    project.hook(0x3DAB, IsInArrayBoundary(), length=0x20)
    project.hook(b + 17, Sm83LoadAAtHlIncrement(b + 18), length=1)
    project.hook(b + 18, LoadHFromHL(), length=1)
    project.hook(b + 19, LoadLFromA(), length=1)
    project.hook(b + 20, Sm83LoadAImmediate(STANDING_TILE, b + 23), length=3)
    project.hook(b + 24, Sm83LoadAAtHlIncrement(b + 25), length=1)
    project.hook(b + 25, Sm83AndRegister("a", b + 26), length=1)
    project.hook(b + 28, Sm83CpRegister("b", b + 29), length=1)
    project.hook(b + 31, Sm83Scf(b + 32), length=1)
    project.hook(b + 33, Sm83AndRegister("a", b + 34), length=1)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    _setup(state, 0, tileset=tileset, table_tileset=table_tileset,
           standing=standing, list_values=list_values)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN, num_find=1)
    assert not manager.errored and len(manager.found) == 1
    return [_endpoint(end, native=False) for end in manager.found]


def _native(values: dict[str, claripy.ast.BV], *, tileset: int,
            table_tileset: int, standing: int,
            list_values: tuple[int, ...]) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_is_player_standing_on_door_tile")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, NATIVE_MEMORY, tileset=tileset, table_tileset=table_tileset,
           standing=standing, list_values=list_values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [_endpoint(end, native=True) for end in manager.deadended]


@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("tileset,table_tileset,standing,list_values", (
    (0x05, 0x05, 0x39, (0x1B,)),
    (0x05, 0x05, 0x39, (0x1B, 0x2C)),
    (0x05, 0x05, 0x39, (0x1B, 0x2C, 0x39)),
    (0x05, 0x05, 0x39, (0x39, 0x1B)),
    (0x07, 0x05, 0x39, (0x1B,)),
))
def test_is_player_standing_on_door_tile_pathwise_equivalence(
    tileset: int, table_tileset: int, standing: int,
    list_values: tuple[int, ...],
) -> None:
    values = symbolic_registers(f"door_tile_{tileset}_{len(list_values)}")
    assert_pathwise_equivalent(
        _assembly(values, tileset=tileset, table_tileset=table_tileset,
                  standing=standing, list_values=list_values),
        _native(values, tileset=tileset, table_tileset=table_tileset,
                standing=standing, list_values=list_values),
        (*REGISTERS, "memory"),
    )
