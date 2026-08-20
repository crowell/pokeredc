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
from verification.harness.rom import rom_window, symbol_location

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF
W_TEMP_TILESET_NUM_TILES = 0xD07D
W_WHICH_BATTLE_ANIM_TILESET = 0xD09F


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


class TilesetZeroSummary(angr.SimProcedure):
    def run(self) -> None:
        self.state.memory.store(W_TEMP_TILESET_NUM_TILES, claripy.BVV(79, 8))
        self.state.regs.a = claripy.BVV(79, 8)
        self.state.regs.b = claripy.BVV(0x1E, 8)
        self.state.regs.c = claripy.BVV(79, 8)
        self.state.regs.d = claripy.BVV(0x41, 8)
        self.state.regs.e = claripy.BVV(0xFE, 8)
        self.state.regs.h = claripy.BVV(0x83, 8)
        self.state.regs.l = claripy.BVV(0x10, 8)
        self.state.regs.f = claripy.BVV(0x80, 8)
        self.jump(DONE)


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["temp_tiles"] = claripy.BVS(f"{prefix}_temp_tiles", 8)
    values["tileset"] = claripy.BVS(f"{prefix}_tileset", 8)
    return values


def _memory_endpoint(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        state.memory.load(base + W_TEMP_TILESET_NUM_TILES, 1),
        state.memory.load(base + W_WHICH_BATTLE_ANIM_TILESET, 1),
    )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "LoadMoveAnimationTiles")
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
    project.hook(location.address, TilesetZeroSummary(), length=1)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.memory.store(W_TEMP_TILESET_NUM_TILES, values["temp_tiles"])
    state.memory.store(W_WHICH_BATTLE_ANIM_TILESET, claripy.BVV(0, 8))
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored
    return [
        Endpoint(**assembly_registers(end), memory=_memory_endpoint(end, 0), constraints=tuple(end.solver.constraints))
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_load_move_animation_tiles_zero")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_MEMORY + W_TEMP_TILESET_NUM_TILES, values["temp_tiles"])
    state.memory.store(NATIVE_MEMORY + W_WHICH_BATTLE_ANIM_TILESET, claripy.BVV(0, 8))
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
def test_load_move_animation_tiles_zero_pathwise_equivalence() -> None:
    values = _inputs("load_move_animation_tiles_zero")
    assert_pathwise_equivalent(_assembly(values), _native(values), (*REGISTERS, "memory"))
