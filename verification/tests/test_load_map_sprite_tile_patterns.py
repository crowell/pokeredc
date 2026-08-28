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
from verification.harness.sm83_shims import Sm83LoadAImmediate


ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xFFFF
W_NUM_SPRITES = 0xD4E1
H_VRAM_SLOT = 0xFF8D
H_FOUR_TILE_SPRITE_COUNT = 0xFF8E
SPRITE_STATE = 0xC200
SPRITE_STATE_BYTES = 0x110


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
    num_sprites: claripy.ast.BV
    vram_slot: claripy.ast.BV
    four_tile_count: claripy.ast.BV
    sprite_state: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class AndA(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.f = claripy.BVV(0x40, 8)  # Z80-layout Z
        self.jump(self.next_address)


class BranchNZ(angr.SimProcedure):
    def __init__(self, taken: int, fallthrough: int) -> None:
        super().__init__()
        self.taken = taken
        self.fallthrough = fallthrough

    def run(self) -> None:  # type: ignore[override]
        condition = (self.state.regs.f & 0x40) == 0
        taken = self.state.copy()
        fallthrough = self.state.copy()
        taken.solver.add(condition)
        fallthrough.solver.add(claripy.Not(condition))
        taken.regs.ip = claripy.BVV(self.taken, 16)
        fallthrough.regs.ip = claripy.BVV(self.fallthrough, 16)
        self.inhibit_autoret = True
        self.successors.add_successor(taken, self.taken, condition, "Ijk_Boring")
        self.successors.add_successor(
            fallthrough, self.fallthrough, claripy.Not(condition), "Ijk_Boring"
        )


def _endpoint(state: angr.SimState, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    registers = (
        native_registers(state, NATIVE_STATE)
        if native
        else assembly_registers(state)
    )
    return Endpoint(
        **registers,
        num_sprites=state.memory.load(base + W_NUM_SPRITES, 1),
        vram_slot=state.memory.load(base + H_VRAM_SLOT, 1),
        four_tile_count=state.memory.load(base + H_FOUR_TILE_SPRITE_COUNT, 1),
        sprite_state=state.memory.load(base + SPRITE_STATE, SPRITE_STATE_BYTES),
        constraints=tuple(state.solver.constraints),
    )


def _inputs() -> dict[str, claripy.ast.BV]:
    values = symbolic_registers("map_sprite_patterns")
    values["num_sprites"] = claripy.BVV(0, 8)
    values["vram_slot"] = claripy.BVS("map_sprite_patterns_vram_slot", 8)
    values["four_tile_count"] = claripy.BVS("map_sprite_patterns_four_tile", 8)
    values["sprite_state"] = claripy.BVS(
        "map_sprite_patterns_sprite_state", SPRITE_STATE_BYTES * 8
    )
    return values


def _store_memory(state: angr.SimState, base: int, values: dict[str, claripy.ast.BV]) -> None:
    state.memory.store(base + W_NUM_SPRITES, values["num_sprites"])
    state.memory.store(base + H_VRAM_SLOT, values["vram_slot"])
    state.memory.store(base + H_FOUR_TILE_SPRITE_COUNT, values["four_tile_count"])
    state.memory.store(base + SPRITE_STATE, values["sprite_state"])


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "LoadMapSpriteTilePatterns")
    assert linked_bytes(ROM, location, 7) == bytes.fromhex("fae1d4a72001c9")
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
    project.hook(base, Sm83LoadAImmediate(W_NUM_SPRITES, base + 3), length=3)
    project.hook(base + 3, AndA(base + 4), length=1)
    project.hook(base + 4, BranchNZ(base + 7, base + 6), length=2)

    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _store_memory(state, 0, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    manager = project.factory.simulation_manager(state)
    manager.explore(find=lambda candidate: candidate.addr == RETURN)
    assert not manager.errored
    assert len(manager.found) == 1
    return [_endpoint(manager.found[0], native=False)]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_load_map_sprite_tile_patterns")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _store_memory(state, NATIVE_MEMORY, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    return [_endpoint(manager.deadended[0], native=True)]


@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_load_map_sprite_tile_patterns_pathwise_equivalence() -> None:
    values = _inputs()
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "num_sprites", "vram_slot", "four_tile_count", "sprite_state"),
    )
