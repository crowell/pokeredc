from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
    set_assembly_registers,
    store_native_registers,
    symbolic_registers,
)
from verification.harness.rom import collect_returns, rom_window, symbol_location
from verification.harness.sm83_shims import (
    Sm83CpImmediate,
    Sm83LoadAHighImmediate,
    Sm83StoreAHighImmediate,
    Sm83XorA,
)

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
W_FONT_LOADED = 0xCFC4
SPRITE_STATE = 0xC200
SPRITE_STATE_BYTES = 0x110

@dataclass(frozen=True)
class Endpoint:
    num_sprites: claripy.ast.BV
    vram_slot: claripy.ast.BV
    four_tile_count: claripy.ast.BV
    sprite_state: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class Jump(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__()
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.jump(self.target)


class LoadPairImmediate(angr.SimProcedure):
    def __init__(self, pair: str, value: int, next_address: int) -> None:
        super().__init__()
        self.high, self.low = pair
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.high, claripy.BVV(self.value >> 8, 8))
        setattr(self.state.regs, self.low, claripy.BVV(self.value & 0xFF, 8))
        self.jump(self.next_address)


class ReadSpriteSheetData(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x40, 8)
        self.state.regs.b = claripy.BVV(0, 8)
        self.state.regs.c = claripy.BVV(0, 8)
        self.state.regs.d = claripy.BVV(0, 8)
        self.state.regs.e = claripy.BVV(0, 8)
        self.jump(self.addr + 3)

class ZeroPictureIDIteration(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        state = self.state
        state.memory.store(state.regs.hl, state.regs.a)
        low = (state.solver.eval(state.regs.l) + 0x10) & 0xFF
        count = (state.solver.eval(state.regs.b) - 1) & 0xFF
        state.regs.a = claripy.BVV(low, 8)
        state.regs.l = claripy.BVV(low, 8)
        state.regs.b = claripy.BVV(count, 8)
        self.jump(0x7967 if count != 0 else 0x7970)


def _endpoint(state: angr.SimState, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    return Endpoint(
        num_sprites=state.memory.load(base + W_NUM_SPRITES, 1),
        vram_slot=state.memory.load(base + H_VRAM_SLOT, 1),
        four_tile_count=state.memory.load(base + H_FOUR_TILE_SPRITE_COUNT, 1),
        sprite_state=state.memory.load(base + SPRITE_STATE, SPRITE_STATE_BYTES),
        constraints=tuple(state.solver.constraints),
    )


def _inputs() -> dict[str, claripy.ast.BV]:
    values = symbolic_registers("map_sprite_nonzero")
    values["num_sprites"] = claripy.BVV(1, 8)
    values["sprite_state"] = claripy.BVV(
        int.from_bytes(
            bytes.fromhex(
                "00" * 0x0D
                + "00"
                + "00"
                + "00" * 0x0E
                + "3d"
                + "3d"
                + "00" * 0xF1
            ),
            "big",
        ),
        SPRITE_STATE_BYTES * 8,
    )
    return values


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "LoadMapSpriteTilePatterns.loadTilePatternLoop")
    base = location.address
    project = angr.Project(
        rom_window(ROM, location.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": base,
        },
    )
    project.hook(0x7898, Jump(0x789A), length=2)
    project.hook(0x789B, Jump(0x789C), length=1)
    project.hook(0x789C, Jump(0x78A5), length=3)
    project.hook(0x78B0, Jump(0x78BD), length=2)
    project.hook(0x788D, LoadPairImmediate("de", 0xC21D, 0x7890), length=3)
    project.hook(0x78C2, Sm83CpImmediate(0x3D, 0x78C4), length=2)
    project.hook(0x78C4, Jump(0x78C6), length=2)
    project.hook(0x78A5, LoadPairImmediate("de", 0xC20E, 0x78A8), length=3)
    project.hook(0x78C7, Sm83LoadAHighImmediate(0x8E, 0x78C9), length=2)
    project.hook(0x78CF, Sm83StoreAHighImmediate(0x8D, 0x78D1), length=2)
    project.hook(0x78E9, LoadPairImmediate("hl", 0x8000, 0x78EC), length=3)
    project.hook(0x78EC, LoadPairImmediate("bc", 0x00C0, 0x78EF), length=3)
    project.hook(0x78EF, Sm83LoadAHighImmediate(0x8D, 0x78F1), length=2)
    project.hook(0x78F1, Sm83CpImmediate(0x0B, 0x78F3), length=2)
    project.hook(0x78FD, LoadPairImmediate("hl", 0x807C, 0x7900), length=3)
    project.hook(0x7900, Sm83LoadAHighImmediate(0x8E, 0x7902), length=2)
    project.hook(0x7909, Sm83StoreAHighImmediate(0x8E, 0x790B), length=2)
    project.hook(0x78E3, ReadSpriteSheetData(), length=3)
    project.hook(0x7914, Jump(0x7921), length=3)
    project.hook(0x7923, Sm83LoadAHighImmediate(0x8D, 0x7925), length=2)
    project.hook(0x7925, Sm83CpImmediate(0x0B, 0x7927), length=2)
    project.hook(0x7962, LoadPairImmediate("hl", 0xC20D, 0x7965), length=3)
    project.hook(0x7967, Sm83XorA(0x7968), length=1)
    project.hook(0x7968, ZeroPictureIDIteration(), length=8)

    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.regs.b = claripy.BVV(16, 8)
    state.regs.c = claripy.BVV(1, 8)
    state.regs.h = claripy.BVV(0xC2, 8)
    state.regs.l = claripy.BVV(0x1E, 8)
    state.memory.store(SPRITE_STATE, values["sprite_state"])
    state.memory.store(W_NUM_SPRITES, values["num_sprites"])
    state.memory.store(H_VRAM_SLOT, claripy.BVV(0, 8))
    state.memory.store(H_FOUR_TILE_SPRITE_COUNT, claripy.BVV(0, 8))
    state.memory.store(W_FONT_LOADED, claripy.BVV(1, 8))
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, RETURN)
    return [_endpoint(end, native=False) for end in returned]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_load_map_sprite_tile_patterns")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_MEMORY + SPRITE_STATE, values["sprite_state"])
    state.memory.store(NATIVE_MEMORY + W_NUM_SPRITES, claripy.BVV(1, 8))
    state.memory.store(NATIVE_MEMORY + H_VRAM_SLOT, claripy.BVV(0, 8))
    state.memory.store(NATIVE_MEMORY + H_FOUR_TILE_SPRITE_COUNT, claripy.BVV(0, 8))
    state.memory.store(NATIVE_MEMORY + W_FONT_LOADED, claripy.BVV(1, 8))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert manager.deadended
    return [_endpoint(end, native=True) for end in manager.deadended]


@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_load_map_sprite_tile_patterns_nonzero_four_tile_pathwise_equivalence() -> None:
    values = _inputs()
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        ("num_sprites", "vram_slot", "four_tile_count", "sprite_state"),
    )
