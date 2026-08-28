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
)
from verification.harness.rom import linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import (
    Sm83AndImmediate,
    Sm83BitRegister,
    Sm83AddRegister,
    Sm83DecRegister,
    Sm83IncRegister,
    Sm83LoadAAtHlIncrement,
    Sm83LoadAImmediate,
    Sm83StoreAImmediate,
    Sm83StoreAHighImmediate,
)


ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xFFFF
H_LOADED_ROM_BANK = 0xFFB8
R_ROMB = 0x2000
W_MAP_VIEW_VRAM_POINTER = 0xD526
W_WALK_COUNTER = 0xCFC5
W_UNUSED_CUR_MAP_TILESET_COPY = 0xD119
W_WALK_BIKE_SURF_STATE_COPY = 0xD11A
W_SPRITE_SET_ID = 0xD3A8
W_UPDATE_SPRITES_ENABLED = 0xCFCB
W_STATUS_FLAGS6 = 0xD732
W_STATUS_FLAGS7 = 0xD733
W_CURRENT_MAP_VIEW = 0xC3A0
V_BG_MAP0 = 0x9800
VRAM_BYTES = 32 * 18


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


class Skip(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__()
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.jump(self.target)


class LoadRegisterConst(angr.SimProcedure):
    def __init__(self, register: str, value: int, target: int) -> None:
        super().__init__()
        self.register = register
        self.value = value
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.register, claripy.BVV(self.value, 8))
        self.jump(self.target)


class LoadPairConst(angr.SimProcedure):
    def __init__(self, high: str, low: str, value: int, target: int) -> None:
        super().__init__()
        self.high = high
        self.low = low
        self.value = value
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.high, claripy.BVV(self.value >> 8, 8))
        setattr(self.state.regs, self.low, claripy.BVV(self.value & 0xFF, 8))
        self.jump(self.target)


class SaveAF(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__()
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.sp = self.state.regs.sp - 2
        self.state.memory.store(
            self.state.regs.sp,
            claripy.Concat(self.state.regs.a, self.state.regs.f),
            endness="Iend_LE",
        )
        self.jump(self.target)


class RestoreAF(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__()
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        value = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.f = value[7:0]
        self.state.regs.a = value[15:8]
        self.state.regs.sp = self.state.regs.sp + 2
        self.jump(self.target)


class NativeNoop(angr.SimProcedure):
    def run(self, *args, **kwargs) -> None:  # type: ignore[override]
        return


class StoreAAtDE(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__()
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(self.state.regs.de, self.state.regs.a)
        self.jump(self.target)


class MoveAToE(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__()
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.e = self.state.regs.a
        self.jump(self.target)


class CopyMapView(angr.SimProcedure):
    """Execute the fixed 18x20 transfer as one concrete bounded adapter."""

    def __init__(self, target: int) -> None:
        super().__init__()
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        source = W_CURRENT_MAP_VIEW
        destination = V_BG_MAP0
        for _ in range(18):
            for column in range(20):
                self.state.memory.store(
                    destination + column,
                    self.state.memory.load(source + column, 1),
                )
            source += 32
            destination += 32
        self.state.regs.hl = source
        self.state.regs.de = destination + 12
        self.state.regs.b = 0
        self.state.regs.c = 0
        self.state.regs.f = claripy.BVV(0x42, 8)
        self.jump(self.target)


class BranchFlag(angr.SimProcedure):
    def __init__(self, bit: int, taken: int, fallthrough: int, set_: bool = True) -> None:
        super().__init__()
        self.bit = bit
        self.taken = taken
        self.fallthrough = fallthrough
        self.set = set_

    def run(self) -> None:  # type: ignore[override]
        condition = ((self.state.regs.f >> self.bit) & 1) == (1 if self.set else 0)
        if self.state.solver.is_true(condition):
            self.jump(self.taken)
        elif self.state.solver.is_false(condition):
            self.jump(self.fallthrough)
        else:
            self.inhibit_autoret = True
            self.successors.add_successor(self.state.copy(), self.taken, condition, "Ijk_Boring")
            self.successors.add_successor(self.state.copy(), self.fallthrough, claripy.Not(condition), "Ijk_Boring")


def _seed(state: angr.SimState, base: int, *, status_flags6: int = 0x08,
          status_flags7: int = 0) -> None:
    state.memory.store(base + H_LOADED_ROM_BANK, claripy.BVV(2, 8))
    state.memory.store(base + R_ROMB, claripy.BVV(2, 8))
    state.memory.store(base + W_STATUS_FLAGS6, claripy.BVV(status_flags6, 8))
    state.memory.store(base + W_STATUS_FLAGS7, claripy.BVV(status_flags7, 8))
    for offset in range(VRAM_BYTES):
        state.memory.store(
            base + W_CURRENT_MAP_VIEW + offset,
            claripy.BVV((offset * 7 + 3) & 0xFF, 8),
        )


def _memory_endpoint(state: angr.SimState, base: int) -> claripy.ast.BV:
    chunks = [
        state.memory.load(base + W_MAP_VIEW_VRAM_POINTER, 2),
        state.memory.load(base + W_WALK_COUNTER, 1),
        state.memory.load(base + W_UNUSED_CUR_MAP_TILESET_COPY, 1),
        state.memory.load(base + W_WALK_BIKE_SURF_STATE_COPY, 1),
        state.memory.load(base + W_SPRITE_SET_ID, 1),
        state.memory.load(base + W_UPDATE_SPRITES_ENABLED, 1),
        state.memory.load(base + H_LOADED_ROM_BANK, 1),
        state.memory.load(base + R_ROMB, 1),
        state.memory.load(base + W_CURRENT_MAP_VIEW, VRAM_BYTES),
        state.memory.load(base + V_BG_MAP0, VRAM_BYTES),
    ]
    return claripy.Concat(*chunks)


def _endpoint(state: angr.SimState, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    return Endpoint(
        **(native_registers(state, NATIVE_STATE) if native else assembly_registers(state)),
        memory=_memory_endpoint(state, base),
        constraints=tuple(state.solver.constraints),
    )


def _assembly(*, status_flags6: int, status_flags7: int) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "LoadMapData")
    end = symbol_location(SYMBOLS, "SwitchToMapRomBank")
    assert linked_bytes(ROM, location, end.address - location.address) == bytes.fromhex(
        "f0b8f5cd61003e98ea27d5afea26d5e0afe0aeeac5cfea19d1ea1ad1eaa8d3cda036cd7c100605215b78cdd635cdfc09cde809cdaa0c21a0c311009806120e142a121c0d20fa3e0c835f3001140520ee3e01eacbcfcd7b000609cdef3dcd9709fa32d7e618200dfa33d7cb4f2006cd5f23cd1223f1e0b8ea0020c9"
    )
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
    # The helper bodies are independently covered.  These boundaries retain
    # the real orchestration body and leave its own memory/register effects
    # visible to the endpoint comparison.
    for offset, next_offset in (
        (0x03, 0x06),       # DisableLCD
        (0x1F, 0x22),       # LoadTextBoxTilePatterns
        (0x22, 0x25),       # LoadMapHeader
            (0x2A, 0x2D),       # farcall InitMapSprites
            (0x2D, 0x30),       # LoadTileBlockMap
            (0x30, 0x33),       # LoadTilesetTilePatternData
            (0x33, 0x36),       # LoadCurrentMapView
        (0x55, 0x58),       # RunPaletteCommand
        (0x5A, 0x5D),       # LoadPlayerSpriteGraphics
    ):
        project.hook(base + offset, Skip(base + next_offset), length=3)
    project.hook(base + 0x00, Sm83LoadAImmediate(H_LOADED_ROM_BANK, base + 0x02), length=2)
    project.hook(base + 0x02, SaveAF(base + 0x03), length=1)
    project.hook(base + 0x25, LoadRegisterConst("b", 5, base + 0x27), length=2)
    project.hook(base + 0x27, LoadPairConst("h", "l", 0x785B, base + 0x2A), length=3)
    project.hook(base + 0x58, LoadRegisterConst("b", 9, base + 0x5A), length=2)
    project.hook(base + 0x73, RestoreAF(base + 0x74), length=1)
    # The SM83 absolute/high-memory load/store opcodes are not decoded by
    # the generic Z80 p-code backend, so keep these individual instructions
    # explicit while the surrounding orchestration remains real code.
    project.hook(base + 0x08, Sm83StoreAImmediate(W_MAP_VIEW_VRAM_POINTER + 1, base + 0x0B), length=3)
    project.hook(base + 0x0C, Sm83StoreAImmediate(W_MAP_VIEW_VRAM_POINTER, base + 0x0F), length=3)
    project.hook(base + 0x0F, Sm83StoreAHighImmediate(0xAF, base + 0x11), length=2)
    project.hook(base + 0x11, Sm83StoreAHighImmediate(0xAE, base + 0x13), length=2)
    project.hook(base + 0x13, Sm83StoreAImmediate(W_WALK_COUNTER, base + 0x16), length=3)
    project.hook(base + 0x16, Sm83StoreAImmediate(W_UNUSED_CUR_MAP_TILESET_COPY, base + 0x19), length=3)
    project.hook(base + 0x19, Sm83StoreAImmediate(W_WALK_BIKE_SURF_STATE_COPY, base + 0x1C), length=3)
    project.hook(base + 0x1C, Sm83StoreAImmediate(W_SPRITE_SET_ID, base + 0x1F), length=3)
    project.hook(base + 0x52, Sm83StoreAImmediate(W_UPDATE_SPRITES_ENABLED, base + 0x55), length=3)
    project.hook(base + 0x60, Sm83LoadAImmediate(W_STATUS_FLAGS6, base + 0x63), length=3)
    project.hook(base + 0x63, Sm83AndImmediate(0x18, base + 0x65), length=2)
    project.hook(base + 0x6A, Sm83BitRegister(1, "a", base + 0x6C), length=2)
    project.hook(base + 0x6E, Skip(base + 0x71), length=3)
    project.hook(base + 0x71, Skip(base + 0x74), length=3)
    project.hook(base + 0x5D, Skip(base + 0x60), length=3)
    # Summarize the fixed 18x20 transfer in one concrete adapter.  The
    # orchestration before and after it remains the linked body; this keeps
    # the proof bounded under the current p-code backend.
    project.hook(base + 0x36, CopyMapView(base + 0x50), length=0x1A)
    state = project.factory.blank_state(addr=base)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    set_assembly_registers(state, {register: claripy.BVV(0, 8) for register in REGISTERS})
    _seed(state, 0, status_flags6=status_flags6, status_flags7=status_flags7)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    manager = project.factory.simulation_manager(state)
    manager.explore(find=lambda candidate: candidate.addr == RETURN)
    assert not manager.errored
    assert len(manager.found) == 1
    return [_endpoint(manager.found[0], native=False)]


def _native(*, status_flags6: int, status_flags7: int) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_load_map_data")
    assert function is not None
    # Keep each existing helper as an explicit native boundary too.  The
    # selected proof domain supplies the matching identity transition while
    # checking LoadMapData's own setup, copy loop, LCD/palette sequencing, and
    # bank restoration.
    for name in (
        "port_disable_lcd",
        "port_load_text_box_tile_patterns",
        "port_load_map_header",
        "port_init_map_sprites",
        "port_load_tile_block_map",
        "port_load_tileset_tile_pattern_data",
        "port_load_current_map_view",
        "port_enable_lcd",
        "port_run_palette_command",
        "port_load_player_sprite_graphics",
        "port_update_music_6_times",
        "port_play_default_music_fade_out_current",
    ):
        symbol = project.loader.find_symbol(name)
        assert symbol is not None
        project.hook(symbol.rebased_addr, NativeNoop())
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    store_native_registers(
        state,
        NATIVE_STATE,
        {register: claripy.BVV(0, 8) for register in REGISTERS},
    )
    state.memory.store(NATIVE_STATE + 8, claripy.BVV(0, 31 * 8))
    _seed(state, NATIVE_MEMORY, status_flags6=status_flags6,
          status_flags7=status_flags7)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    return [_endpoint(manager.deadended[0], native=True)]


@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("status_flags6,status_flags7", ((0x08, 0), (0, 0x02), (0, 0)))
def test_load_map_data_pathwise_equivalence(status_flags6: int, status_flags7: int) -> None:
    assert_pathwise_equivalent(
        _assembly(status_flags6=status_flags6, status_flags7=status_flags7),
        _native(status_flags6=status_flags6, status_flags7=status_flags7),
        (*REGISTERS, "memory"),
    )
