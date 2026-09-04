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
from verification.harness.rom import linked_bytes, rom_window, sm83_flags_to_z80, symbol_location
from verification.harness.sm83_shims import (
    Sm83AndRegister,
    Sm83AddRegister,
    Sm83DecRegister,
    Sm83LoadAHighImmediate,
    Sm83LoadABytePreserveF,
    Sm83LoadAImmediate,
    Sm83StoreAImmediate,
    Sm83XorA,
    Sm83IncRegister,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xEFFF

W_STATE = 0xD700
W_STATE_COPY = 0xD11A
W_CUR_MAP = 0xD35E
W_CUR_MAP_TILESET = 0xD367
H_TILE_ANIMATIONS = 0xFFD7
H_AUTO = 0xFFBA
H_BANK = 0xFFB8
H_ROM_TEMP = 0xFF8B
R_ROMB = 0x2000
H_COPY_SOURCE = 0xFFC7
H_COPY_DEST = 0xFFC9
H_COPY_SIZE = 0xFFC6
H_VBLANK_OCCURRED = 0xFFD6
BIKE_TILES = 0x09E2

MEMORY_BYTES = (
    W_STATE, W_STATE_COPY, W_CUR_MAP, W_CUR_MAP_TILESET, H_TILE_ANIMATIONS,
    H_AUTO, H_BANK, H_ROM_TEMP, R_ROMB, H_COPY_SOURCE, H_COPY_SOURCE + 1,
    H_COPY_DEST, H_COPY_DEST + 1, H_COPY_SIZE, H_VBLANK_OCCURRED,
    BIKE_TILES, BIKE_TILES + 1, BIKE_TILES + 2,
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


class BikeAllowedBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        current_map = self.state.solver.eval(self.state.memory.load(W_CUR_MAP, 1))
        current_tileset = self.state.solver.eval(
            self.state.memory.load(W_CUR_MAP_TILESET, 1)
        )
        if current_map in (0x22, 0x09):
            self.state.regs.a = claripy.BVV(current_map, 8)
            self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0x90, 8))
        else:
            self.state.regs.a = claripy.BVV(0, 8)
            self.state.regs.b = claripy.BVV(current_tileset, 8)
            self.state.regs.h = claripy.BVV(0x09, 8)
            self.state.regs.l = claripy.BVV(0xE5, 8)
            ptr = BIKE_TILES
            while True:
                value = self.state.solver.eval(self.state.memory.load(ptr, 1))
                ptr += 1
                if value == current_tileset:
                    self.state.regs.a = claripy.BVV(value, 8)
                    self.state.regs.h = claripy.BVV(ptr >> 8, 8)
                    self.state.regs.l = claripy.BVV(ptr & 0xFF, 8)
                    self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0x90, 8))
                    break
                if value == 0xFF:
                    self.state.regs.a = claripy.BVV(0, 8)
                    self.state.regs.h = claripy.BVV(ptr >> 8, 8)
                    self.state.regs.l = claripy.BVV(ptr & 0xFF, 8)
                    self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0xA0, 8))
                    break
                old = value
                self.state.regs.a = claripy.BVV((old + 1) & 0xFF, 8)
                self.state.regs.h = claripy.BVV(ptr >> 8, 8)
                self.state.regs.l = claripy.BVV(ptr & 0xFF, 8)
        ret = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp = self.state.regs.sp + 2
        self.jump(ret)


class CopyVideoDataBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        saved_auto = self.state.memory.load(H_AUTO, 1)
        saved_bank = self.state.memory.load(H_BANK, 1)
        saved_f = self.state.regs.f
        self.state.memory.store(H_AUTO, claripy.BVV(0, 8))
        self.state.memory.store(H_ROM_TEMP, saved_bank)
        self.state.memory.store(H_BANK, self.state.regs.b)
        self.state.memory.store(R_ROMB, self.state.regs.b)
        self.state.memory.store(H_COPY_SOURCE, self.state.regs.e)
        self.state.memory.store(H_COPY_SOURCE + 1, self.state.regs.d)
        self.state.memory.store(H_COPY_DEST, self.state.regs.l)
        self.state.memory.store(H_COPY_DEST + 1, self.state.regs.h)
        self.state.regs.c = claripy.BVV(4, 8)
        self.state.memory.store(H_COPY_SIZE, claripy.BVV(4, 8))
        self.state.memory.store(H_VBLANK_OCCURRED, claripy.BVV(0, 8))
        self.state.memory.store(H_BANK, saved_bank)
        self.state.memory.store(R_ROMB, saved_bank)
        self.state.memory.store(H_AUTO, saved_auto)
        self.state.regs.a = saved_auto
        self.state.regs.f = saved_f
        ret = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp = self.state.regs.sp + 2
        self.jump(ret)


class LoadEFromA(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__()
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.e = self.state.regs.a
        self.jump(self.target)


def _setup(state: angr.SimState, base: int, *, walk_state: int | claripy.ast.BV,
           tile_animations: int | claripy.ast.BV, current_map: int,
           current_tileset: int, bike_list_match: bool = True) -> None:
    for address, value in (
        (W_STATE, walk_state), (W_STATE_COPY, 0xA5),
        (W_CUR_MAP, current_map), (W_CUR_MAP_TILESET, current_tileset),
        (H_TILE_ANIMATIONS, tile_animations), (H_AUTO, 0x66),
        (H_BANK, 0x77), (H_ROM_TEMP, 0x88), (R_ROMB, 0x99),
        (H_COPY_SOURCE, 0x11), (H_COPY_SOURCE + 1, 0x22),
        (H_COPY_DEST, 0x33), (H_COPY_DEST + 1, 0x44),
        (H_COPY_SIZE, 0x55), (H_VBLANK_OCCURRED, 0),
        (BIKE_TILES, 0),
        (BIKE_TILES + 1, current_tileset if bike_list_match else 0xFF),
        (BIKE_TILES + 2, 0xFF),
    ):
        state.memory.store(
            base + address,
            value if isinstance(value, claripy.ast.BV) else claripy.BVV(value, 8),
        )


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(*(state.memory.load(base + address, 1)
                            for address in MEMORY_BYTES))


def _assembly(values: dict[str, claripy.ast.BV], *,
              walk_state: int | claripy.ast.BV,
              tile_animations: int | claripy.ast.BV, current_map: int,
              current_tileset: int, bike_list_match: bool = True) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "LoadPlayerSpriteGraphics")
    assert linked_bytes(ROM, location, 46) == bytes.fromhex(
        "fa00d73d2807f0d7a720111805cdc509380aafea00d7ea1ad1c34d10"
        "fa00d7a7ca4d103dca5d103dca5510c34d10"
    )
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    b = location.address
    project.hook(b, Sm83LoadAImmediate(W_STATE, b + 3), length=3)
    project.hook(b + 3, Sm83DecRegister("a", b + 4), length=1)
    project.hook(b + 6, Sm83LoadAHighImmediate(0xD7, b + 8), length=2)
    project.hook(b + 8, Sm83AndRegister("a", b + 9), length=1)
    project.hook(0x09C5, BikeAllowedBoundary(), length=45)
    project.hook(b + 0x12, Sm83XorA(b + 0x13), length=1)
    project.hook(b + 0x13, Sm83StoreAImmediate(W_STATE, b + 0x16), length=3)
    project.hook(b + 0x16, Sm83StoreAImmediate(W_STATE_COPY, b + 0x19), length=3)
    project.hook(b + 0x1C, Sm83LoadAImmediate(W_STATE, b + 0x1F), length=3)
    project.hook(b + 0x1F, Sm83AndRegister("a", b + 0x20), length=1)
    project.hook(b + 0x23, Sm83DecRegister("a", b + 0x24), length=1)
    project.hook(b + 0x27, Sm83DecRegister("a", b + 0x28), length=1)
    common = symbol_location(SYMBOLS, "LoadPlayerSpriteGraphicsCommon").address
    project.hook(common + 10,
                 Sm83LoadABytePreserveF(common + 11, common + 12), length=2)
    project.hook(common + 12, Sm83AddRegister("e", common + 13), length=1)
    project.hook(common + 13, LoadEFromA(common + 14), length=1)
    project.hook(common + 16, Sm83IncRegister("d", common + 17), length=1)
    project.hook(0x1848, CopyVideoDataBoundary(), length=45)
    state = project.factory.blank_state(addr=b)
    set_assembly_registers(state, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    _setup(state, 0, walk_state=walk_state, tile_animations=tile_animations,
           current_map=current_map, current_tileset=current_tileset,
           bike_list_match=bike_list_match)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN, num_find=16)
    assert not manager.errored and manager.found
    return [Endpoint(**assembly_registers(end), memory=_memory(end, 0),
                     constraints=tuple(end.solver.constraints))
            for end in manager.found]


def _native(values: dict[str, claripy.ast.BV], *,
            walk_state: int | claripy.ast.BV,
            tile_animations: int | claripy.ast.BV, current_map: int,
            current_tileset: int, bike_list_match: bool = True) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_load_player_sprite_graphics")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE,
                                       NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, NATIVE_MEMORY, walk_state=walk_state,
           tile_animations=tile_animations, current_map=current_map,
           current_tileset=current_tileset, bike_list_match=bike_list_match)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and manager.deadended
    return [Endpoint(**native_registers(end, NATIVE_STATE),
                     memory=_memory(end, NATIVE_MEMORY),
                     constraints=tuple(end.solver.constraints))
            for end in manager.deadended]


@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    "walk_state,tile_animations,current_map,current_tileset,bike_list_match",
    (
        (0, 0, 1, 0, True),
        (0, 1, 1, 0, True),
        (1, 1, 1, 7, False),
        (1, 1, 0x22, 0, True),
        (1, 1, 1, 3, True),
        (2, 1, 1, 0, True),
        (3, 1, 1, 0, True),
        (2, 0, 1, 0, True),
    ),
)
def test_load_player_sprite_graphics_pathwise_equivalence(
    walk_state: int, tile_animations: int, current_map: int,
    current_tileset: int, bike_list_match: bool,
) -> None:
    values = symbolic_registers(
        f"load_player_sprite_graphics_{walk_state}_{tile_animations}_"
        f"{current_map}_{current_tileset}"
    )
    assert_pathwise_equivalent(
        _assembly(values, walk_state=walk_state,
                  tile_animations=tile_animations, current_map=current_map,
                  current_tileset=current_tileset,
                  bike_list_match=bike_list_match),
        _native(values, walk_state=walk_state,
                tile_animations=tile_animations, current_map=current_map,
                current_tileset=current_tileset,
                bike_list_match=bike_list_match),
        (*REGISTERS, "memory"),
    )


def test_load_player_sprite_graphics_symbolic_state_selection() -> None:
    values = symbolic_registers("load_player_sprite_graphics_symbolic")
    walk_state = claripy.BVS("load_player_sprite_graphics_walk_state", 8)
    tile_animations = claripy.BVS(
        "load_player_sprite_graphics_tile_animations", 8
    )
    assert_pathwise_equivalent(
        _assembly(values, walk_state=walk_state, tile_animations=tile_animations,
                  current_map=1, current_tileset=0),
        _native(values, walk_state=walk_state, tile_animations=tile_animations,
                current_map=1, current_tileset=0),
        (*REGISTERS, "memory"),
    )
