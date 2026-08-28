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
from verification.harness.rom import rom_window, sm83_flags_to_z80, symbol_location
from verification.harness.sm83_shims import (
    Sm83LoadAHighImmediate,
    Sm83LoadAImmediate,
    Sm83StoreAHighImmediate,
    Sm83StoreAImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
RETURN = 0xEFFF
STACK = 0xD000

W_LIST_MENU_ID = 0xCF94
W_AUTO_TEXT_BOX_DRAWING_CONTROL = 0xCF0C
H_TEXT_ID = 0xFF8C
W_FONT_LOADED = 0xCFC4
W_MISC_FLAGS = 0xCD60
W_UPDATE_SPRITES_ENABLED = 0xCFCB
W_EVENT_FLAGS = 0xD747
W_SPRITE_PLAYER_IMAGE = 0xC102
W_SPRITE_01_FACING = 0xC119
W_SPRITE_01_ORIG_FACING = 0xC219
H_WY = 0xFFB0
H_AUTO = 0xFFBA
H_LOADED_BANK = 0xFFB8
R_ROMB = 0x2000
H_VBLANK = tuple(range(0xFFC1, 0xFFC6))
TILEMAP = 0xC3A0
FONT_DEST = 0x8800
SPRITE_STRIDE = 0x10


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


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    return symbolic_registers(prefix)


def _setup(state: angr.SimState, base: int, *, text_id: int,
           pokedex: bool, no_box: bool, no_sprite_updates: bool) -> None:
    state.memory.store(base + W_LIST_MENU_ID, claripy.BVV(0xA5, 8))
    state.memory.store(base + W_AUTO_TEXT_BOX_DRAWING_CONTROL,
                       claripy.BVV(1 if no_box else 0, 8))
    state.memory.store(base + H_TEXT_ID, claripy.BVV(text_id, 8))
    state.memory.store(base + W_FONT_LOADED, claripy.BVV(0x80, 8))
    state.memory.store(base + W_MISC_FLAGS,
                       claripy.BVV(0x10 if no_sprite_updates else 0, 8))
    state.memory.store(base + W_UPDATE_SPRITES_ENABLED, claripy.BVV(2, 8))
    state.memory.store(base + W_EVENT_FLAGS + 2,
                       claripy.BVV(1 << 5 if pokedex else 0, 8))
    state.memory.store(base + H_WY, claripy.BVV(0x77, 8))
    state.memory.store(base + H_AUTO, claripy.BVV(0x66, 8))
    state.memory.store(base + H_LOADED_BANK, claripy.BVV(1, 8))
    state.memory.store(base + R_ROMB, claripy.BVV(1, 8))
    state.memory.store(base + 0xFF40, claripy.BVV(0, 8))
    for address in H_VBLANK:
        state.memory.store(base + address, claripy.BVV(0x44, 8))
    for i in range(0x240):
        state.memory.store(base + TILEMAP + i, claripy.BVV((0x20 + i) & 0xFF, 8))
    for i in range(0x400):
        state.memory.store(base + 0x5A80 + i, claripy.BVV(0, 8))
    for i in range(0x800):
        state.memory.store(base + FONT_DEST + i, claripy.BVV(0xCC, 8))
    for i in range(15):
        state.memory.store(base + W_SPRITE_01_FACING + i * SPRITE_STRIDE,
                           claripy.BVV((0x30 + i) & 0xFF, 8))
    for i in range(15):
        state.memory.store(base + W_SPRITE_01_ORIG_FACING + i * SPRITE_STRIDE,
                           claripy.BVV((0x50 + i) & 0xFF, 8))
    for i in range(16):
        state.memory.store(base + W_SPRITE_PLAYER_IMAGE + i * SPRITE_STRIDE,
                           claripy.BVV(0x12 + i, 8))


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    pieces = [
        state.memory.load(base + a, 1)
        for a in (W_LIST_MENU_ID, W_AUTO_TEXT_BOX_DRAWING_CONTROL, H_TEXT_ID,
                  W_FONT_LOADED, W_MISC_FLAGS, W_UPDATE_SPRITES_ENABLED,
                  W_EVENT_FLAGS + 2, H_WY, H_AUTO, H_LOADED_BANK, R_ROMB, *H_VBLANK)
    ]
    pieces.append(state.memory.load(base + TILEMAP, 0x240))
    pieces.append(state.memory.load(base + FONT_DEST, 0x800))
    pieces.append(state.memory.load(base + W_SPRITE_01_FACING, 0xF0))
    pieces.append(state.memory.load(base + W_SPRITE_01_ORIG_FACING, 0xF0))
    pieces.extend(state.memory.load(base + W_SPRITE_PLAYER_IMAGE + i * SPRITE_STRIDE, 1)
                  for i in range(16))
    return claripy.Concat(*pieces)


class ReturnAt(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__()
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.jump(self.target)


class Border(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__(); self.target = target

    def run(self) -> None:  # type: ignore[override]
        hl = self.state.solver.eval(self.state.regs.hl)
        height = self.state.solver.eval(self.state.regs.b)
        width = self.state.solver.eval(self.state.regs.c)
        m = self.state.memory
        m.store(hl, claripy.BVV(0x79, 8))
        for i in range(width): m.store(hl + 1 + i, claripy.BVV(0x7A, 8))
        m.store(hl + width + 1, claripy.BVV(0x7B, 8))
        for y in range(1, height + 1):
            row = hl + y * 20
            m.store(row, claripy.BVV(0x7C, 8))
            for i in range(width): m.store(row + 1 + i, claripy.BVV(0x7F, 8))
            m.store(row + width + 1, claripy.BVV(0x7C, 8))
        row = hl + (height + 1) * 20
        m.store(row, claripy.BVV(0x7D, 8))
        for i in range(width): m.store(row + 1 + i, claripy.BVV(0x7A, 8))
        m.store(row + width + 1, claripy.BVV(0x7E, 8))
        self.state.regs.a = claripy.BVV(0x7A, 8)
        self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0xC0, 8))
        self.state.regs.b = claripy.BVV(0, 8)
        self.state.regs.d = claripy.BVV(0, 8)
        self.state.regs.e = claripy.BVV(20, 8)
        self.state.regs.hl = claripy.BVV(row + width + 1, 16)
        self.jump(self.target)


class UpdateSprites(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__(); self.target = target

    def run(self) -> None:  # type: ignore[override]
        before = self.state.solver.eval(self.state.memory.load(W_UPDATE_SPRITES_ENABLED, 1))
        value = (before - 1) & 0xFF
        self.state.regs.a = claripy.BVV(value, 8)
        flags = 0x40 | (0x20 if (before & 0x0F) == 0 else 0)
        if value == 0: flags |= 0x80
        self.state.regs.f = sm83_flags_to_z80(claripy.BVV(flags, 8))
        self.jump(self.target)


class CopyScreen(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__(); self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.c = claripy.BVV(6, 8)
        self.state.regs.h = claripy.BVV(6, 8)
        self.state.regs.l = claripy.BVV(0, 8)
        self.state.regs.d = claripy.BVV(0xC4, 8)
        self.state.regs.e = claripy.BVV(0x90, 8)
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0x10, 8))
        m = self.state.memory
        m.store(0xFFC1, claripy.BVV(0x90, 8))
        m.store(0xFFC2, claripy.BVV(0xC4, 8))
        m.store(0xFFC3, claripy.BVV(0x80, 8))
        m.store(0xFFC4, claripy.BVV(0x9D, 8))
        m.store(0xFFC5, claripy.BVV(6, 8))
        self.jump(self.target)


class LoadFont(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__(); self.target = target

    def run(self) -> None:  # type: ignore[override]
        bank = self.state.memory.load(H_LOADED_BANK, 1)
        self.state.regs.h = claripy.BVV(0x5E, 8)
        self.state.regs.l = claripy.BVV(0x80, 8)
        self.state.regs.d = claripy.BVV(0x90, 8)
        self.state.regs.e = claripy.BVV(0, 8)
        self.state.regs.b = claripy.BVV(0, 8)
        self.state.regs.c = claripy.BVV(0, 8)
        self.state.regs.a = bank
        # FarCopyDataDouble restores the LCD-off LoadFont flag result:
        # canonical H|Z ($a0), represented at the Z80 p-code boundary.
        self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0xA0, 8))
        self.state.memory.store(H_LOADED_BANK, bank)
        self.state.memory.store(R_ROMB, bank)
        for i in range(0x800): self.state.memory.store(FONT_DEST + i, claripy.BVV(0, 8))
        self.jump(self.target)


def _assembly(values: dict[str, claripy.ast.BV], *, text_id: int,
              pokedex: bool, no_box: bool, no_sprite_updates: bool) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "DisplayTextIDInit")
    p = angr.Project(rom_window(ROM, location.bank), auto_load_libs=False,
                     rebase_granularity=0x100,
                     main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                                "base_addr": 0, "entry_point": location.address})
    b = location.address
    p.hook(b + 0x01, Sm83StoreAImmediate(W_LIST_MENU_ID, b + 4), length=3)
    p.hook(b + 0x04, Sm83LoadAImmediate(W_AUTO_TEXT_BOX_DRAWING_CONTROL, b + 7), length=3)
    p.hook(b + 0x0B, Sm83LoadAHighImmediate(0x8C, b + 0x0D), length=2)
    p.hook(b + 0x10, Sm83LoadAImmediate(W_EVENT_FLAGS + 2, b + 0x13), length=3)
    p.hook(b + 0x2E, Border(b + 0x31), length=3)
    p.hook(b + 0x3F, UpdateSprites(b + 0x42), length=3)
    p.hook(b + 0x67, CopyScreen(b + 0x6A), length=3)
    p.hook(b + 0x6B, Sm83StoreAHighImmediate(0xB0, b + 0x6D), length=2)
    p.hook(b + 0x6D, LoadFont(b + 0x70), length=3)
    p.hook(b + 0x72, Sm83StoreAHighImmediate(0xBA, b + 0x74), length=2)
    state = p.factory.blank_state(addr=b)
    set_assembly_registers(state, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    _setup(state, 0, text_id=text_id, pokedex=pokedex, no_box=no_box,
           no_sprite_updates=no_sprite_updates)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = p.factory.simulation_manager(state)
    manager.explore(find=RETURN, num_find=1)
    assert not manager.errored and len(manager.found) == 1
    return [Endpoint(**assembly_registers(x), memory=_memory(x, 0),
                     constraints=tuple(x.solver.constraints)) for x in manager.found]


def _native(values: dict[str, claripy.ast.BV], *, text_id: int,
            pokedex: bool, no_box: bool, no_sprite_updates: bool) -> list[Endpoint]:
    p = angr.Project(ELF, auto_load_libs=False)
    function = p.loader.find_symbol("port_display_text_id_init")
    assert function is not None
    state = p.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, NATIVE_MEMORY, text_id=text_id, pokedex=pokedex, no_box=no_box,
           no_sprite_updates=no_sprite_updates)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = p.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    end = manager.deadended[0]
    return [Endpoint(**native_registers(end, NATIVE_STATE), memory=_memory(end, NATIVE_MEMORY),
                     constraints=tuple(end.solver.constraints))]


@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("text_id,pokedex,no_box,no_sprite_updates", (
    (1, False, False, False),
    (0, False, False, False),
    (0, True, False, False),
    (1, False, True, False),
    (1, False, False, True),
))
def test_display_text_id_init_pathwise_equivalence(
    text_id: int, pokedex: bool, no_box: bool, no_sprite_updates: bool,
) -> None:
    values = _inputs(f"display_text_id_init_{text_id}_{int(pokedex)}_{int(no_box)}_{int(no_sprite_updates)}")
    assert_pathwise_equivalent(
        _assembly(values, text_id=text_id, pokedex=pokedex, no_box=no_box,
                  no_sprite_updates=no_sprite_updates),
        _native(values, text_id=text_id, pokedex=pokedex, no_box=no_box,
                no_sprite_updates=no_sprite_updates),
        (*REGISTERS, "memory"),
    )
