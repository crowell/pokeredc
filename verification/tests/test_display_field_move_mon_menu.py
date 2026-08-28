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
    Sm83LoadAImmediate,
    Sm83LoadAAtHlIncrement,
    Sm83SubRegister,
    Sm83StoreAHighImmediate,
    Sm83StoreAAtHlIncrement,
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
W_FIELD_MOVES = 0xCD3D
W_NUM_FIELD_MOVES = 0xCD41
W_FIELD_MOVES_LEFTMOST_XCOORD = 0xCD42
W_LAST_FIELD_MOVE_ID = 0xCD43
W_WHICH_POKEMON = 0xCF92
W_PARTY_MON1_MOVES = 0xD173
W_UPDATE_SPRITES_ENABLED = 0xCFCB
H_FIELD_MOVE_MON_MENU_TOP_MENU_ITEM_X = 0xFFF7
H_UI_LAYOUT_FLAGS = 0xFFF6
TILEMAP = 0xC3A0
FIELD_MOVE_NAMES = 0x778D
POKEMON_MENU_ENTRIES = 0x77C2
FIELD_MOVE_DISPLAY_DATA = 0x7823


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


class GetMonFieldMovesBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        moves = [self.state.solver.eval(self.state.memory.load(W_PARTY_MON1_MOVES + i, 1))
                 for i in range(4)]
        field_ptr = W_FIELD_MOVES
        count = 0
        leftmost = 12
        last = self.state.solver.eval(self.state.memory.load(W_LAST_FIELD_MOVE_ID, 1))
        for move in moves:
            if move == 0:
                break
            ptr = FIELD_MOVE_DISPLAY_DATA
            found = False
            while True:
                listed = self.state.solver.eval(self.state.memory.load(ptr, 1))
                ptr += 1
                if listed == 0xFF:
                    break
                if listed == move:
                    name_index = self.state.solver.eval(self.state.memory.load(ptr, 1))
                    xcoord = self.state.solver.eval(self.state.memory.load(ptr + 1, 1))
                    self.state.memory.store(field_ptr, claripy.BVV(name_index, 8))
                    field_ptr += 1
                    count += 1
                    leftmost = min(leftmost, xcoord)
                    last = move
                    found = True
                    break
                ptr += 2
            if not found:
                continue
        self.state.memory.store(W_NUM_FIELD_MOVES, claripy.BVV(count, 8))
        self.state.memory.store(W_FIELD_MOVES_LEFTMOST_XCOORD, claripy.BVV(leftmost, 8))
        self.state.memory.store(W_LAST_FIELD_MOVE_ID, claripy.BVV(last, 8))
        target = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp = self.state.regs.sp + 2
        self.jump(target)


class TextBoxBorderBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        start = self.state.solver.eval(self.state.regs.hl)
        height = self.state.solver.eval(self.state.regs.b)
        width = self.state.solver.eval(self.state.regs.c)
        def store(address: int, value: int) -> None:
            self.state.memory.store(address & 0xFFFF, claripy.BVV(value, 8))
        store(start, 0x79)
        for x in range(width):
            store(start + 1 + x, 0x7A)
        store(start + width + 1, 0x7B)
        for y in range(1, height + 1):
            row = start + y * 20
            store(row, 0x7C)
            for x in range(width):
                store(row + 1 + x, 0x7F)
            store(row + width + 1, 0x7C)
        bottom = start + (height + 1) * 20
        store(bottom, 0x7D)
        for x in range(width):
            store(bottom + 1 + x, 0x7A)
        store(bottom + width + 1, 0x7E)
        self.state.regs.a = claripy.BVV(0x7A, 8)
        self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0xC0, 8))
        self.state.regs.b = claripy.BVV(0, 8)
        self.state.regs.d = claripy.BVV(0, 8)
        self.state.regs.e = claripy.BVV(20, 8)
        self.state.regs.hl = claripy.BVV((bottom + width + 1) & 0xFFFF, 16)
        target = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp = self.state.regs.sp + 2
        self.jump(target)


class UpdateSpritesBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        before = self.state.solver.eval(self.state.memory.load(W_UPDATE_SPRITES_ENABLED, 1))
        value = (before - 1) & 0xFF
        carry = self.state.regs.f & 0x10
        self.state.regs.a = claripy.BVV(value, 8)
        flags = claripy.BVV(0x40, 8) | carry
        if value == 0:
            flags |= 0x80
        if (before & 0x0F) == 0:
            flags |= 0x20
        self.state.regs.f = sm83_flags_to_z80(flags)
        target = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp = self.state.regs.sp + 2
        self.jump(target)


class PlaceStringBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        start = self.state.solver.eval(self.state.regs.hl)
        source = self.state.solver.eval(self.state.regs.de)
        destination = start
        while True:
            value = self.state.solver.eval(self.state.memory.load(source, 1))
            if value == 0x50:
                break
            if value == 0x4E:
                destination = (start + 40) & 0xFFFF
                start = destination
                source = (source + 1) & 0xFFFF
                continue
            self.state.memory.store(destination & 0xFFFF, claripy.BVV(value, 8))
            destination = (destination + 1) & 0xFFFF
            source = (source + 1) & 0xFFFF
        self.state.regs.a = claripy.BVV(0x50, 8)
        self.state.regs.b = claripy.BVV(destination >> 8, 8)
        self.state.regs.c = claripy.BVV(destination & 0xFF, 8)
        self.state.regs.d = claripy.BVV(source >> 8, 8)
        self.state.regs.e = claripy.BVV(source & 0xFF, 8)
        self.state.regs.hl = claripy.BVV(start, 16)
        self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0xC0, 8))
        target = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp = self.state.regs.sp + 2
        self.jump(target)


def _seed_rom(state: angr.SimState, base: int) -> None:
    data = ROM.read_bytes()
    for address in range(FIELD_MOVE_NAMES, FIELD_MOVE_DISPLAY_DATA + 0x30):
        state.memory.store(base + address, claripy.BVV(data[address], 8))


def _setup(state: angr.SimState, base: int, moves: tuple[int, ...]) -> None:
    state.memory.store(base + H_UI_LAYOUT_FLAGS, claripy.BVV(0, 8))
    state.memory.store(base + W_WHICH_POKEMON, claripy.BVV(0, 8))
    for i, value in enumerate((*moves, 0, 0, 0, 0)[:4]):
        state.memory.store(base + W_PARTY_MON1_MOVES + i, claripy.BVV(value, 8))
    state.memory.store(base + W_UPDATE_SPRITES_ENABLED, claripy.BVV(2, 8))
    for address, value in ((W_FIELD_MOVES, 0xAA), (W_NUM_FIELD_MOVES, 0xBB),
                           (W_FIELD_MOVES_LEFTMOST_XCOORD, 0xCC),
                           (W_LAST_FIELD_MOVE_ID, 0xDD),
                           (H_FIELD_MOVE_MON_MENU_TOP_MENU_ITEM_X, 0xEE)):
        state.memory.store(base + address, claripy.BVV(value, 8))
    for i in range(0x200):
        state.memory.store(base + TILEMAP + i, claripy.BVV(0x11, 8))
    _seed_rom(state, base)


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        state.memory.load(base + W_FIELD_MOVES, 5),
        state.memory.load(base + W_FIELD_MOVES_LEFTMOST_XCOORD, 2),
        state.memory.load(base + H_FIELD_MOVE_MON_MENU_TOP_MENU_ITEM_X, 1),
        state.memory.load(base + W_UPDATE_SPRITES_ENABLED, 1),
        state.memory.load(base + W_PARTY_MON1_MOVES, 4),
        state.memory.load(base + TILEMAP, 0x200),
    )


def _endpoint(state: angr.SimState, *, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    fields = native_registers(state, NATIVE_STATE) if native else assembly_registers(state)
    return Endpoint(**fields, memory=_memory(state, base), constraints=tuple(state.solver.constraints))


def _assembly(values: dict[str, claripy.ast.BV], moves: tuple[int, ...]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "DisplayFieldMoveMonMenu")
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    for offset in range(4, 9):
        project.hook(location.address + offset,
                     Sm83StoreAAtHlIncrement(location.address + offset + 1), length=1)
    for offset, address in ((14, W_NUM_FIELD_MOVES), (50, W_FIELD_MOVES_LEFTMOST_XCOORD),
                            (88, W_FIELD_MOVES_LEFTMOST_XCOORD),
                            (99, W_NUM_FIELD_MOVES), (150, W_FIELD_MOVES_LEFTMOST_XCOORD),
                            (158, W_FIELD_MOVES_LEFTMOST_XCOORD)):
        project.hook(location.address + offset,
                     Sm83LoadAImmediate(address, location.address + offset + 3), length=3)
    project.hook(location.address + 107,
                 Sm83StoreAImmediate(W_NUM_FIELD_MOVES, location.address + 110), length=3)
    project.hook(location.address + 35,
                 Sm83StoreAHighImmediate(0xF7, location.address + 37), length=2)
    project.hook(location.address + 153,
                 Sm83StoreAHighImmediate(0xF7, location.address + 155), length=2)
    project.hook(location.address + 126,
                 Sm83LoadAAtHlIncrement(location.address + 127), length=1)
    project.hook(location.address + 62,
                 Sm83SubRegister("e", location.address + 63), length=1)
    project.hook(0x77D6, GetMonFieldMovesBoundary(), length=75)
    project.hook(0x1922, TextBoxBorderBoundary(), length=51)
    project.hook(0x2429, UpdateSpritesBoundary(), length=25)
    project.hook(0x1955, PlaceStringBoundary(), length=0x100)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    _setup(state, 0, moves)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN, num_find=1)
    assert not manager.errored and len(manager.found) == 1
    return [_endpoint(end, native=False) for end in manager.found]


def _native(values: dict[str, claripy.ast.BV], moves: tuple[int, ...]) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_display_field_move_mon_menu")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, NATIVE_MEMORY, moves)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [_endpoint(end, native=True) for end in manager.deadended]


@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("moves", [(), (0x0F,), (0x0F, 0x13),
                                    (0x0F, 0x13, 0xB4),
                                    (0x0F, 0x13, 0xB4, 0x39)])
def test_display_field_move_mon_menu_pathwise_equivalence(
    moves: tuple[int, ...],
) -> None:
    values = symbolic_registers(f"display_field_move_mon_menu_{len(moves)}")
    assert_pathwise_equivalent(_assembly(values, moves), _native(values, moves),
                               (*REGISTERS, "memory"))
