from __future__ import annotations

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
from verification.harness.sm83_shims import (
    Sm83LoadAAtHlIncrement,
    Sm83LoadAImmediate,
    Sm83StoreAAtHlIncrement,
    Sm83StoreAHighImmediate,
    Sm83StoreAImmediate,
    Sm83SubRegister,
)
from verification.tests import test_display_field_move_mon_menu as direct
from verification.tests.test_display_text_box_id_money_dispatch import (
    LoadTextBoxID,
    SearchFunctionTable,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xEFFF
FUNCTION_TABLE = 0x7387
DISPLAY_TEXT_BOX_DONE = 0x7314
FIELD_MOVE_MON_MENU = 0x04
FIELD_MOVE_MON_MENU_HANDLER = 0x76E1


class JumpFieldMoveMonMenu(angr.SimProcedure):
    """Model the dispatcher’s function-pointer load and pushed return."""

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.hl = claripy.BVV(FIELD_MOVE_MON_MENU_HANDLER, 16)
        self.state.regs.sp -= 2
        self.state.memory.store(
            self.state.regs.sp, claripy.BVV(DISPLAY_TEXT_BOX_DONE, 16),
            endness="Iend_LE",
        )
        self.jump(FIELD_MOVE_MON_MENU_HANDLER)


class GetMonFieldMovesBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        moves = [self.state.solver.eval(self.state.memory.load(direct.W_PARTY_MON1_MOVES + i, 1))
                 for i in range(4)]
        field_ptr = direct.W_FIELD_MOVES
        count = 0
        leftmost = 12
        last = self.state.solver.eval(self.state.memory.load(direct.W_LAST_FIELD_MOVE_ID, 1))
        for move in moves:
            if move == 0:
                break
            ptr = direct.FIELD_MOVE_DISPLAY_DATA
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
        self.state.memory.store(direct.W_NUM_FIELD_MOVES, claripy.BVV(count, 8))
        self.state.memory.store(direct.W_FIELD_MOVES_LEFTMOST_XCOORD, claripy.BVV(leftmost, 8))
        self.state.memory.store(direct.W_LAST_FIELD_MOVE_ID, claripy.BVV(last, 8))
        target = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp += 2
        self.jump(target)


def _setup(state: angr.SimState, base: int, moves: tuple[int, ...]) -> None:
    direct._setup(state, base, moves)
    state.memory.store(base + direct.W_WHICH_POKEMON, claripy.BVV(0, 8))
    state.memory.store(base + 0xD125, claripy.BVV(FIELD_MOVE_MON_MENU, 8))
    table = (FIELD_MOVE_MON_MENU, FIELD_MOVE_MON_MENU_HANDLER & 0xFF,
             FIELD_MOVE_MON_MENU_HANDLER >> 8, 0xFF)
    for i, value in enumerate(table):
        state.memory.store(base + FUNCTION_TABLE + i, claripy.BVV(value, 8))


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return direct._memory(state, base)


def _endpoint(state: angr.SimState, *, native: bool):
    base = NATIVE_MEMORY if native else 0
    fields = native_registers(state, NATIVE_STATE) if native else assembly_registers(state)
    return direct.Endpoint(**fields, memory=_memory(state, base), constraints=tuple(state.solver.constraints))


def _assembly(values: dict[str, claripy.ast.BV], moves: tuple[int, ...]):
    location = symbol_location(SYMBOLS, "DisplayTextBoxID_")
    handler = symbol_location(SYMBOLS, "DisplayFieldMoveMonMenu")
    assert handler.address == FIELD_MOVE_MON_MENU_HANDLER
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    project.hook(location.address, LoadTextBoxID(), length=3)
    project.hook(0x734C, SearchFunctionTable(), length=14)
    project.hook(0x7315, JumpFieldMoveMonMenu(), length=8)

    h = handler.address
    for offset in range(4, 9):
        project.hook(h + offset, Sm83StoreAAtHlIncrement(h + offset + 1), length=1)
    for offset, address in ((14, direct.W_NUM_FIELD_MOVES),
                            (50, direct.W_FIELD_MOVES_LEFTMOST_XCOORD),
                            (88, direct.W_FIELD_MOVES_LEFTMOST_XCOORD),
                            (99, direct.W_NUM_FIELD_MOVES),
                            (150, direct.W_FIELD_MOVES_LEFTMOST_XCOORD),
                            (158, direct.W_FIELD_MOVES_LEFTMOST_XCOORD)):
        project.hook(h + offset, Sm83LoadAImmediate(address, h + offset + 3), length=3)
    project.hook(h + 107, Sm83StoreAImmediate(direct.W_NUM_FIELD_MOVES, h + 110), length=3)
    project.hook(h + 35, Sm83StoreAHighImmediate(0xF7, h + 37), length=2)
    project.hook(h + 153, Sm83StoreAHighImmediate(0xF7, h + 155), length=2)
    project.hook(h + 126, Sm83LoadAAtHlIncrement(h + 127), length=1)
    project.hook(h + 62, Sm83SubRegister("e", h + 63), length=1)
    project.hook(0x77D6, GetMonFieldMovesBoundary(), length=75)
    project.hook(0x1922, direct.TextBoxBorderBoundary(), length=51)
    project.hook(0x2429, direct.UpdateSpritesBoundary(), length=25)
    project.hook(0x1955, direct.PlaceStringBoundary(), length=0x100)

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


def _native(values: dict[str, claripy.ast.BV], moves: tuple[int, ...]):
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_display_text_box_id_function_dispatch")
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
def test_display_text_box_id_field_move_dispatch_pathwise_equivalence(
    moves: tuple[int, ...],
) -> None:
    values = symbolic_registers(f"display_text_box_id_field_move_dispatch_{len(moves)}")
    assert_pathwise_equivalent(_assembly(values, moves), _native(values, moves),
                               (*REGISTERS, "memory"))
