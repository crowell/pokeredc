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
from verification.harness.rom import rom_window, sm83_flags_to_z80, symbol_location
from verification.harness.sm83_shims import (
    Sm83CpImmediate,
    Sm83LoadAImmediate,
)
from verification.tests import test_display_two_option_menu as menu

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xEFFF
W_TEXT_BOX_ID = 0xD125
TWO_OPTION_MENU = 0x14


class JumpIfZero(angr.SimProcedure):
    def __init__(self, taken: int, fallthrough: int) -> None:
        super().__init__()
        self.taken = taken
        self.fallthrough = fallthrough

    def run(self) -> None:  # type: ignore[override]
        condition = (self.state.regs.f & 0x40) != 0
        taken = self.state.copy()
        fallthrough = self.state.copy()
        taken.solver.add(condition)
        fallthrough.solver.add(claripy.Not(condition))
        self.inhibit_autoret = True
        self.successors.add_successor(taken, self.taken, condition, "Ijk_Boring")
        self.successors.add_successor(
            fallthrough, self.fallthrough, claripy.Not(condition), "Ijk_Boring"
        )


def _assembly(values: dict[str, claripy.ast.BV], menu_id: int):
    location = symbol_location(SYMBOLS, "DisplayTextBoxID_")
    menu_location = symbol_location(SYMBOLS, "DisplayTwoOptionMenu")
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
    project.hook(
        location.address,
        Sm83LoadAImmediate(W_TEXT_BOX_ID, location.address + 3),
        length=3,
    )
    project.hook(
        location.address + 3,
        Sm83CpImmediate(TWO_OPTION_MENU, location.address + 5),
        length=2,
    )
    project.hook(
        location.address + 5,
        JumpIfZero(menu_location.address, location.address + 8),
        length=3,
    )

    for offset, address in (
        (1, menu.W_STATUS_FLAGS5),
        (61, menu.W_TWO_OPTION_MENU_ID),
        (84, menu.W_TWO_OPTION_MENU_ID),
        (127, menu.W_TWO_OPTION_MENU_ID),
        (138, menu.W_MISC_FLAGS),
        (182, menu.W_CURRENT_MENU_ITEM),
    ):
        project.hook(
            menu_location.address + offset,
            menu.Sm83LoadAImmediate(
                address, menu_location.address + offset + 3
            ),
            length=3,
        )
    for offset, address in (
        (6, menu.W_STATUS_FLAGS5),
        (10, menu.W_CHOSEN_MENU_ITEM),
        (13, menu.W_MENU_EXIT_METHOD),
        (18, menu.W_MENU_WATCHED_KEYS),
        (23, menu.W_MAX_MENU_ITEM),
        (27, menu.W_TOP_MENU_ITEM_Y),
        (31, menu.W_TOP_MENU_ITEM_X),
        (35, menu.W_LAST_MENU_ITEM),
        (38, menu.W_MENU_WATCH_MOVING_OUT_OF_BOUNDS),
        (52, menu.W_CURRENT_MENU_ITEM),
        (135, menu.W_TWO_OPTION_MENU_ID),
        (160, menu.W_MISC_FLAGS),
        (171, menu.W_TWO_OPTION_MENU_ID),
        (185, menu.W_CHOSEN_MENU_ITEM),
        (193, menu.W_MENU_EXIT_METHOD),
        (208, menu.W_CURRENT_MENU_ITEM),
        (211, menu.W_CHOSEN_MENU_ITEM),
        (216, menu.W_MENU_EXIT_METHOD),
    ):
        project.hook(
            menu_location.address + offset,
            menu.Sm83StoreAImmediate(
                address, menu_location.address + offset + 3
            ),
            length=3,
        )
    for offset in (16, 21, 70, 163, 191, 206, 214):
        project.hook(
            menu_location.address + offset,
            menu.Sm83LoadABytePreserveF(
                menu_location.address + offset + 1,
                menu_location.address + offset + 2,
            ),
            length=2,
        )
    project.hook(menu_location.address + 9,
                 menu.Sm83XorA(menu_location.address + 10), length=1)
    project.hook(menu_location.address + 134,
                 menu.Sm83XorA(menu_location.address + 135), length=1)
    project.hook(menu_location.address + 170,
                 menu.Sm83XorA(menu_location.address + 171), length=1)
    project.hook(menu_location.address + 68,
                 menu.LoadDZeroBoundary(), length=2)
    project.hook(menu_location.address + 105,
                 menu.LoadPairImmediateBoundary("bc", 0x0016), length=3)
    project.hook(menu_location.address + 110,
                 menu.LoadPairImmediateBoundary("bc", 0x002A), length=3)
    project.hook(menu_location.address + 103,
                 menu.LoadAAtHlIncrementBoundary(), length=1)
    project.hook(menu_location.address + 113,
                 menu.LoadAtHlIntoPairByteBoundary("e"), length=2)
    project.hook(menu_location.address + 115,
                 menu.LoadAtHlIntoPairByteBoundary("d"), length=2)
    project.hook(menu_location.address + 76,
                 menu.LoadAtHlIntoRegisterBoundary("c"), length=2)
    project.hook(menu_location.address + 78,
                 menu.LoadAtHlIntoRegisterBoundary("b"), length=2)
    project.hook(0x763E, menu.SaveBoundary(), length=24)
    project.hook(0x7656, menu.RestoreBoundary(), length=27)
    project.hook(0x1922, menu.BorderBoundary(), length=51)
    project.hook(0x5AB3, menu.CableBorderBoundary(), length=51)
    project.hook(0x2429, menu.UpdateBoundary(), length=25)
    project.hook(0x1955, menu.PlaceBoundary(), length=0x100)
    project.hook(0x3ABE, menu.HandleBoundary(), length=4)
    project.hook(0x3739, menu.DelayBoundary(), length=7)
    project.hook(0x23B1, menu.ReturnBoundary(), length=0x74)

    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    state.memory.store(W_TEXT_BOX_ID, claripy.BVV(TWO_OPTION_MENU, 8))
    menu._seed(state, 0, menu_id)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN, num_find=1)
    assert not manager.errored and len(manager.found) == 1
    return [menu._endpoint(end, native=False) for end in manager.found]


def _native(values: dict[str, claripy.ast.BV], menu_id: int):
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_display_text_box_id")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_MEMORY + W_TEXT_BOX_ID,
                       claripy.BVV(TWO_OPTION_MENU, 8))
    menu._seed(state, NATIVE_MEMORY, menu_id)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [menu._endpoint(end, native=True) for end in manager.deadended]


@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("menu_id", range(8))
def test_display_text_box_id_two_option_pathwise_equivalence(menu_id: int) -> None:
    values = symbolic_registers(f"display_text_box_id_two_option_{menu_id}")
    values["b"] = claripy.BVV(1, 8)
    values["c"] = claripy.BVV(1, 8)
    values["h"] = claripy.BVV(0xC4, 8)
    values["l"] = claripy.BVV(0x20, 8)
    assert_pathwise_equivalent(
        _assembly(values, menu_id),
        _native(values, menu_id),
        (*REGISTERS, "memory"),
    )
