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
    Sm83LoadABytePreserveF,
    Sm83LoadAImmediate,
    Sm83StoreAImmediate,
    Sm83XorA,
)
from verification.tests import test_do_buy_sell_quit_menu as direct
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
BUY_SELL_QUIT_MENU = 0x15
BUY_SELL_QUIT_MENU_HANDLER = 0x74EA


class JumpDoBuySellQuitMenu(angr.SimProcedure):
    """Model the dispatcher’s function-pointer load and pushed return."""

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.hl = claripy.BVV(BUY_SELL_QUIT_MENU_HANDLER, 16)
        self.state.regs.sp -= 2
        self.state.memory.store(
            self.state.regs.sp, claripy.BVV(DISPLAY_TEXT_BOX_DONE, 16),
            endness="Iend_LE",
        )
        self.jump(BUY_SELL_QUIT_MENU_HANDLER)


class ReturnBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        target = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp += 2
        self.jump(target)


class NativeReturn(angr.SimProcedure):
    def run(self, *args: claripy.ast.BV) -> None:  # type: ignore[override]
        self.ret()


def _setup(state: angr.SimState, base: int) -> None:
    direct._setup(state, base)
    state.memory.store(base + direct.W_TEXT_BOX_ID, claripy.BVV(BUY_SELL_QUIT_MENU, 8))
    table = (BUY_SELL_QUIT_MENU, BUY_SELL_QUIT_MENU_HANDLER & 0xFF,
             BUY_SELL_QUIT_MENU_HANDLER >> 8, 0xFF)
    for i, value in enumerate(table):
        state.memory.store(base + FUNCTION_TABLE + i, claripy.BVV(value, 8))


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return direct._memory(state, base)


def _endpoint(state: angr.SimState, *, native: bool):
    base = NATIVE_MEMORY if native else 0
    fields = native_registers(state, NATIVE_STATE) if native else assembly_registers(state)
    return direct.Endpoint(**fields, memory=_memory(state, base), constraints=tuple(state.solver.constraints))


def _assembly(values: dict[str, claripy.ast.BV]):
    location = symbol_location(SYMBOLS, "DisplayTextBoxID_")
    handler = symbol_location(SYMBOLS, "DoBuySellQuitMenu")
    assert handler.address == BUY_SELL_QUIT_MENU_HANDLER
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    project.hook(location.address, LoadTextBoxID(), length=3)
    project.hook(0x734C, SearchFunctionTable(), length=14)
    project.hook(0x7315, JumpDoBuySellQuitMenu(), length=8)

    h = handler.address
    project.hook(h, Sm83LoadAImmediate(direct.W_STATUS_FLAGS5, h + 3), length=3)
    project.hook(h + 5, Sm83StoreAImmediate(direct.W_STATUS_FLAGS5, h + 8), length=3)
    project.hook(h + 9, Sm83StoreAImmediate(direct.W_CHOSEN_MENU_ITEM, h + 12), length=3)
    project.hook(h + 12, Sm83LoadABytePreserveF(h + 13, h + 14), length=2)
    project.hook(h + 14, Sm83StoreAImmediate(direct.W_TEXT_BOX_ID, h + 17), length=3)
    for offset, address in ((22, direct.W_MENU_WATCHED_KEYS), (27, direct.W_MAX_MENU_ITEM),
                            (32, direct.W_TOP_MENU_ITEM_Y), (37, direct.W_TOP_MENU_ITEM_X),
                            (41, direct.W_CURRENT_MENU_ITEM), (44, direct.W_LAST_MENU_ITEM),
                            (47, direct.W_MENU_WATCH_MOVING_OUT_OF_BOUNDS)):
        project.hook(h + offset, Sm83StoreAImmediate(address, h + offset + 3), length=3)
    for offset, value in ((20, 3), (25, 2), (30, 1), (35, 1),
                          (72, 2), (79, 2), (98, 2)):
        project.hook(h + offset,
                     Sm83LoadABytePreserveF(h + offset + 1, h + offset + 2), length=2)
    project.hook(h + 40, Sm83XorA(h + 41), length=1)
    project.hook(h + 50, Sm83LoadAImmediate(direct.W_STATUS_FLAGS5, h + 53), length=3)
    project.hook(h + 55, Sm83StoreAImmediate(direct.W_STATUS_FLAGS5, h + 58), length=3)
    for offset, address in ((74, direct.W_MENU_EXIT_METHOD), (81, direct.W_MENU_EXIT_METHOD),
                            (87, direct.W_CHOSEN_MENU_ITEM), (100, direct.W_MENU_EXIT_METHOD),
                            (106, direct.W_CHOSEN_MENU_ITEM)):
        project.hook(h + offset, Sm83StoreAImmediate(address, h + offset + 3), length=3)
    for offset, address in ((84, direct.W_CURRENT_MENU_ITEM), (91, direct.W_MAX_MENU_ITEM),
                            (103, direct.W_CURRENT_MENU_ITEM)):
        project.hook(h + offset, Sm83LoadAImmediate(address, h + offset + 3), length=3)
    project.hook(0x30E8, ReturnBoundary(), length=8)
    project.hook(0x3ABE, direct.HandleMenuInputBoundary(), length=4)
    project.hook(0x3BEC, direct.PlaceCursorBoundary(), length=13)

    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    _setup(state, 0)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN, num_find=1)
    assert not manager.errored and len(manager.found) == 1
    return [_endpoint(end, native=False) for end in manager.found]


def _native(values: dict[str, claripy.ast.BV]):
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_display_text_box_id_function_dispatch")
    display = project.loader.find_symbol("port_display_text_box_id")
    assert function is not None and display is not None
    project.hook(display.rebased_addr, NativeReturn())
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, NATIVE_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [_endpoint(end, native=True) for end in manager.deadended]


@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_display_text_box_id_buy_sell_dispatch_pathwise_equivalence() -> None:
    values = symbolic_registers("display_text_box_id_buy_sell_dispatch")
    assert_pathwise_equivalent(_assembly(values), _native(values), (*REGISTERS, "memory"))
