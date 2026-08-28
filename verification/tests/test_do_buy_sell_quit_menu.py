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
from verification.harness.sm83_shims import (
    Sm83LoadABytePreserveF,
    Sm83LoadAImmediate,
    Sm83StoreAImmediate,
    Sm83XorA,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xEFFF
W_STATUS_FLAGS5 = 0xD730
W_TEXT_BOX_ID = 0xD125
W_CHOSEN_MENU_ITEM = 0xD12D
W_MENU_EXIT_METHOD = 0xD12E
W_TOP_MENU_ITEM_Y = 0xCC24
W_TOP_MENU_ITEM_X = 0xCC25
W_CURRENT_MENU_ITEM = 0xCC26
W_MAX_MENU_ITEM = 0xCC28
W_MENU_WATCHED_KEYS = 0xCC29
W_LAST_MENU_ITEM = 0xCC2A
W_MENU_CURSOR_LOCATION = 0xCC30
W_MENU_WATCH_MOVING_OUT_OF_BOUNDS = 0xCC37
CURSOR_DEST = 0xC500


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


class ReturnBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        target = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp = self.state.regs.sp + 2
        self.jump(target)


class NativeReturn(angr.SimProcedure):
    def run(self, *args: claripy.ast.BV) -> None:  # type: ignore[override]
        self.ret()


class HandleMenuInputBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x80, 8)
        target = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp = self.state.regs.sp + 2
        self.jump(target)


class PlaceCursorBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        saved_a = self.state.regs.a
        self.state.regs.b = saved_a
        low = self.state.memory.load(W_MENU_CURSOR_LOCATION, 1)
        high = self.state.memory.load(W_MENU_CURSOR_LOCATION + 1, 1)
        self.state.regs.l = low
        self.state.regs.h = high
        destination = (high.zero_extend(8) << 8) | low.zero_extend(8)
        self.state.memory.store(destination, claripy.BVV(0xEC, 8))
        self.state.regs.a = self.state.regs.b
        target = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp = self.state.regs.sp + 2
        self.jump(target)


def _setup(state: angr.SimState, base: int) -> None:
    state.memory.store(base + W_STATUS_FLAGS5, claripy.BVV(0xA5, 8))
    state.memory.store(base + W_TEXT_BOX_ID, claripy.BVV(0x13, 8))
    state.memory.store(base + W_CHOSEN_MENU_ITEM, claripy.BVV(0x77, 8))
    state.memory.store(base + W_MENU_EXIT_METHOD, claripy.BVV(0x66, 8))
    state.memory.store(base + W_MENU_CURSOR_LOCATION, claripy.BVV(CURSOR_DEST & 0xFF, 8))
    state.memory.store(base + W_MENU_CURSOR_LOCATION + 1, claripy.BVV(CURSOR_DEST >> 8, 8))
    state.memory.store(base + CURSOR_DEST, claripy.BVV(0x11, 8))
    for address, value in (
        (W_TOP_MENU_ITEM_Y, 0x44), (W_TOP_MENU_ITEM_X, 0x45),
        (W_CURRENT_MENU_ITEM, 0x46), (W_MAX_MENU_ITEM, 0x47),
        (W_MENU_WATCHED_KEYS, 0x48), (W_LAST_MENU_ITEM, 0x49),
        (W_MENU_WATCH_MOVING_OUT_OF_BOUNDS, 0x4A),
    ):
        state.memory.store(base + address, claripy.BVV(value, 8))


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    addresses = (
        W_STATUS_FLAGS5, W_TEXT_BOX_ID, W_CHOSEN_MENU_ITEM,
        W_MENU_EXIT_METHOD, W_TOP_MENU_ITEM_Y, W_TOP_MENU_ITEM_X,
        W_CURRENT_MENU_ITEM, W_MAX_MENU_ITEM, W_MENU_WATCHED_KEYS,
        W_LAST_MENU_ITEM, W_MENU_WATCH_MOVING_OUT_OF_BOUNDS,
        W_MENU_CURSOR_LOCATION, W_MENU_CURSOR_LOCATION + 1, CURSOR_DEST,
    )
    return claripy.Concat(*(state.memory.load(base + address, 1) for address in addresses))


def _endpoint(state: angr.SimState, *, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    fields = native_registers(state, NATIVE_STATE) if native else assembly_registers(state)
    return Endpoint(**fields, memory=_memory(state, base), constraints=tuple(state.solver.constraints))


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "DoBuySellQuitMenu")
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    project.hook(location.address,
                 Sm83LoadAImmediate(W_STATUS_FLAGS5, location.address + 3), length=3)
    project.hook(location.address + 5,
                 Sm83StoreAImmediate(W_STATUS_FLAGS5, location.address + 8), length=3)
    project.hook(location.address + 9,
                 Sm83StoreAImmediate(W_CHOSEN_MENU_ITEM, location.address + 12), length=3)
    project.hook(location.address + 12,
                 Sm83LoadABytePreserveF(location.address + 13, location.address + 14), length=2)
    project.hook(location.address + 14,
                 Sm83StoreAImmediate(W_TEXT_BOX_ID, location.address + 17), length=3)
    for offset, address in ((22, W_MENU_WATCHED_KEYS), (27, W_MAX_MENU_ITEM),
                            (32, W_TOP_MENU_ITEM_Y), (37, W_TOP_MENU_ITEM_X),
                            (41, W_CURRENT_MENU_ITEM), (44, W_LAST_MENU_ITEM),
                            (47, W_MENU_WATCH_MOVING_OUT_OF_BOUNDS)):
        project.hook(location.address + offset,
                     Sm83StoreAImmediate(address, location.address + offset + 3), length=3)
    for offset, value in ((20, 3), (25, 2), (30, 1), (35, 1),
                          (72, 2), (79, 2), (98, 2)):
        project.hook(location.address + offset,
                     Sm83LoadABytePreserveF(location.address + offset + 1,
                                             location.address + offset + 2), length=2)
    project.hook(location.address + 40,
                 Sm83XorA(location.address + 41), length=1)
    project.hook(location.address + 50,
                 Sm83LoadAImmediate(W_STATUS_FLAGS5, location.address + 53), length=3)
    project.hook(location.address + 55,
                 Sm83StoreAImmediate(W_STATUS_FLAGS5, location.address + 58), length=3)
    for offset, address in ((74, W_MENU_EXIT_METHOD), (81, W_MENU_EXIT_METHOD),
                            (87, W_CHOSEN_MENU_ITEM), (100, W_MENU_EXIT_METHOD),
                            (106, W_CHOSEN_MENU_ITEM)):
        project.hook(location.address + offset,
                     Sm83StoreAImmediate(address, location.address + offset + 3), length=3)
    for offset, address in ((84, W_CURRENT_MENU_ITEM), (91, W_MAX_MENU_ITEM),
                            (103, W_CURRENT_MENU_ITEM)):
        project.hook(location.address + offset,
                     Sm83LoadAImmediate(address, location.address + offset + 3), length=3)
    project.hook(0x30E8, ReturnBoundary(), length=8)  # DisplayTextBoxID
    project.hook(0x3ABE, HandleMenuInputBoundary(), length=4)
    project.hook(0x3BEC, PlaceCursorBoundary(), length=13)
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


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_do_buy_sell_quit_menu")
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
def test_do_buy_sell_quit_menu_pathwise_equivalence() -> None:
    values = symbolic_registers("do_buy_sell_quit_menu")
    assert_pathwise_equivalent(_assembly(values), _native(values), (*REGISTERS, "memory"))
