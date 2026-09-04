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
TILEMAP = 0xC3A0
W_BUFFER = 0xCEE9
W_STATUS_FLAGS5 = 0xD730
W_CHOSEN_MENU_ITEM = 0xD12D
W_MENU_EXIT_METHOD = 0xD12E
W_MENU_WATCHED_KEYS = 0xCC29
W_MAX_MENU_ITEM = 0xCC28
W_TOP_MENU_ITEM_Y = 0xCC24
W_TOP_MENU_ITEM_X = 0xCC25
W_CURRENT_MENU_ITEM = 0xCC26
W_LAST_MENU_ITEM = 0xCC2A
W_MENU_WATCH_MOVING_OUT_OF_BOUNDS = 0xCC37
W_TWO_OPTION_MENU_ID = 0xD12C
W_MISC_FLAGS = 0xCD60
W_UPDATE_SPRITES_ENABLED = 0xCFCB
TWO_OPTION_STRINGS = 0x7671
SCREEN_WIDTH = 20


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
        self.state.regs.sp += 2
        self.jump(target)


class HandleBoundary(ReturnBoundary):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0x80, 8))
        super().run()


class DelayBoundary(ReturnBoundary):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.c = claripy.BVV(0, 8)
        self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0xC0, 8))
        super().run()


class UpdateBoundary(ReturnBoundary):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(1, 8)
        self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0x40, 8))
        super().run()


class LoadDZeroBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.d = claripy.BVV(0, 8)
        self.jump(self.addr + 2)


class LoadPairImmediateBoundary(angr.SimProcedure):
    def __init__(self, pair: str, value: int) -> None:
        super().__init__()
        self._pair = pair
        self._value = value

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self._pair, claripy.BVV(self._value, 16))
        self.jump(self.addr + 3)


class LoadAtHlIntoRegisterBoundary(angr.SimProcedure):
    def __init__(self, register: str) -> None:
        super().__init__()
        self._register = register

    def run(self) -> None:  # type: ignore[override]
        value = self.state.memory.load(self.state.regs.hl, 1)
        self.state.regs.hl = self.state.regs.hl + 1
        setattr(self.state.regs, self._register, value)
        self.state.regs.a = value
        self.jump(self.addr + 2)


class LoadAAtHlIncrementBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self.state.regs.hl, 1)
        self.state.regs.hl = self.state.regs.hl + 1
        self.jump(self.addr + 1)


class LoadAtHlIntoPairByteBoundary(angr.SimProcedure):
    def __init__(self, register: str) -> None:
        super().__init__()
        self._register = register

    def run(self) -> None:  # type: ignore[override]
        value = self.state.memory.load(self.state.regs.hl, 1)
        self.state.regs.hl = self.state.regs.hl + 1
        setattr(self.state.regs, self._register, value)
        self.state.regs.a = value
        self.jump(self.addr + 2)


class SaveBoundary(ReturnBoundary):
    def run(self) -> None:  # type: ignore[override]
        hl = self.state.solver.eval(self.state.regs.hl)
        for row in range(5):
            for col in range(6):
                value = self.state.memory.load(hl + row * 20 + col, 1)
                self.state.memory.store(W_BUFFER + row * 6 + col, value)
        self.state.regs.de = claripy.BVV(W_BUFFER + 30, 16)
        self.state.regs.b = claripy.BVV(0, 8)
        self.state.regs.c = claripy.BVV(6, 8)
        self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0xC0, 8))
        super().run()


class RestoreBoundary(ReturnBoundary):
    def run(self) -> None:  # type: ignore[override]
        hl = self.state.solver.eval(self.state.regs.hl)
        for row in range(5):
            for col in range(6):
                value = self.state.memory.load(W_BUFFER + row * 6 + col, 1)
                self.state.memory.store(hl + row * 20 + col, value)
        self.state.regs.de = claripy.BVV(W_BUFFER + 30, 16)
        self.state.regs.b = claripy.BVV(0, 8)
        self.state.regs.c = claripy.BVV(6, 8)
        self.state.regs.hl = claripy.BVV((hl + 100) & 0xFFFF, 16)
        self.state.regs.a = claripy.BVV(1, 8)
        self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0x40, 8))
        super().run()


class BorderBoundary(ReturnBoundary):
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
        super().run()


class CableBorderBoundary(ReturnBoundary):
    def run(self) -> None:  # type: ignore[override]
        start = self.state.solver.eval(self.state.regs.hl)
        height = self.state.solver.eval(self.state.regs.b)
        width = self.state.solver.eval(self.state.regs.c)

        def store(address: int, value: int) -> None:
            self.state.memory.store(address & 0xFFFF, claripy.BVV(value, 8))

        store(start, 0x78)
        for x in range(width):
            store(start + 1 + x, 0x79)
        store(start + width + 1, 0x7A)
        for y in range(1, height + 1):
            row = start + y * 20
            store(row, 0x7B)
            for x in range(width):
                store(row + 1 + x, 0x7F)
            store(row + width + 1, 0x77)
        bottom = start + (height + 1) * 20
        store(bottom, 0x7C)
        for x in range(width):
            store(bottom + 1 + x, 0x76)
        store(bottom + width + 1, 0x7D)
        self.state.regs.a = claripy.BVV(0x7D, 8)
        self.state.regs.b = claripy.BVV(0, 8)
        self.state.regs.d = claripy.BVV(0, 8)
        self.state.regs.e = claripy.BVV(20, 8)
        self.state.regs.hl = claripy.BVV((bottom + width + 1) & 0xFFFF, 16)
        super().run()


class PlaceBoundary(ReturnBoundary):
    def run(self) -> None:  # type: ignore[override]
        saved = self.state.solver.eval(self.state.regs.hl)
        source = self.state.solver.eval(self.state.regs.de)
        destination = saved
        while True:
            value = self.state.solver.eval(self.state.memory.load(source, 1))
            if value == 0x50:
                break
            if value == 0x4E:
                destination = (saved + 40) & 0xFFFF
                saved = destination
            else:
                self.state.memory.store(destination, claripy.BVV(value, 8))
                destination = (destination + 1) & 0xFFFF
            source = (source + 1) & 0xFFFF
        self.state.regs.a = claripy.BVV(0x50, 8)
        self.state.regs.b = claripy.BVV(destination >> 8, 8)
        self.state.regs.c = claripy.BVV(destination & 0xFF, 8)
        self.state.regs.d = claripy.BVV(source >> 8, 8)
        self.state.regs.e = claripy.BVV(source & 0xFF, 8)
        self.state.regs.hl = claripy.BVV(saved, 16)
        self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0xC0, 8))
        super().run()


def _seed(state: angr.SimState, base: int, menu_id: int) -> None:
    data = ROM.read_bytes()
    for address in range(TWO_OPTION_STRINGS, 0x76E1):
        state.memory.store(base + address, claripy.BVV(data[address], 8))
    state.memory.store(base + W_STATUS_FLAGS5, claripy.BVV(0xA5, 8))
    state.memory.store(base + W_CHOSEN_MENU_ITEM, claripy.BVV(0x11, 8))
    state.memory.store(base + W_MENU_EXIT_METHOD, claripy.BVV(0x22, 8))
    state.memory.store(base + W_TWO_OPTION_MENU_ID, claripy.BVV(menu_id, 8))
    state.memory.store(base + W_MISC_FLAGS, claripy.BVV(0x18, 8))
    state.memory.store(base + W_UPDATE_SPRITES_ENABLED, claripy.BVV(2, 8))
    state.memory.store(base + 0xFFF6, claripy.BVV(0, 8))
    for address, value in ((W_MENU_WATCHED_KEYS, 0x31), (W_MAX_MENU_ITEM, 0x32),
                           (W_TOP_MENU_ITEM_Y, 0x33), (W_TOP_MENU_ITEM_X, 0x34),
                           (W_CURRENT_MENU_ITEM, 0x35), (W_LAST_MENU_ITEM, 0x36),
                           (W_MENU_WATCH_MOVING_OUT_OF_BOUNDS, 0x37)):
        state.memory.store(base + address, claripy.BVV(value, 8))
    for i in range(30):
        state.memory.store(base + W_BUFFER + i, claripy.BVV(0x80 + i, 8))
    for i in range(0x300):
        state.memory.store(base + TILEMAP + i, claripy.BVV(0x11, 8))


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    addresses = (W_STATUS_FLAGS5, W_CHOSEN_MENU_ITEM, W_MENU_EXIT_METHOD,
                 W_MENU_WATCHED_KEYS, W_MAX_MENU_ITEM, W_TOP_MENU_ITEM_Y,
                 W_TOP_MENU_ITEM_X, W_CURRENT_MENU_ITEM, W_LAST_MENU_ITEM,
                 W_MENU_WATCH_MOVING_OUT_OF_BOUNDS, W_TWO_OPTION_MENU_ID,
                 W_MISC_FLAGS, W_UPDATE_SPRITES_ENABLED)
    return claripy.Concat(
        *(state.memory.load(base + address, 1) for address in addresses),
        state.memory.load(base + W_BUFFER, 30),
        state.memory.load(base + TILEMAP, 0x300),
    )


def _endpoint(state: angr.SimState, *, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    fields = native_registers(state, NATIVE_STATE) if native else assembly_registers(state)
    return Endpoint(**fields, memory=_memory(state, base), constraints=tuple(state.solver.constraints))


def _assembly(values: dict[str, claripy.ast.BV], menu_id: int) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "DisplayTwoOptionMenu")
    project = angr.Project(rom_window(ROM, location.bank), auto_load_libs=False,
                           rebase_granularity=0x100,
                           main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                                      "base_addr": 0, "entry_point": location.address})
    absolute_loads = ((1, W_STATUS_FLAGS5), (61, W_TWO_OPTION_MENU_ID),
                      (84, W_TWO_OPTION_MENU_ID), (127, W_TWO_OPTION_MENU_ID),
                      (138, W_MISC_FLAGS), (182, W_CURRENT_MENU_ITEM))
    absolute_stores = ((6, W_STATUS_FLAGS5), (10, W_CHOSEN_MENU_ITEM),
                       (13, W_MENU_EXIT_METHOD), (18, W_MENU_WATCHED_KEYS),
                       (23, W_MAX_MENU_ITEM), (27, W_TOP_MENU_ITEM_Y),
                       (31, W_TOP_MENU_ITEM_X), (35, W_LAST_MENU_ITEM),
                       (38, W_MENU_WATCH_MOVING_OUT_OF_BOUNDS), (52, W_CURRENT_MENU_ITEM),
                       (135, W_TWO_OPTION_MENU_ID), (160, W_MISC_FLAGS),
                       (171, W_TWO_OPTION_MENU_ID), (185, W_CHOSEN_MENU_ITEM),
                       (193, W_MENU_EXIT_METHOD), (208, W_CURRENT_MENU_ITEM),
                       (211, W_CHOSEN_MENU_ITEM), (216, W_MENU_EXIT_METHOD))
    for offset, address in absolute_loads:
        project.hook(location.address + offset,
                     Sm83LoadAImmediate(address, location.address + offset + 3), length=3)
    for offset, address in absolute_stores:
        project.hook(location.address + offset,
                     Sm83StoreAImmediate(address, location.address + offset + 3), length=3)
    for offset in (16, 21, 70, 163, 191, 206, 214):
        project.hook(location.address + offset,
                     Sm83LoadABytePreserveF(location.address + offset + 1,
                                             location.address + offset + 2), length=2)
    project.hook(location.address + 9, Sm83XorA(location.address + 10), length=1)
    project.hook(location.address + 134, Sm83XorA(location.address + 135), length=1)
    project.hook(location.address + 170, Sm83XorA(location.address + 171), length=1)
    project.hook(location.address + 68, LoadDZeroBoundary(), length=2)
    project.hook(location.address + 105, LoadPairImmediateBoundary("bc", 0x0016), length=3)
    project.hook(location.address + 110, LoadPairImmediateBoundary("bc", 0x002A), length=3)
    project.hook(location.address + 103, LoadAAtHlIncrementBoundary(), length=1)
    project.hook(location.address + 113, LoadAtHlIntoPairByteBoundary("e"), length=2)
    project.hook(location.address + 115, LoadAtHlIntoPairByteBoundary("d"), length=2)
    project.hook(location.address + 76, LoadAtHlIntoRegisterBoundary("c"), length=2)
    project.hook(location.address + 78, LoadAtHlIntoRegisterBoundary("b"), length=2)
    project.hook(0x763E, SaveBoundary(), length=24)
    project.hook(0x7656, RestoreBoundary(), length=27)
    project.hook(0x1922, BorderBoundary(), length=51)
    project.hook(0x5AB3, CableBorderBoundary(), length=51)
    project.hook(0x2429, UpdateBoundary(), length=25)
    project.hook(0x1955, PlaceBoundary(), length=0x100)
    project.hook(0x3ABE, HandleBoundary(), length=4)
    project.hook(0x3739, DelayBoundary(), length=7)
    project.hook(0x23B1, ReturnBoundary(), length=0x74)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    _seed(state, 0, menu_id)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN, num_find=1)
    assert not manager.errored and len(manager.found) == 1
    return [_endpoint(end, native=False) for end in manager.found]


def _native(values: dict[str, claripy.ast.BV], menu_id: int) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_display_two_option_menu")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _seed(state, NATIVE_MEMORY, menu_id)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [_endpoint(end, native=True) for end in manager.deadended]


@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("menu_id", [0, 1, 2, 3, 4, 5, 6, 7])
def test_display_two_option_menu_pathwise_equivalence(menu_id: int) -> None:
    values = symbolic_registers(f"display_two_option_menu_{menu_id}")
    values["b"] = claripy.BVV(1, 8)
    values["c"] = claripy.BVV(1, 8)
    values["h"] = claripy.BVV(0xC4, 8)
    values["l"] = claripy.BVV(0x20, 8)
    assert_pathwise_equivalent(_assembly(values, menu_id), _native(values, menu_id),
                               (*REGISTERS, "memory"))
