"""Proof for the deterministic DisplayNamingScreen setup prefix."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
    assembly_registers,
    native_registers,
    set_assembly_registers,
    store_native_registers,
    symbolic_registers,
)
from verification.harness.rom import collect_returns, linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import (
    Sm83StoreAAtHlIncrement,
    Sm83StoreAImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF
W_STATUS_FLAGS5 = 0xD730
W_TOP_MENU_ITEM_Y = 0xCC24
W_TOP_MENU_ITEM_X = 0xCC25
W_CURRENT_MENU_ITEM = 0xCC26
W_MAX_MENU_ITEM = 0xCC28
W_MENU_WATCHED_KEYS = 0xCC29
W_LAST_MENU_ITEM = 0xCC2A
W_STRING_BUFFER = 0xCF4B
W_NAMING_SCREEN_SUBMIT_NAME = 0xCEEA
W_ANIM_COUNTER = 0xD08B
EXPECTED = bytes.fromhex(
    "e52130d7cbf6cdd43dcd0f19cd29240608cdef3dcdc036cd5b67"
    "061c216c57cdd63521f0c306090e12cd2219cdf8683e03ea24cc3e01"
    "ea25ccea2accea26cc3effea29cc3e07ea28cc3e50ea4bcfaf21eace"
    "2222ea8bd0cd6f67"
)


@dataclass(frozen=True)
class Endpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    status: claripy.ast.BV
    menu: claripy.ast.BV
    string_buffer: claripy.ast.BV
    submit: claripy.ast.BV
    anim_counter: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class CallBoundary(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.jump(self._next_address)


class LoadHLImmediate(angr.SimProcedure):
    def __init__(self, value: int, next_address: int) -> None:
        super().__init__()
        self._value = value
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = claripy.BVV(self._value >> 8, 8)
        self.state.regs.l = claripy.BVV(self._value & 0xFF, 8)
        self.jump(self._next_address)


class StoreAAtHLIncrement(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        state = self.state
        address = claripy.Concat(state.regs.h, state.regs.l)
        state.memory.store(state.solver.eval(address), state.regs.a)
        address = address + claripy.BVV(1, 16)
        state.regs.h = claripy.Extract(15, 8, address)
        state.regs.l = claripy.Extract(7, 0, address)
        self.jump(self._next_address)

class SetBitAtHL(angr.SimProcedure):
    def __init__(self, bit: int, next_address: int) -> None:
        super().__init__()
        self._bit = bit
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        state = self.state
        address = state.solver.eval(state.regs.hl)
        value = state.memory.load(address, 1)
        state.memory.store(address, value | claripy.BVV(1 << self._bit, 8))
        self.jump(self._next_address)


def _memory(state: angr.SimState, base: int) -> tuple[claripy.ast.BV, ...]:
    return (
        state.memory.load(base + W_STATUS_FLAGS5, 1),
        state.memory.load(base + W_CURRENT_MENU_ITEM, 1),
        state.memory.load(base + W_LAST_MENU_ITEM, 1),
        state.memory.load(base + W_TOP_MENU_ITEM_X, 1),
        state.memory.load(base + W_MENU_WATCHED_KEYS, 1),
        state.memory.load(base + W_TOP_MENU_ITEM_Y, 1),
        state.memory.load(base + W_MAX_MENU_ITEM, 1),
        state.memory.load(base + W_STRING_BUFFER, 1),
        claripy.Concat(
            state.memory.load(base + W_NAMING_SCREEN_SUBMIT_NAME, 1),
            state.memory.load(base + W_NAMING_SCREEN_SUBMIT_NAME + 1, 1),
        ),
        state.memory.load(base + W_ANIM_COUNTER, 1),
    )


def _endpoint(state: angr.SimState, base: int) -> Endpoint:
    registers = assembly_registers(state) if base == 0 else native_registers(state, NATIVE_STATE)
    memory = _memory(state, base)
    return Endpoint(
        a=registers["a"],
        f=registers["f"],
        h=registers["h"],
        l=registers["l"],
        status=memory[0],
        menu=claripy.Concat(*memory[1:7]),
        string_buffer=memory[7],
        submit=memory[8],
        anim_counter=memory[9],
        constraints=tuple(state.solver.constraints),
    )


def _assembly(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    loc = symbol_location(SYMBOLS, "DisplayNamingScreen")
    base = loc.address
    project = angr.Project(
        rom_window(ROM, loc.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": base,
        },
    )
    project.hook(base + 0x01, LoadHLImmediate(W_STATUS_FLAGS5, base + 0x04), length=3)
    project.hook(base + 0x4F, LoadHLImmediate(W_NAMING_SCREEN_SUBMIT_NAME, base + 0x52), length=3)
    project.hook(base + 0x52, StoreAAtHLIncrement(base + 0x53), length=1)
    project.hook(base + 0x53, StoreAAtHLIncrement(base + 0x54), length=1)
    project.hook(base + 0x31, Sm83StoreAImmediate(W_TOP_MENU_ITEM_Y, base + 0x34), length=3)
    project.hook(base + 0x36, Sm83StoreAImmediate(W_TOP_MENU_ITEM_X, base + 0x39), length=3)
    project.hook(base + 0x39, Sm83StoreAImmediate(W_LAST_MENU_ITEM, base + 0x3C), length=3)
    project.hook(base + 0x3C, Sm83StoreAImmediate(W_CURRENT_MENU_ITEM, base + 0x3F), length=3)
    project.hook(base + 0x41, Sm83StoreAImmediate(W_MENU_WATCHED_KEYS, base + 0x44), length=3)
    project.hook(base + 0x46, Sm83StoreAImmediate(W_MAX_MENU_ITEM, base + 0x49), length=3)
    project.hook(base + 0x4B, Sm83StoreAImmediate(W_STRING_BUFFER, base + 0x4E), length=3)
    project.hook(base + 0x54, Sm83StoreAImmediate(W_ANIM_COUNTER, base + 0x57), length=3)
    project.hook(base + 0x04, SetBitAtHL(6, base + 0x06), length=2)
    for offset, length in ((0x06, 3), (0x09, 3), (0x0C, 3), (0x11, 3), (0x14, 3), (0x17, 3), (0x1A, 3), (0x1F, 3), (0x29, 3), (0x2C, 3)):
        project.hook(base + offset, CallBoundary(base + offset + length), length=length)
    project.hook(base + 0x57, CallBoundary(DONE), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, inputs)
    state.memory.store(W_STATUS_FLAGS5, claripy.BVV(0, 8))
    for address in (W_CURRENT_MENU_ITEM, W_LAST_MENU_ITEM, W_TOP_MENU_ITEM_X, W_MENU_WATCHED_KEYS, W_TOP_MENU_ITEM_Y, W_MAX_MENU_ITEM, W_STRING_BUFFER, W_NAMING_SCREEN_SUBMIT_NAME, W_NAMING_SCREEN_SUBMIT_NAME + 1, W_ANIM_COUNTER):
        state.memory.store(address, claripy.BVV(0, 8))
    returned = collect_returns(project, state, DONE)
    return [_endpoint(end, 0) for end in returned]


def _native(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_display_naming_screen")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_MEMORY + W_STATUS_FLAGS5, claripy.BVV(0, 8))
    for address in (W_CURRENT_MENU_ITEM, W_LAST_MENU_ITEM, W_TOP_MENU_ITEM_X, W_MENU_WATCHED_KEYS, W_TOP_MENU_ITEM_Y, W_MAX_MENU_ITEM, W_STRING_BUFFER, W_NAMING_SCREEN_SUBMIT_NAME, W_NAMING_SCREEN_SUBMIT_NAME + 1, W_ANIM_COUNTER):
        state.memory.store(NATIVE_MEMORY + address, claripy.BVV(0, 8))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [_endpoint(end, NATIVE_MEMORY) for end in manager.deadended]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_display_naming_screen_setup_pathwise_equivalence() -> None:
    assert_pathwise_equivalent(
        _assembly(symbolic_registers("display_naming_screen")),
        _native(symbolic_registers("display_naming_screen")),
        ("a", "f", "h", "l", "status", "menu", "string_buffer", "submit", "anim_counter"),
    )


def test_display_naming_screen_exact_linked_prefix() -> None:
    loc = symbol_location(SYMBOLS, "DisplayNamingScreen")
    assert linked_bytes(ROM, loc, 0x5A) == EXPECTED
