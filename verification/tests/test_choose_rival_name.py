"""Proof for the custom-name prefix of ChooseRivalName."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import assembly_registers, native_registers, set_assembly_registers, store_native_registers, symbolic_registers
from verification.harness.rom import collect_returns, linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import Sm83LoadAFromImmediate, Sm83StoreAImmediate

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF
W_CURRENT_MENU_ITEM = 0xCC26
W_NAMING_SCREEN_TYPE = 0xD07D
W_RIVAL_NAME = 0xD34A
NAME_SOURCE = 0x6ABE
TITLE_NAME_STRING = 0x6AA3
W_UPDATE_SPRITES_ENABLED = 0xCFCB
EXPECTED = bytes.fromhex("cd126a11be6acd6c6afa26cca7280e21086bcdd66a114ad3cdec691820214ad33e01ea7dd0cd9665")


@dataclass(frozen=True)
class Endpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    menu: claripy.ast.BV
    naming_type: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class CallBoundary(angr.SimProcedure):
    def __init__(self, next_address: int, set_custom_menu: bool = False) -> None:
        super().__init__()
        self._next_address = next_address
        self._set_custom_menu = set_custom_menu

    def run(self) -> None:  # type: ignore[override]
        if self._set_custom_menu:
            self.state.memory.store(W_CURRENT_MENU_ITEM, claripy.BVV(0, 8))
        self.jump(self._next_address)


class LoadAFromMemory(angr.SimProcedure):
    def __init__(self, address: int, next_address: int) -> None:
        super().__init__()
        self._address = address
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self._address, 1)
        self.jump(self._next_address)


class AndA(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        value = self.state.regs.a
        self.state.regs.a = value & claripy.BVV(0xFF, 8)
        self.state.regs.f = claripy.If(value == 0, claripy.BVV(0x80, 8), claripy.BVV(0, 8))
        self.jump(self._next_address)


class Jump(angr.SimProcedure):
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


def _endpoint(state: angr.SimState, base: int) -> Endpoint:
    registers = assembly_registers(state) if base == 0 else native_registers(state, NATIVE_STATE)
    return Endpoint(
        a=registers["a"], f=registers["f"], h=registers["h"], l=registers["l"],
        menu=state.memory.load(base + W_CURRENT_MENU_ITEM, 1),
        naming_type=state.memory.load(base + W_NAMING_SCREEN_TYPE, 1),
        constraints=tuple(state.solver.constraints),
    )


def _assembly(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    loc = symbol_location(SYMBOLS, "ChooseRivalName")
    base = loc.address
    project = angr.Project(rom_window(ROM, loc.bank), auto_load_libs=False, rebase_granularity=0x100, main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0, "entry_point": base})
    project.hook(base + 0x00, CallBoundary(base + 0x03), length=3)
    project.hook(base + 0x06, CallBoundary(base + 0x09, set_custom_menu=True), length=3)
    project.hook(base + 0x09, LoadAFromMemory(W_CURRENT_MENU_ITEM, base + 0x0C), length=3)
    project.hook(base + 0x0C, AndA(base + 0x0D), length=1)
    project.hook(base + 0x0D, Jump(base + 0x1D), length=2)
    project.hook(base + 0x1D, LoadHLImmediate(W_RIVAL_NAME, base + 0x20), length=3)
    project.hook(base + 0x20, Sm83LoadAFromImmediate(base + 0x21, base + 0x22), length=2)
    project.hook(base + 0x22, Sm83StoreAImmediate(W_NAMING_SCREEN_TYPE, base + 0x25), length=3)
    project.hook(base + 0x25, CallBoundary(DONE), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, inputs)
    state.memory.store(W_CURRENT_MENU_ITEM, claripy.BVV(1, 8))
    state.memory.store(W_NAMING_SCREEN_TYPE, claripy.BVV(0xFF, 8))
    return [_endpoint(end, 0) for end in collect_returns(project, state, DONE)]


def _native(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_choose_rival_name")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_MEMORY + W_CURRENT_MENU_ITEM, claripy.BVV(1, 8))
    state.memory.store(NATIVE_MEMORY + W_NAMING_SCREEN_TYPE, claripy.BVV(0xFF, 8))
    state.memory.store(NATIVE_MEMORY + NAME_SOURCE, claripy.BVV(0x50, 8))
    state.memory.store(NATIVE_MEMORY + TITLE_NAME_STRING, claripy.BVV(0x50, 8))
    state.memory.store(NATIVE_MEMORY + W_UPDATE_SPRITES_ENABLED, claripy.BVV(2, 8))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [_endpoint(end, NATIVE_MEMORY) for end in manager.deadended]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_choose_rival_name_custom_prefix_pathwise_equivalence() -> None:
    inputs = symbolic_registers("choose_rival_name")
    assert_pathwise_equivalent(_assembly(inputs), _native(inputs), ("a", "f", "h", "l", "menu", "naming_type"))


def test_choose_rival_name_exact_linked_prefix() -> None:
    loc = symbol_location(SYMBOLS, "ChooseRivalName")
    assert linked_bytes(ROM, loc, 0x28) == EXPECTED
