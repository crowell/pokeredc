"""Proof for the deterministic setup of DisplayIntroNameTextBox."""

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
    Sm83IncRegister,
    Sm83StoreAImmediate,
    Sm83XorA,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF
NAME_SOURCE = 0x7000
W_CURRENT_MENU_ITEM = 0xCC26
W_LAST_MENU_ITEM = 0xCC2A
W_TOP_MENU_ITEM_X = 0xCC25
W_MENU_WATCHED_KEYS = 0xCC29
W_TOP_MENU_ITEM_Y = 0xCC24
W_MAX_MENU_ITEM = 0xCC28
W_UPDATE_SPRITES_ENABLED = 0xCFCB
EXPECTED = bytes.fromhex(
    "d521a0c3060a0e09cd221921a3c311a36acd5519d121cac3cd5519"
    "cd2924afea26ccea2acc3cea25ccea29cc3cea24cc3cea28ccc3be3a"
)
TITLE_NAME = bytes.fromhex("8d808c84e650")


@dataclass(frozen=True)
class Endpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    menu: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class CallBoundary(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.jump(self._next_address)


def _menu(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        state.memory.load(base + W_CURRENT_MENU_ITEM, 1),
        state.memory.load(base + W_LAST_MENU_ITEM, 1),
        state.memory.load(base + W_TOP_MENU_ITEM_X, 1),
        state.memory.load(base + W_MENU_WATCHED_KEYS, 1),
        state.memory.load(base + W_TOP_MENU_ITEM_Y, 1),
        state.memory.load(base + W_MAX_MENU_ITEM, 1),
    )


def _assembly(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    loc = symbol_location(SYMBOLS, "DisplayIntroNameTextBox")
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
    project.hook(base + 0x08, CallBoundary(base + 0x0B), length=3)
    project.hook(base + 0x11, CallBoundary(base + 0x14), length=3)
    project.hook(base + 0x18, CallBoundary(base + 0x1B), length=3)
    project.hook(base + 0x1B, CallBoundary(base + 0x1E), length=3)
    project.hook(base + 0x1E, Sm83XorA(base + 0x1F), length=1)
    project.hook(base + 0x1F, Sm83StoreAImmediate(W_CURRENT_MENU_ITEM, base + 0x22), length=3)
    project.hook(base + 0x22, Sm83StoreAImmediate(W_MAX_MENU_ITEM + 2, base + 0x25), length=3)
    project.hook(base + 0x25, Sm83IncRegister("a", base + 0x26), length=1)
    project.hook(base + 0x26, Sm83StoreAImmediate(W_TOP_MENU_ITEM_X, base + 0x29), length=3)
    project.hook(base + 0x29, Sm83StoreAImmediate(W_MENU_WATCHED_KEYS, base + 0x2C), length=3)
    project.hook(base + 0x2C, Sm83IncRegister("a", base + 0x2D), length=1)
    project.hook(base + 0x2D, Sm83StoreAImmediate(W_TOP_MENU_ITEM_Y, base + 0x30), length=3)
    project.hook(base + 0x30, Sm83IncRegister("a", base + 0x31), length=1)
    project.hook(base + 0x31, Sm83StoreAImmediate(W_MAX_MENU_ITEM, base + 0x34), length=3)
    project.hook(base + 0x34, CallBoundary(DONE), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, inputs)
    state.regs.d = NAME_SOURCE >> 8
    state.regs.e = NAME_SOURCE & 0xFF
    state.memory.store(NAME_SOURCE, TITLE_NAME)
    state.memory.store(symbol_location(SYMBOLS, "DisplayIntroNameTextBox.namestring").address, TITLE_NAME)
    returned = collect_returns(project, state, DONE)
    return [
        Endpoint(
            a=assembly_registers(end)["a"],
            f=assembly_registers(end)["f"],
            menu=_menu(end, 0),
            constraints=tuple(end.solver.constraints),
        )
        for end in returned
    ]


def _native(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_display_intro_name_text_box")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 4, claripy.BVV(NAME_SOURCE >> 8, 8))
    state.memory.store(NATIVE_STATE + 5, claripy.BVV(NAME_SOURCE & 0xFF, 8))
    state.memory.store(NATIVE_MEMORY + NAME_SOURCE, TITLE_NAME)
    state.memory.store(NATIVE_MEMORY + 0x6AA3, TITLE_NAME)
    state.memory.store(NATIVE_MEMORY + W_UPDATE_SPRITES_ENABLED, claripy.BVV(2, 8))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            a=native_registers(end, NATIVE_STATE)["a"],
            f=native_registers(end, NATIVE_STATE)["f"],
            menu=_menu(end, NATIVE_MEMORY),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_display_intro_name_text_box_pathwise_equivalence() -> None:
    inputs = symbolic_registers("display_intro_name_text_box")
    assert_pathwise_equivalent(
        _assembly(inputs),
        _native(inputs),
        ("a", "f", "menu"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_display_intro_name_text_box_exact_linked_body() -> None:
    loc = symbol_location(SYMBOLS, "DisplayIntroNameTextBox")
    assert linked_bytes(ROM, loc, len(EXPECTED)) == EXPECTED
