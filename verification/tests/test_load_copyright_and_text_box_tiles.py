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
from verification.harness.rom import linked_bytes, rom_window, symbol_location
from verification.tests.test_load_copyright_tiles import PlaceStringSummary

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
DONE = 0xEFFF
TILEMAP = 0xC3A0
TILEMAP_SIZE = 360
H_WY = 0xFFB0
R_LCDC = 0xFF40
R_ROMB = 0x2000
UI_LAYOUT_FLAGS = 0xFFF6
TEXT_STRING = 0x4556
PLACE_STRING = "PlaceString"
EXPECTED = bytes.fromhex("afe0b0cd0f19cda036")


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
    tilemap: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class ClearScreenSummary(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next = next_address

    def run(self) -> None:  # type: ignore[override]
        for offset in range(TILEMAP_SIZE):
            self.state.memory.store(TILEMAP + offset, claripy.BVV(0x7F, 8))
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.b = claripy.BVV(0, 8)
        self.state.regs.h = claripy.BVV(0xC5, 8)
        self.state.regs.l = claripy.BVV(0x08, 8)
        self.state.regs.f = claripy.BVV(0x42, 8)
        self.jump(self._next)


class LoadTextBoxSummary(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next = next_address

    def run(self) -> None:  # type: ignore[override]
        self.jump(self._next)


class CopyVideoDataSummary(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.b = claripy.BVV(4, 8)
        self.state.regs.c = claripy.BVV(4, 8)
        self.jump(self._next)


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["tilemap_in"] = claripy.BVS(f"{prefix}_tilemap_in", 8 * TILEMAP_SIZE)
    return values


def _setup_assembly(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    state.memory.store(TILEMAP, values["tilemap_in"])
    state.memory.store(UI_LAYOUT_FLAGS, claripy.BVV(0, 8))
    state.memory.store(H_WY, claripy.BVV(0, 8))
    state.memory.store(R_LCDC, claripy.BVV(0, 8))
    state.memory.store(R_ROMB, claripy.BVV(0, 8))


def _setup_native(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    state.memory.store(NATIVE_MEMORY + TILEMAP, values["tilemap_in"])
    state.memory.store(NATIVE_MEMORY + UI_LAYOUT_FLAGS, claripy.BVV(0, 8))
    state.memory.store(NATIVE_MEMORY + H_WY, claripy.BVV(0, 8))
    state.memory.store(NATIVE_MEMORY + R_LCDC, claripy.BVV(0, 8))
    state.memory.store(NATIVE_MEMORY + R_ROMB, claripy.BVV(0, 8))
    text = linked_bytes(ROM, symbol_location(SYMBOLS, "CopyrightTextString"), 0x32)
    for offset, value in enumerate(text):
        state.memory.store(NATIVE_MEMORY + TEXT_STRING + offset, claripy.BVV(value, 8))


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "LoadCopyrightAndTextBoxTiles")
    assert location.bank == 1
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
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
    clear = symbol_location(SYMBOLS, "ClearScreen")
    text = symbol_location(SYMBOLS, "LoadTextBoxTilePatterns")
    place = symbol_location(SYMBOLS, PLACE_STRING)
    base = location.address
    assert clear.bank == 0
    assert text.bank == 0
    assert place.bank == 0
    project.hook(clear.address, ClearScreenSummary(base + 6), length=3)
    project.hook(text.address, LoadTextBoxSummary(base + 9), length=3)
    project.hook(base + 18, CopyVideoDataSummary(base + 21), length=3)
    project.hook(place.address, PlaceStringSummary(DONE), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _setup_assembly(state, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(DONE, 16), endness="Iend_LE")
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=4)
    assert not manager.errored
    assert len(manager.found) == 1
    end = manager.found[0]
    return [
        Endpoint(
            **assembly_registers(end),
            tilemap=end.memory.load(TILEMAP, TILEMAP_SIZE),
            constraints=tuple(end.solver.constraints),
        )
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_load_copyright_and_text_box_tiles")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup_native(state, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    end = manager.deadended[0]
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            tilemap=end.memory.load(NATIVE_MEMORY + TILEMAP, TILEMAP_SIZE),
            constraints=tuple(end.solver.constraints),
        )
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_load_copyright_and_text_box_tiles_pathwise_equivalence() -> None:
    values = _inputs("load_copyright_and_text_box_tiles")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        ("a", "f", "b", "c", "d", "e", "h", "l", "tilemap"),
    )
