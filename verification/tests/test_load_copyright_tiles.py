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
from verification.harness.rom import (
    linked_bytes,
    rom_window,
    sm83_flags_to_z80,
    symbol_location,
)

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
AUTO_BG_TRANSFER = 0xFFBA
UI_LAYOUT_FLAGS = 0xFFF6
TEXT_STRING = 0x4556
TEXT_END = 0x50
TX_NEXT = 0x4E
SCREEN_WIDTH = 20
START_CURSOR = 0xC42E
EXPECTED = bytes.fromhex("11c860210096011c04cd4818212ec4115645c35519")


def _copyright_bytes() -> bytes:
    location = symbol_location(SYMBOLS, "CopyrightTextString")
    return linked_bytes(ROM, location, 0x32)


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


class CopyVideoDataSummary(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next = next_address

    def run(self) -> None:  # type: ignore[override]
        # CopyVideoData transfers 28 tiles in three full 8-tile frames and a
        # final 4-tile frame, then restores AF and the caller's ROM bank.
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.c = claripy.BVV(4, 8)
        self.state.regs.f = sm83_flags_to_z80(self.state.globals["saved_f"])
        self.state.regs.b = claripy.BVV(4, 8)
        self.jump(self._next)


class PlaceStringSummary(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next = next_address

    def run(self) -> None:  # type: ignore[override]
        source = _copyright_bytes()
        cursor = START_CURSOR
        destination = cursor
        for value in source:
            if value == TEXT_END:
                break
            if value == TX_NEXT:
                destination = (cursor + (SCREEN_WIDTH * 2)) & 0xFFFF
                cursor = destination
                continue
            self.state.memory.store(destination, claripy.BVV(value, 8))
            destination = (destination + 1) & 0xFFFF
        self.state.regs.a = claripy.BVV(TEXT_END, 8)
        self.state.regs.b = claripy.BVV(destination >> 8, 8)
        self.state.regs.c = claripy.BVV(destination & 0xFF, 8)
        self.state.regs.d = claripy.BVV(TEXT_STRING >> 8, 8)
        self.state.regs.e = claripy.BVV(TEXT_STRING + len(source) - 1, 8)
        self.state.regs.h = claripy.BVV(cursor >> 8, 8)
        self.state.regs.l = claripy.BVV(cursor & 0xFF, 8)
        self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0xC0, 8))
        self.jump(self._next)


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["tilemap_in"] = claripy.BVS(f"{prefix}_tilemap_in", 8 * TILEMAP_SIZE)
    return values
def _setup_assembly(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    state.globals["saved_f"] = values["f"]
    state.globals["saved_b"] = values["b"]
    state.globals["saved_d"] = values["d"]
    state.globals["saved_e"] = values["e"]
    state.globals["saved_h"] = values["h"]
    state.globals["saved_l"] = values["l"]
    state.memory.store(TILEMAP, values["tilemap_in"])
    state.memory.store(UI_LAYOUT_FLAGS, claripy.BVV(0, 8))


def _setup_native(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    state.memory.store(NATIVE_MEMORY + AUTO_BG_TRANSFER, claripy.BVV(0, 8))
    state.memory.store(NATIVE_MEMORY + TILEMAP, values["tilemap_in"])
    text = _copyright_bytes()
    for offset, value in enumerate(text):
        state.memory.store(NATIVE_MEMORY + TEXT_STRING + offset, claripy.BVV(value, 8))


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "LoadCopyrightTiles")
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
    base = location.address
    copy = symbol_location(SYMBOLS, "CopyVideoData")
    place = symbol_location(SYMBOLS, "PlaceString")
    assert copy.bank == 0
    assert place.bank == 0
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _setup_assembly(state, values)
    state.regs.sp = STACK
    project.hook(base + 9, CopyVideoDataSummary(base + 12), length=3)
    project.hook(place.address, PlaceStringSummary(DONE), length=3)
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
    function = project.loader.find_symbol("port_load_copyright_tiles")
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr,
        NATIVE_STATE,
        NATIVE_MEMORY,
    )
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
def test_load_copyright_tiles_pathwise_equivalence() -> None:
    values = _inputs("load_copyright_tiles")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        ("a", "f", "b", "c", "d", "e", "h", "l", "tilemap"),
    )
