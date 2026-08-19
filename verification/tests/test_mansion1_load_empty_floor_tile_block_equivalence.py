from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
    native_registers,
    set_assembly_registers,
    store_native_registers,
    symbolic_registers,
)
from verification.harness.rom import (
    linked_bytes,
    rom_window,
    symbol_location,
    z80_flags_to_sm83,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
DONE = 0xEFFF
W_NEW_TILE_BLOCK_ID = 0xD09F  # wNewTileBlockID from pokered.sym


@dataclass(frozen=True)
class E:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    new_tile_block_id: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native")
def test_exact_body() -> None:
    loc = symbol_location(SYMBOLS, "Mansion1LoadEmptyFloorTileBlock")
    # ld a, $0e; ld [wNewTileBlockID], a; ld a, $17; jp Mansion1ReplaceBlock
    assert linked_bytes(ROM, loc, 10) == bytes.fromhex("3e0eea9fd03e17cd6d3e")