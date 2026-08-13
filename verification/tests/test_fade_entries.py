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
from verification.harness.rom import linked_bytes, rom_window, symbol_location


ROOT = Path(__file__).resolve().parents[2]
VERIFY = ROOT / "verification"
NATIVE_ELF = VERIFY / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000

PORTS = (
    ("GBFadeInFromBlack", "FadePal1", 0, 4, "GBFadeIncCommon", "port_gb_fade_in_from_black", True),
    ("GBFadeOutToWhite", "FadePal6", 0, 3, "GBFadeIncCommon", "port_gb_fade_out_to_white", False),
    ("GBFadeOutToBlack", "FadePal4", 2, 4, "GBFadeDecCommon", "port_gb_fade_out_to_black", True),
    ("GBFadeInFromWhite", "FadePal7", 2, 3, "GBFadeDecCommon", "port_gb_fade_in_from_white", False),
)


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
    continuation: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _assembly(symbol: str, tail_symbol: str, inputs: dict[str, claripy.ast.BV]) -> Endpoint:
    location = symbol_location(SYMBOLS, symbol)
    tail = symbol_location(SYMBOLS, tail_symbol).address
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
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=tail)
    assert not manager.errored
    assert len(manager.found) == 1
    end = manager.found[0]
    return Endpoint(
        **assembly_registers(end),
        continuation=claripy.BVV(1 if tail_symbol == "GBFadeIncCommon" else 2, 8),
        constraints=tuple(end.solver.constraints),
    )


def _native(
    c_symbol: str, tail_symbol: str, inputs: dict[str, claripy.ast.BV]
) -> Endpoint:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(c_symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    end = manager.deadended[0]
    return Endpoint(
        **native_registers(end, NATIVE_STATE),
        continuation=claripy.BVV(1 if tail_symbol == "GBFadeIncCommon" else 2, 8),
        constraints=tuple(end.solver.constraints),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    "symbol,_palette_symbol,_adjustment,_count,tail_symbol,c_symbol,_has_jump", PORTS
)
def test_fade_entry_symbolic_equivalence(
    symbol: str,
    _palette_symbol: str,
    _adjustment: int,
    _count: int,
    tail_symbol: str,
    c_symbol: str,
    _has_jump: bool,
) -> None:
    inputs = symbolic_registers(symbol.lower())
    assert_pathwise_equivalent(
        [_assembly(symbol, tail_symbol, inputs)],
        [_native(c_symbol, tail_symbol, inputs)],
        (*REGISTERS, "continuation"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    "symbol,palette_symbol,adjustment,count,tail_symbol,_c_symbol,has_jump", PORTS
)
def test_fade_entry_exact_linked_body(
    symbol: str,
    palette_symbol: str,
    adjustment: int,
    count: int,
    tail_symbol: str,
    _c_symbol: str,
    has_jump: bool,
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    palette = symbol_location(SYMBOLS, palette_symbol).address + adjustment
    expected = bytearray((0x21, palette & 0xFF, palette >> 8, 0x06, count))
    if has_jump:
        tail = symbol_location(SYMBOLS, tail_symbol).address
        expected.extend((0x18, (tail - (location.address + 7)) & 0xFF))
    assert linked_bytes(ROM, location, len(expected)) == bytes(expected)
