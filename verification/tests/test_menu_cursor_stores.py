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
from verification.harness.rom import collect_returns, linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import Sm83LoadAImmediate


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
GB_STACK = 0xD000
GB_RETURN = 0xFFFF
CURSOR = 0xCC30

CASES = (
    (
        "PlaceUnfilledArrowMenuCursor",
        "port_place_unfilled_arrow_menu_cursor",
        0xEC,
        "47fa30cc6ffa31cc6736ec78c9",
    ),
    (
        "EraseMenuCursor",
        "port_erase_menu_cursor",
        0x7F,
        "fa30cc6ffa31cc67367fc9",
    ),
)


class StoreAtHl(angr.SimProcedure):
    def __init__(self, tile: int, next_address: int) -> None:
        super().__init__()
        self._tile = tile
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        address = self.state.regs.hl
        low = self.state.globals["cursor_low"]
        high = self.state.globals["cursor_high"]
        tile = claripy.BVV(self._tile, 8)
        self.state.globals["cursor_low"] = claripy.If(
            address == CURSOR, tile, low
        )
        self.state.globals["cursor_high"] = claripy.If(
            address == CURSOR + 1, tile, high
        )
        self.state.globals["destination"] = tile
        self.jump(self._next_address)


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
    cursor_low: claripy.ast.BV
    cursor_high: claripy.ast.BV
    destination: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for name in ("cursor_low", "cursor_high", "destination"):
        values[name] = claripy.BVS(f"{prefix}_{name}", 8)
    return values


def alias_constraints(values: dict[str, claripy.ast.BV]) -> tuple[claripy.ast.Bool, ...]:
    address = claripy.Concat(values["cursor_high"], values["cursor_low"])
    return (
        claripy.Or(address != CURSOR, values["destination"] == values["cursor_low"]),
        claripy.Or(
            address != CURSOR + 1,
            values["destination"] == values["cursor_high"],
        ),
    )


def assembly(
    symbol: str, tile: int, values: dict[str, claripy.ast.BV]
) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, symbol)
    loaded = angr.Project(
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
    prefix = 1 if symbol == "PlaceUnfilledArrowMenuCursor" else 0
    loaded.hook(base + prefix, Sm83LoadAImmediate(CURSOR, base + prefix + 3), length=3)
    loaded.hook(
        base + prefix + 4,
        Sm83LoadAImmediate(CURSOR + 1, base + prefix + 7),
        length=3,
    )
    loaded.hook(
        base + prefix + 8,
        StoreAtHl(tile, base + prefix + 10),
        length=2,
    )
    state = loaded.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.memory.store(CURSOR, values["cursor_low"])
    state.memory.store(CURSOR + 1, values["cursor_high"])
    state.globals["cursor_low"] = values["cursor_low"]
    state.globals["cursor_high"] = values["cursor_high"]
    state.globals["destination"] = values["destination"]
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    ends = collect_returns(loaded, state, GB_RETURN)
    constraints = alias_constraints(values)
    return [
        Endpoint(
            **assembly_registers(end),
            cursor_low=end.globals["cursor_low"],
            cursor_high=end.globals["cursor_high"],
            destination=end.globals["destination"],
            constraints=constraints + tuple(end.solver.constraints),
        )
        for end in ends
    ]


def native(symbol: str, values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    loaded = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = loaded.loader.find_symbol(symbol)
    assert function is not None
    state = loaded.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(
        NATIVE_STATE + 8,
        claripy.Concat(
            values["cursor_low"],
            values["cursor_high"],
            values["destination"],
        ),
    )
    manager = loaded.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    constraints = alias_constraints(values)
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            cursor_low=end.memory.load(NATIVE_STATE + 8, 1),
            cursor_high=end.memory.load(NATIVE_STATE + 9, 1),
            destination=end.memory.load(NATIVE_STATE + 10, 1),
            constraints=constraints + tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native port not built")
@pytest.mark.parametrize("symbol,c_symbol,tile,_body", CASES)
def test_equivalence(symbol: str, c_symbol: str, tile: int, _body: str) -> None:
    values = inputs(symbol.lower())
    assert_pathwise_equivalent(
        assembly(symbol, tile, values),
        native(c_symbol, values),
        (*REGISTERS, "cursor_low", "cursor_high", "destination"),
    )


@pytest.mark.parametrize("symbol,_c_symbol,_tile,body", CASES)
def test_exact_body(symbol: str, _c_symbol: str, _tile: int, body: str) -> None:
    expected = bytes.fromhex(body)
    assert linked_bytes(ROM, symbol_location(SYMBOLS, symbol), len(expected)) == expected
