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
from verification.harness.sm83_shims import Sm83LoadAImmediate


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
BOUNDARY = 0xEFFF

CASES = (
    (
        "SlotMachine_GetWheel1Tiles",
        "port_slot_machine_get_wheel1_tiles_begin",
        0xCD3E,
        "1141cd21e579fa3ecd",
        23,
    ),
    (
        "SlotMachine_GetWheel2Tiles",
        "port_slot_machine_get_wheel2_tiles_begin",
        0xCD3F,
        "1144cd21097afa3fcd",
        35,
    ),
    (
        "SlotMachine_GetWheel3Tiles",
        "port_slot_machine_get_wheel3_tiles_begin",
        0xCD40,
        "1147cd212d7afa40cd",
        47,
    ),
)


class Boundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(BOUNDARY)


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
    offset: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["offset"] = claripy.BVS(f"{prefix}_offset", 8)
    return values


def assembly(
    symbol: str, offset_address: int, values: dict[str, claripy.ast.BV]
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
    loaded.hook(
        location.address + 6,
        Sm83LoadAImmediate(offset_address, location.address + 9),
        length=3,
    )
    loaded.hook(location.address + 9, Boundary(), length=1)
    state = loaded.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.memory.store(offset_address, values["offset"])
    manager = loaded.factory.simulation_manager(state)
    manager.explore(find=BOUNDARY)
    assert not manager.errored and len(manager.found) == 1
    end = manager.found[0]
    return [
        Endpoint(
            **assembly_registers(end),
            offset=end.memory.load(offset_address, 1),
            constraints=tuple(end.solver.constraints),
        )
    ]


def native(symbol: str, values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    loaded = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = loaded.loader.find_symbol(symbol)
    assert function is not None
    state = loaded.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, values["offset"])
    manager = loaded.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            offset=end.memory.load(NATIVE_STATE + 8, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native port not built")
@pytest.mark.parametrize("symbol,c_symbol,offset_address,_setup,_length", CASES)
def test_setup_equivalence(
    symbol: str,
    c_symbol: str,
    offset_address: int,
    _setup: str,
    _length: int,
) -> None:
    values = inputs(symbol.lower())
    assert_pathwise_equivalent(
        assembly(symbol, offset_address, values),
        native(c_symbol, values),
        (*REGISTERS, "offset"),
    )


@pytest.mark.parametrize("symbol,_c_symbol,_offset_address,setup,length", CASES)
def test_exact_composed_body(
    symbol: str,
    _c_symbol: str,
    _offset_address: int,
    setup: str,
    length: int,
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    generic = "4f0600090e032a1213230d20f9c9"
    wheel1 = "1141cd21e579fa3ecd" + generic
    wheel2 = "1144cd21097afa3fcd" + "cdc976" + wheel1
    expected = bytes.fromhex(
        {
            "SlotMachine_GetWheel1Tiles": wheel1,
            "SlotMachine_GetWheel2Tiles": wheel2,
            "SlotMachine_GetWheel3Tiles": (
                "1147cd212d7afa40cd" + "cdc976" + wheel2
            ),
        }[symbol]
    )
    assert len(expected) == length
    assert linked_bytes(ROM, location, length) == expected
