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
from verification.harness.rom import (
    collect_returns,
    linked_bytes,
    rom_window,
    symbol_location,
)
from verification.harness.sm83_shims import (
    Sm83LoadAImmediate,
    Sm83StoreAAtHlIncrement,
)


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
GB_STACK = 0xD000
GB_RETURN = 0xFFFF
WARP_SOURCE = 0xD73B
MAP_SOURCE = 0xD73C
DESTINATIONS = (0xD3B1, 0xD3B2, 0xD3B5, 0xD3B6)
CASES = (
    (
        "CeladonMartElevatorStoreWarpEntriesScript",
        "port_celadon_mart_elevator_store_warp_entries",
        "21afd3fa3bd747fa3cd74fcd2a46232378227922c9",
    ),
    (
        "RocketHideoutElevatorStoreWarpEntriesScript",
        "port_rocket_hideout_elevator_store_warp_entries",
        "21afd3fa3bd747fa3cd74fcd3a57232378227922c9",
    ),
    (
        "SilphCoElevatorStoreWarpEntriesScript",
        "port_silph_co_elevator_store_warp_entries",
        "21afd3fa3bd747fa3cd74fcdea57232378227922c9",
    ),
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
    memory: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["source_warp"] = claripy.BVS(f"{prefix}_source_warp", 8)
    values["source_map"] = claripy.BVS(f"{prefix}_source_map", 8)
    for index in range(4):
        values[f"destination{index}"] = claripy.BVS(
            f"{prefix}_destination{index}", 8
        )
    return values


def assembly(symbol: str, values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, symbol)
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
    project.hook(
        base + 3, Sm83LoadAImmediate(WARP_SOURCE, base + 6), length=3
    )
    project.hook(
        base + 7, Sm83LoadAImmediate(MAP_SOURCE, base + 10), length=3
    )
    project.hook(
        base + 17, Sm83StoreAAtHlIncrement(base + 18), length=1
    )
    project.hook(
        base + 19, Sm83StoreAAtHlIncrement(base + 20), length=1
    )
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.memory.store(WARP_SOURCE, values["source_warp"])
    state.memory.store(MAP_SOURCE, values["source_map"])
    for index, address in enumerate(DESTINATIONS):
        state.memory.store(address, values[f"destination{index}"])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    return [
        Endpoint(
            **assembly_registers(end),
            memory=claripy.Concat(
                end.memory.load(WARP_SOURCE, 1),
                end.memory.load(MAP_SOURCE, 1),
                *(end.memory.load(address, 1) for address in DESTINATIONS),
            ),
            constraints=tuple(end.solver.constraints),
        )
        for end in returned
    ]


def native(symbol: str, values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(
        NATIVE_STATE + 8,
        claripy.Concat(
            values["source_warp"],
            values["source_map"],
            *(values[f"destination{index}"] for index in range(4)),
        ),
    )
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=end.memory.load(NATIVE_STATE + 8, 6),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native port not built")
@pytest.mark.parametrize("symbol,c_symbol,_body", CASES)
def test_equivalence(symbol: str, c_symbol: str, _body: str) -> None:
    values = inputs(symbol.lower())
    assert_pathwise_equivalent(
        assembly(symbol, values), native(c_symbol, values), (*REGISTERS, "memory")
    )


@pytest.mark.parametrize("symbol,_c_symbol,body", CASES)
def test_exact_body(symbol: str, _c_symbol: str, body: str) -> None:
    location = symbol_location(SYMBOLS, symbol)
    expected = bytes.fromhex(body)
    assert linked_bytes(ROM, location, len(expected)) == expected
