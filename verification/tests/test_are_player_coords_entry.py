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
NATIVE_ELF = ROOT / "verification" / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000


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
    coords: claripy.ast.BV
    continuation: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def assembly(inputs: dict[str, claripy.ast.BV]) -> Endpoint:
    location = symbol_location(SYMBOLS, "ArePlayerCoordsInArray")
    tail = symbol_location(SYMBOLS, "CheckCoords").address
    y_address = symbol_location(SYMBOLS, "wYCoord").address
    x_address = symbol_location(SYMBOLS, "wXCoord").address
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
    project.hook(
        location.address,
        Sm83LoadAImmediate(y_address, location.address + 3),
        length=3,
    )
    project.hook(
        location.address + 4,
        Sm83LoadAImmediate(x_address, location.address + 7),
        length=3,
    )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    state.memory.store(y_address, inputs["y"])
    state.memory.store(x_address, inputs["x"])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=tail)
    assert not manager.errored and len(manager.found) == 1
    end = manager.found[0]
    return Endpoint(
        **assembly_registers(end),
        coords=claripy.Concat(end.memory.load(y_address, 1), end.memory.load(x_address, 1)),
        continuation=claripy.BVV(1, 8),
        constraints=tuple(end.solver.constraints),
    )


def native(inputs: dict[str, claripy.ast.BV]) -> Endpoint:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_are_player_coords_in_array")
    assert function
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["y"])
    state.memory.store(NATIVE_STATE + 9, inputs["x"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    end = manager.deadended[0]
    return Endpoint(
        **native_registers(end, NATIVE_STATE),
        coords=end.memory.load(NATIVE_STATE + 8, 2),
        continuation=claripy.BVV(1, 8),
        constraints=tuple(end.solver.constraints),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
def test_are_player_coords_entry_equivalence() -> None:
    inputs = symbolic_registers("are_player_coords")
    inputs["y"] = claripy.BVS("player_y", 8)
    inputs["x"] = claripy.BVS("player_x", 8)
    assert_pathwise_equivalent(
        [assembly(inputs)],
        [native(inputs)],
        (*REGISTERS, "coords", "continuation"),
    )


def test_are_player_coords_entry_exact_body() -> None:
    location = symbol_location(SYMBOLS, "ArePlayerCoordsInArray")
    y_address = symbol_location(SYMBOLS, "wYCoord").address
    x_address = symbol_location(SYMBOLS, "wXCoord").address
    expected = bytes(
        (0xFA, y_address & 0xFF, y_address >> 8, 0x47,
         0xFA, x_address & 0xFF, x_address >> 8, 0x4F)
    )
    assert linked_bytes(ROM, location, len(expected)) == expected
