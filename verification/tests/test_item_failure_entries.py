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
from verification.harness.sm83_shims import Sm83StoreAImmediate


ROOT = Path(__file__).resolve().parents[2]
VERIFY = ROOT / "verification"
NATIVE_ELF = VERIFY / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000

PORTS = (
    ("ItemUseNoEffect", "ItemUseNoEffectText", "port_item_use_no_effect", True),
    ("ItemUseNotTime", "ItemUseNotTimeText", "port_item_use_not_time", True),
    (
        "ItemUseNotYoursToUse",
        "ItemUseNotYoursToUseText",
        "port_item_use_not_yours_to_use",
        True,
    ),
    (
        "NoCyclingAllowedHere",
        "NoCyclingAllowedHereText",
        "port_no_cycling_allowed_here",
        True,
    ),
    (
        "BoxFullCannotThrowBall",
        "BoxFullCannotThrowBallText",
        "port_box_full_cannot_throw_ball",
        True,
    ),
    (
        "SurfingAttemptFailed",
        "NoSurfingHereText",
        "port_surfing_attempt_failed",
        False,
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
    continuation: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class ItemFailedEndpoint(Endpoint):
    action_result: claripy.ast.BV


def _assembly(symbol: str, inputs: dict[str, claripy.ast.BV]) -> Endpoint:
    location = symbol_location(SYMBOLS, symbol)
    tail = symbol_location(SYMBOLS, "ItemUseFailed").address
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
        continuation=claripy.BVV(1, 8),
        constraints=tuple(end.solver.constraints),
    )


def _native(c_symbol: str, inputs: dict[str, claripy.ast.BV]) -> Endpoint:
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
        continuation=claripy.BVV(1, 8),
        constraints=tuple(end.solver.constraints),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("symbol,_text_symbol,c_symbol,_has_jump", PORTS)
def test_item_failure_entry_symbolic_equivalence(
    symbol: str, _text_symbol: str, c_symbol: str, _has_jump: bool
) -> None:
    inputs = symbolic_registers(symbol.lower())
    assert_pathwise_equivalent(
        [_assembly(symbol, inputs)],
        [_native(c_symbol, inputs)],
        (*REGISTERS, "continuation"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("symbol,text_symbol,_c_symbol,has_jump", PORTS)
def test_item_failure_entry_exact_linked_body(
    symbol: str, text_symbol: str, _c_symbol: str, has_jump: bool
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    text_address = symbol_location(SYMBOLS, text_symbol).address
    expected = bytearray((0x21, text_address & 0xFF, text_address >> 8))
    if has_jump:
        tail = symbol_location(SYMBOLS, "ItemUseFailed").address
        displacement = (tail - (location.address + 5)) & 0xFF
        expected.extend((0x18, displacement))
    assert linked_bytes(ROM, location, len(expected)) == bytes(expected)


def _item_use_failed_assembly(
    inputs: dict[str, claripy.ast.BV]
) -> ItemFailedEndpoint:
    location = symbol_location(SYMBOLS, "ItemUseFailed")
    destination = symbol_location(SYMBOLS, "wActionResultOrTookBattleTurn").address
    tail = symbol_location(SYMBOLS, "PrintText").address
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
        location.address + 1,
        Sm83StoreAImmediate(destination, location.address + 4),
        length=3,
    )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    state.memory.store(destination, inputs["action_result"])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=tail)
    assert not manager.errored
    assert len(manager.found) == 1
    end = manager.found[0]
    return ItemFailedEndpoint(
        **assembly_registers(end),
        continuation=claripy.BVV(1, 8),
        constraints=tuple(end.solver.constraints),
        action_result=end.memory.load(destination, 1),
    )


def _item_use_failed_native(
    inputs: dict[str, claripy.ast.BV]
) -> ItemFailedEndpoint:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_item_use_failed")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["action_result"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    end = manager.deadended[0]
    return ItemFailedEndpoint(
        **native_registers(end, NATIVE_STATE),
        continuation=claripy.BVV(1, 8),
        constraints=tuple(end.solver.constraints),
        action_result=end.memory.load(NATIVE_STATE + 8, 1),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_item_use_failed_symbolic_equivalence() -> None:
    inputs = symbolic_registers("item_use_failed")
    inputs["action_result"] = claripy.BVS("item_use_failed_action_result", 8)
    assert_pathwise_equivalent(
        [_item_use_failed_assembly(inputs)],
        [_item_use_failed_native(inputs)],
        (*REGISTERS, "action_result", "continuation"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_item_use_failed_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "ItemUseFailed")
    destination = symbol_location(SYMBOLS, "wActionResultOrTookBattleTurn").address
    tail = symbol_location(SYMBOLS, "PrintText").address
    assert linked_bytes(ROM, location, 7) == bytes(
        (
            0xAF,
            0xEA, destination & 0xFF, destination >> 8,
            0xC3, tail & 0xFF, tail >> 8,
        )
    )
