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
from verification.harness.sm83_shims import (
    Sm83AddHlRegisterPair,
    Sm83CpImmediate,
    Sm83LoadAImmediate,
)


ROOT = Path(__file__).resolve().parents[2]
VERIFY = ROOT / "verification"
NATIVE_ELF = VERIFY / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
GB_STACK = 0xD000
GB_RETURN = 0xFFFF
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
    value: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class TailEndpoint(Endpoint):
    continuation: claripy.ast.BV


def _assembly(inputs: dict[str, claripy.ast.BV]) -> Endpoint:
    location = symbol_location(SYMBOLS, "SafariZoneGateReturnSimulatedJoypadStateScript")
    value_address = symbol_location(SYMBOLS, "wSimulatedJoypadStatesIndex").address
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
        Sm83LoadAImmediate(value_address, location.address + 3),
        length=3,
    )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    state.memory.store(value_address, inputs["value"])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    assert len(returned) == 1
    end = returned[0]
    return Endpoint(
        **assembly_registers(end),
        value=end.memory.load(value_address, 1),
        constraints=tuple(end.solver.constraints),
    )


def _native(inputs: dict[str, claripy.ast.BV]) -> Endpoint:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(
        "port_safari_zone_gate_return_simulated_joypad_state_script"
    )
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["value"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    end = manager.deadended[0]
    return Endpoint(
        **native_registers(end, NATIVE_STATE),
        value=end.memory.load(NATIVE_STATE + 8, 1),
        constraints=tuple(end.solver.constraints),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_safari_zone_gate_return_simulated_joypad_state_script_equivalence() -> None:
    inputs = symbolic_registers("safari_zone_gate_return_simulated_joypad")
    inputs["value"] = claripy.BVS("safari_zone_gate_simulated_joypad_index", 8)
    assert_pathwise_equivalent(
        [_assembly(inputs)], [_native(inputs)], (*REGISTERS, "value")
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_safari_zone_gate_return_simulated_joypad_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "SafariZoneGateReturnSimulatedJoypadStateScript")
    value_address = symbol_location(SYMBOLS, "wSimulatedJoypadStatesIndex").address
    assert linked_bytes(ROM, location, 5) == bytes(
        (0xFA, value_address & 0xFF, value_address >> 8, 0xA7, 0xC9)
    )


def _outside_map_assembly(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "CheckIfInOutsideMap")
    value_address = symbol_location(SYMBOLS, "wCurMapTileset").address
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
        Sm83LoadAImmediate(value_address, location.address + 3),
        length=3,
    )
    project.hook(
        location.address + 5,
        Sm83CpImmediate(0x17, location.address + 7),
        length=2,
    )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    state.memory.store(value_address, inputs["value"])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    return [
        Endpoint(
            **assembly_registers(end),
            value=end.memory.load(value_address, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in returned
    ]


def _outside_map_native(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_check_if_in_outside_map")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["value"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            value=end.memory.load(NATIVE_STATE + 8, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_check_if_in_outside_map_symbolic_equivalence() -> None:
    inputs = symbolic_registers("check_if_in_outside_map")
    inputs["value"] = claripy.BVS("check_if_in_outside_map_tileset", 8)
    assert_pathwise_equivalent(
        _outside_map_assembly(inputs),
        _outside_map_native(inputs),
        (*REGISTERS, "value"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_check_if_in_outside_map_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "CheckIfInOutsideMap")
    value_address = symbol_location(SYMBOLS, "wCurMapTileset").address
    assert linked_bytes(ROM, location, 8) == bytes(
        (
            0xFA, value_address & 0xFF, value_address >> 8,
            0xA7, 0xC8, 0xFE, 0x17, 0xC9,
        )
    )


def _selected_move_assembly(inputs: dict[str, claripy.ast.BV]) -> Endpoint:
    location = symbol_location(SYMBOLS, "GetSelectedMoveOffset2")
    value_address = symbol_location(SYMBOLS, "wCurrentMenuItem").address
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
        Sm83LoadAImmediate(value_address, location.address + 3),
        length=3,
    )
    project.hook(
        location.address + 6,
        Sm83AddHlRegisterPair("bc", location.address + 7),
        length=1,
    )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    state.memory.store(value_address, inputs["value"])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    assert len(returned) == 1
    end = returned[0]
    return Endpoint(
        **assembly_registers(end),
        value=end.memory.load(value_address, 1),
        constraints=tuple(end.solver.constraints),
    )


def _selected_move_native(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_get_selected_move_offset2")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["value"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            value=end.memory.load(NATIVE_STATE + 8, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_get_selected_move_offset2_symbolic_equivalence() -> None:
    inputs = symbolic_registers("get_selected_move_offset2")
    inputs["value"] = claripy.BVS("get_selected_move_offset2_menu_item", 8)
    assert_pathwise_equivalent(
        [_selected_move_assembly(inputs)],
        _selected_move_native(inputs),
        (*REGISTERS, "value"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_get_selected_move_offset2_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "GetSelectedMoveOffset2")
    value_address = symbol_location(SYMBOLS, "wCurrentMenuItem").address
    assert linked_bytes(ROM, location, 8) == bytes(
        (0xFA, value_address & 0xFF, value_address >> 8, 0x4F, 0x06, 0, 0x09, 0xC9)
    )


def _conditional_failed_assembly(
    inputs: dict[str, claripy.ast.BV]
) -> list[TailEndpoint]:
    location = symbol_location(SYMBOLS, "ConditionalPrintButItFailed")
    tail = symbol_location(SYMBOLS, "PrintButItFailedText_").address
    value_address = symbol_location(SYMBOLS, "wMoveDidntMiss").address
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
        Sm83LoadAImmediate(value_address, location.address + 3),
        length=3,
    )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    state.memory.store(value_address, inputs["value"])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    manager = project.factory.simulation_manager(state)
    manager.stashes["found"] = []
    while manager.active:
        manager.move(
            from_stash="active",
            to_stash="found",
            filter_func=lambda candidate: candidate.addr in {tail, GB_RETURN},
        )
        if manager.active:
            manager.step()
    assert not manager.errored
    assert {end.addr for end in manager.found} == {tail, GB_RETURN}
    return [
        TailEndpoint(
            **assembly_registers(end),
            value=end.memory.load(value_address, 1),
            constraints=tuple(end.solver.constraints),
            continuation=claripy.BVV(1 if end.addr == tail else 0, 8),
        )
        for end in manager.found
    ]


def _conditional_failed_native(
    inputs: dict[str, claripy.ast.BV]
) -> list[TailEndpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_conditional_print_but_it_failed")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["value"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        TailEndpoint(
            **native_registers(end, NATIVE_STATE),
            value=end.memory.load(NATIVE_STATE + 8, 1),
            constraints=tuple(end.solver.constraints),
            continuation=claripy.If(
                end.regs.rax[7:0] == 0,
                claripy.BVV(0, 8),
                claripy.BVV(1, 8),
            ),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_conditional_print_but_it_failed_symbolic_equivalence() -> None:
    inputs = symbolic_registers("conditional_print_but_it_failed")
    inputs["value"] = claripy.BVS("conditional_print_but_it_failed_value", 8)
    assert_pathwise_equivalent(
        _conditional_failed_assembly(inputs),
        _conditional_failed_native(inputs),
        (*REGISTERS, "value", "continuation"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_conditional_print_but_it_failed_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "ConditionalPrintButItFailed")
    value_address = symbol_location(SYMBOLS, "wMoveDidntMiss").address
    assert linked_bytes(ROM, location, 5) == bytes(
        (0xFA, value_address & 0xFF, value_address >> 8, 0xA7, 0xC0)
    )
