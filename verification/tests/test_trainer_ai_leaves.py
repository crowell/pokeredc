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
from verification.harness.sm83_shims import Sm83DecAtHl


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
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class AiCountEndpoint(Endpoint):
    ai_count: claripy.ast.BV


def _assembly_endpoint(inputs: dict[str, claripy.ast.BV]) -> Endpoint:
    location = symbol_location(SYMBOLS, "GenericAI")
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
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    end = collect_returns(project, state, GB_RETURN)[0]
    return Endpoint(**assembly_registers(end), constraints=tuple(end.solver.constraints))


def _native_endpoint(inputs: dict[str, claripy.ast.BV]) -> Endpoint:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_generic_ai")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    end = manager.deadended[0]
    return Endpoint(
        **native_registers(end, NATIVE_STATE), constraints=tuple(end.solver.constraints)
    )


def _decrement_ai_count_assembly(
    inputs: dict[str, claripy.ast.BV],
) -> AiCountEndpoint:
    location = symbol_location(SYMBOLS, "DecrementAICount")
    ai_count = symbol_location(SYMBOLS, "wAICount").address
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
        location.address + 3,
        Sm83DecAtHl(next_address=location.address + 4),
        length=1,
    )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    state.memory.store(ai_count, inputs["ai_count"])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    end = collect_returns(project, state, GB_RETURN)[0]
    return AiCountEndpoint(
        **assembly_registers(end),
        constraints=tuple(end.solver.constraints),
        ai_count=end.memory.load(ai_count, 1),
    )


def _decrement_ai_count_native(
    inputs: dict[str, claripy.ast.BV],
) -> AiCountEndpoint:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_decrement_ai_count")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["ai_count"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    end = manager.deadended[0]
    return AiCountEndpoint(
        **native_registers(end, NATIVE_STATE),
        constraints=tuple(end.solver.constraints),
        ai_count=end.memory.load(NATIVE_STATE + 8, 1),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_generic_ai_symbolic_equivalence() -> None:
    inputs = symbolic_registers("generic_ai")
    assert_pathwise_equivalent(
        [_assembly_endpoint(inputs)], [_native_endpoint(inputs)], REGISTERS
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_decrement_ai_count_symbolic_equivalence() -> None:
    inputs = symbolic_registers("decrement_ai_count")
    inputs["ai_count"] = claripy.BVS("decrement_ai_count_value", 8)
    assert_pathwise_equivalent(
        [_decrement_ai_count_assembly(inputs)],
        [_decrement_ai_count_native(inputs)],
        (*REGISTERS, "ai_count"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_generic_ai_machine_code_is_accounted_for() -> None:
    location = symbol_location(SYMBOLS, "GenericAI")
    assert linked_bytes(ROM, location, 2) == bytes.fromhex("a7c9")


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_decrement_ai_count_machine_code_is_accounted_for() -> None:
    location = symbol_location(SYMBOLS, "DecrementAICount")
    assert linked_bytes(ROM, location, 6) == bytes.fromhex("21dfcc3537c9")
