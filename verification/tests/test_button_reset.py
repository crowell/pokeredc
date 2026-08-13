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
from verification.harness.sm83_shims import Sm83StoreAHighImmediate, Sm83StoreAImmediate


ROOT = Path(__file__).resolve().parents[2]
VERIFY = ROOT / "verification"
NATIVE_ELF = VERIFY / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
GB_STACK = 0xD000
GB_RETURN = 0xFFFF
NATIVE_STATE = 0x100000
MEMORY_SYMBOLS = (
    "wJoyIgnore",
    "hJoyHeld",
    "hJoyPressed",
    "hJoyReleased",
    "wCurMapScript",
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


def _assembly(inputs: dict[str, claripy.ast.BV]) -> Endpoint:
    location = symbol_location(SYMBOLS, "ResetButtonPressedAndMapScript")
    addresses = tuple(symbol_location(SYMBOLS, name).address for name in MEMORY_SYMBOLS)
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
    hooks = (
        (1, Sm83StoreAImmediate, addresses[0], 3),
        (4, Sm83StoreAHighImmediate, addresses[1], 2),
        (6, Sm83StoreAHighImmediate, addresses[2], 2),
        (8, Sm83StoreAHighImmediate, addresses[3], 2),
        (10, Sm83StoreAImmediate, addresses[4], 3),
    )
    for offset, procedure, address, length in hooks:
        project.hook(
            location.address + offset,
            procedure(address, location.address + offset + length),
            length=length,
        )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    for index, address in enumerate(addresses):
        state.memory.store(address, inputs[f"memory{index}"])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    assert len(returned) == 1
    end = returned[0]
    return Endpoint(
        **assembly_registers(end),
        memory=claripy.Concat(*(end.memory.load(address, 1) for address in addresses)),
        constraints=tuple(end.solver.constraints),
    )


def _native(inputs: dict[str, claripy.ast.BV]) -> Endpoint:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_reset_button_pressed_and_map_script")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    for index in range(5):
        state.memory.store(NATIVE_STATE + 8 + index, inputs[f"memory{index}"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    end = manager.deadended[0]
    return Endpoint(
        **native_registers(end, NATIVE_STATE),
        memory=end.memory.load(NATIVE_STATE + 8, 5),
        constraints=tuple(end.solver.constraints),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_reset_button_pressed_and_map_script_symbolic_equivalence() -> None:
    inputs = symbolic_registers("reset_button_pressed_and_map_script")
    for index in range(5):
        inputs[f"memory{index}"] = claripy.BVS(f"button_reset_memory{index}", 8)
    assert_pathwise_equivalent(
        [_assembly(inputs)], [_native(inputs)], (*REGISTERS, "memory")
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_reset_button_pressed_and_map_script_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "ResetButtonPressedAndMapScript")
    assert linked_bytes(ROM, location, 14) == bytes.fromhex(
        "afea6bcde0b4e0b3e0b2ea39dac9"
    )
