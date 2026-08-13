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
    Sm83DecRegister,
    Sm83LoadAAtHlIncrement,
    Sm83StoreAImmediate,
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
    low: claripy.ast.BV
    high: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _assembly_endpoint(
    symbol: str, inputs: dict[str, claripy.ast.BV]
) -> Endpoint:
    location = symbol_location(SYMBOLS, symbol)
    counter = symbol_location(SYMBOLS, "wUnknownSerialCounter").address
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
    if symbol == "IsUnknownCounterZero":
        project.hook(
            location.address + 4,
            Sm83LoadAAtHlIncrement(next_address=location.address + 5),
            length=1,
        )
    else:
        project.hook(
            location.address,
            Sm83DecRegister(register="a", next_address=location.address + 1),
            length=1,
        )
        project.hook(
            location.address + 1,
            Sm83StoreAImmediate(counter, location.address + 4),
            length=3,
        )
        project.hook(
            location.address + 4,
            Sm83StoreAImmediate(counter + 1, location.address + 7),
            length=3,
        )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    state.memory.store(counter, inputs["low"])
    state.memory.store(counter + 1, inputs["high"])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    end = collect_returns(project, state, GB_RETURN)[0]
    return Endpoint(
        **assembly_registers(end),
        low=end.memory.load(counter, 1),
        high=end.memory.load(counter + 1, 1),
        constraints=tuple(end.solver.constraints),
    )


def _native_endpoint(c_symbol: str, inputs: dict[str, claripy.ast.BV]) -> Endpoint:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(c_symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["low"])
    state.memory.store(NATIVE_STATE + 9, inputs["high"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    end = manager.deadended[0]
    return Endpoint(
        **native_registers(end, NATIVE_STATE),
        low=end.memory.load(NATIVE_STATE + 8, 1),
        high=end.memory.load(NATIVE_STATE + 9, 1),
        constraints=tuple(end.solver.constraints),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("assembly_symbol", "c_symbol"),
    [
        ("IsUnknownCounterZero", "port_is_unknown_counter_zero"),
        ("SetUnknownCounterToFFFF", "port_set_unknown_counter_to_ffff"),
    ],
)
def test_serial_counter_symbolic_equivalence(
    assembly_symbol: str, c_symbol: str
) -> None:
    inputs = symbolic_registers(assembly_symbol)
    inputs["low"] = claripy.BVS(f"{assembly_symbol}_low", 8)
    inputs["high"] = claripy.BVS(f"{assembly_symbol}_high", 8)
    assert_pathwise_equivalent(
        [_assembly_endpoint(assembly_symbol, inputs)],
        [_native_endpoint(c_symbol, inputs)],
        (*REGISTERS, "low", "high"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "size", "expected"),
    [
        ("IsUnknownCounterZero", 8, "e52147cc2ab6e1c9"),
        ("SetUnknownCounterToFFFF", 8, "3dea47ccea48ccc9"),
    ],
)
def test_serial_counter_machine_code_is_accounted_for(
    symbol: str, size: int, expected: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, size) == bytes.fromhex(expected)
