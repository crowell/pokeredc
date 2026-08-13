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
from verification.harness.sm83_shims import Sm83StoreAImmediate


ROOT = Path(__file__).resolve().parents[2]
VERIFY = ROOT / "verification"
NATIVE_ELF = VERIFY / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
GB_STACK = 0xD000
GB_RETURN = 0xFFFF
NATIVE_STATE = 0x100000
MEMORY_NAMES = ("ignore_counter", "status_flags5")


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
    ignore_counter: claripy.ast.BV
    status_flags5: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _addresses() -> dict[str, int]:
    return {
        "ignore_counter": symbol_location(SYMBOLS, "wIgnoreInputCounter").address,
        "status_flags5": symbol_location(SYMBOLS, "wStatusFlags5").address,
    }


def _assembly_endpoint(inputs: dict[str, claripy.ast.BV]) -> Endpoint:
    location = symbol_location(SYMBOLS, "IgnoreInputForHalfSecond")
    addresses = _addresses()
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
        location.address + 2,
        Sm83StoreAImmediate(addresses["ignore_counter"], location.address + 5),
        length=3,
    )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    for name, address in addresses.items():
        state.memory.store(address, inputs[name])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    end = collect_returns(project, state, GB_RETURN)[0]
    return Endpoint(
        **assembly_registers(end),
        **{name: end.memory.load(address, 1) for name, address in addresses.items()},
        constraints=tuple(end.solver.constraints),
    )


def _native_endpoint(inputs: dict[str, claripy.ast.BV]) -> Endpoint:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_ignore_input_for_half_second")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    for offset, name in enumerate(MEMORY_NAMES, 8):
        state.memory.store(NATIVE_STATE + offset, inputs[name])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    end = manager.deadended[0]
    return Endpoint(
        **native_registers(end, NATIVE_STATE),
        **{
            name: end.memory.load(NATIVE_STATE + offset, 1)
            for offset, name in enumerate(MEMORY_NAMES, 8)
        },
        constraints=tuple(end.solver.constraints),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_ignore_input_symbolic_equivalence() -> None:
    inputs = symbolic_registers("ignore_input")
    for name in MEMORY_NAMES:
        inputs[name] = claripy.BVS(f"ignore_input_{name}", 8)
    assert_pathwise_equivalent(
        [_assembly_endpoint(inputs)],
        [_native_endpoint(inputs)],
        (*REGISTERS, *MEMORY_NAMES),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_ignore_input_machine_code_is_accounted_for() -> None:
    location = symbol_location(SYMBOLS, "IgnoreInputForHalfSecond")
    assert linked_bytes(ROM, location, 13) == bytes.fromhex(
        "3e1eea3ad12130d77ef62677c9"
    )
