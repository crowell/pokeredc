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
from verification.harness.sm83_shims import Sm83DecRegister, Sm83StoreAAtHlIncrement


ROOT = Path(__file__).resolve().parents[2]
VERIFY = ROOT / "verification"
NATIVE_ELF = VERIFY / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
GB_STACK = 0xD000
GB_RETURN = 0xFFFF
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000


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
    first: claripy.ast.BV
    second: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _initial_hl(inputs: dict[str, claripy.ast.BV]) -> claripy.ast.BV:
    return claripy.Concat(inputs["h"], inputs["l"])


def _assembly_endpoint(inputs: dict[str, claripy.ast.BV]) -> Endpoint:
    location = symbol_location(SYMBOLS, "EmptySRAMBox")
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
        Sm83StoreAAtHlIncrement(next_address=location.address + 2),
        length=1,
    )
    project.hook(
        location.address + 2,
        Sm83DecRegister(register="a", next_address=location.address + 3),
        length=1,
    )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    hl = _initial_hl(inputs)
    state.solver.add(hl >= 0xA000, hl <= 0xBFFE)
    state.memory.store(hl, inputs["first"])
    state.memory.store(hl + 1, inputs["second"])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    end = collect_returns(project, state, GB_RETURN)[0]
    return Endpoint(
        **assembly_registers(end),
        first=end.memory.load(hl, 1),
        second=end.memory.load(hl + 1, 1),
        constraints=tuple(end.solver.constraints),
    )


def _native_endpoint(inputs: dict[str, claripy.ast.BV]) -> Endpoint:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_empty_sram_box")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, inputs)
    hl = _initial_hl(inputs)
    state.solver.add(hl >= 0xA000, hl <= 0xBFFE)
    native_hl = claripy.ZeroExt(48, hl) + NATIVE_MEMORY
    state.memory.store(native_hl, inputs["first"])
    state.memory.store(native_hl + 1, inputs["second"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    end = manager.deadended[0]
    return Endpoint(
        **native_registers(end, NATIVE_STATE),
        first=end.memory.load(native_hl, 1),
        second=end.memory.load(native_hl + 1, 1),
        constraints=tuple(end.solver.constraints),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_empty_sram_box_symbolic_equivalence() -> None:
    inputs = symbolic_registers("empty_sram_box")
    inputs["first"] = claripy.BVS("empty_sram_box_first", 8)
    inputs["second"] = claripy.BVS("empty_sram_box_second", 8)
    assert_pathwise_equivalent(
        [_assembly_endpoint(inputs)],
        [_native_endpoint(inputs)],
        (*REGISTERS, "first", "second"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_empty_sram_box_machine_code_is_accounted_for() -> None:
    location = symbol_location(SYMBOLS, "EmptySRAMBox")
    assert linked_bytes(ROM, location, 5) == bytes.fromhex("af223d77c9")
