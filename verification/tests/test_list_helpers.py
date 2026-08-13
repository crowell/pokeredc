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
from verification.harness.sm83_shims import Sm83DecRegister


ROOT = Path(__file__).resolve().parents[2]
VERIFY = ROOT / "verification"
NATIVE_ELF = VERIFY / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
BOUNDARY = 0xEFFF
NATIVE_STATE = 0x100000


class ReturnBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(BOUNDARY)


class StoreFirstBoundary(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["first_output"] = self.state.regs.a
        self.state.regs.hl = self.state.regs.hl + 1
        self.jump(self._next_address)


class StoreTerminatorBoundary(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["terminator_output"] = self.state.regs.a
        self.jump(self._next_address)


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
    terminator: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _assembly(inputs: dict[str, claripy.ast.BV]) -> Endpoint:
    location = symbol_location(SYMBOLS, "InitializeEmptyList")
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
        StoreFirstBoundary(location.address + 2),
        length=1,
    )
    project.hook(
        location.address + 2,
        Sm83DecRegister("a", location.address + 3),
        length=1,
    )
    project.hook(
        location.address + 3,
        StoreTerminatorBoundary(location.address + 4),
        length=1,
    )
    project.hook(location.address + 4, ReturnBoundary(), length=1)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=BOUNDARY)
    assert not manager.errored
    assert len(manager.found) == 1
    end = manager.found[0]
    assert end.addr == BOUNDARY
    return Endpoint(
        **assembly_registers(end),
        first=end.globals["first_output"],
        terminator=end.globals["terminator_output"],
        constraints=tuple(end.solver.constraints),
    )


def _native(inputs: dict[str, claripy.ast.BV]) -> Endpoint:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_initialize_empty_list")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["first"])
    state.memory.store(NATIVE_STATE + 9, inputs["terminator"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    end = manager.deadended[0]
    return Endpoint(
        **native_registers(end, NATIVE_STATE),
        first=end.memory.load(NATIVE_STATE + 8, 1),
        terminator=end.memory.load(NATIVE_STATE + 9, 1),
        constraints=tuple(end.solver.constraints),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_initialize_empty_list_symbolic_equivalence() -> None:
    inputs = symbolic_registers("initialize_empty_list")
    inputs["first"] = claripy.BVS("initialize_empty_list_first", 8)
    inputs["terminator"] = claripy.BVS("initialize_empty_list_terminator", 8)
    assert_pathwise_equivalent(
        [_assembly(inputs)],
        [_native(inputs)],
        (*REGISTERS, "first", "terminator"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_initialize_empty_list_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "InitializeEmptyList")
    assert linked_bytes(ROM, location, 5) == bytes.fromhex("af223d77c9")
