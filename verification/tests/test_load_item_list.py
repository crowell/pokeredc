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
from verification.harness.sm83_shims import Sm83CpImmediate, Sm83StoreAImmediate


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
LOOP = 0xEFFE
RETURN = 0xEFFF


class Boundary(angr.SimProcedure):
    def __init__(self, destination: int):
        super().__init__()
        self.destination = destination

    def run(self):
        self.state.globals["update"] = self.state.memory.load(self.destination, 1)
        self.jump(LOOP)


class LoadFetched(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__()
        self.next_address = next_address

    def run(self):
        self.state.regs.a = self.state.globals["fetched"]
        self.state.regs.hl = self.state.regs.hl + 1
        self.jump(self.next_address)


class StoreWritten(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__()
        self.next_address = next_address

    def run(self):
        self.state.globals["written"] = self.state.regs.a
        self.jump(self.next_address)


class LoopOnce(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__()
        self.next_address = next_address

    def run(self):
        if self.state.globals.get("entered", False):
            self.jump(LOOP)
        else:
            self.state.globals["entered"] = True
            self.state.regs.a = self.state.globals["fetched"]
            self.state.regs.hl = self.state.regs.hl + 1
            self.jump(self.next_address)


class ReturnBoundary(angr.SimProcedure):
    def run(self):
        self.jump(RETURN)


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
    continuation: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _project() -> tuple[angr.Project, int]:
    location = symbol_location(SYMBOLS, "LoadItemList")
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False, rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0, "entry_point": location.address},
    )
    return project, location.address


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    inputs = symbolic_registers(prefix)
    for name in ("update", "pointer0", "pointer1", "fetched", "written"):
        inputs[name] = claripy.BVS(prefix + "_" + name, 8)
    return inputs


def _begin_assembly(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, address = _project()
    update = symbol_location(SYMBOLS, "wUpdateSpritesEnabled").address
    pointer = symbol_location(SYMBOLS, "wItemListPointer").address
    project.hook(address + 2, Sm83StoreAImmediate(update, address + 5), length=3)
    project.hook(address + 6, Sm83StoreAImmediate(pointer, address + 9), length=3)
    project.hook(address + 10, Sm83StoreAImmediate(pointer + 1, address + 13), length=3)
    project.hook(address + 16, Boundary(update), length=1)
    state = project.factory.blank_state(addr=address)
    set_assembly_registers(state, inputs)
    state.memory.store(update, inputs["update"])
    state.memory.store(pointer, claripy.Concat(inputs["pointer0"], inputs["pointer1"]))
    manager = project.factory.simulation_manager(state)
    manager.explore(find=LOOP)
    return [
        Endpoint(
            **assembly_registers(end),
            memory=claripy.Concat(end.memory.load(update, 1), end.memory.load(pointer, 2), inputs["written"]),
            continuation=claripy.BVV(1, 8),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _begin_native(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_load_item_list_begin")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, claripy.Concat(inputs["update"], inputs["pointer0"], inputs["pointer1"], inputs["fetched"], inputs["written"]))
    manager = project.factory.simulation_manager(state)
    manager.run()
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=claripy.Concat(end.memory.load(NATIVE_STATE + 8, 3), end.memory.load(NATIVE_STATE + 12, 1)),
            continuation=claripy.BVV(1, 8),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


def _step_assembly(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, address = _project()
    loop = address + 16
    project.hook(loop, LoopOnce(loop + 1), length=1)
    project.hook(loop + 1, StoreWritten(loop + 2), length=1)
    project.hook(loop + 3, Sm83CpImmediate(0xff, loop + 5), length=2)
    project.hook(loop + 7, ReturnBoundary(), length=1)
    state = project.factory.blank_state(addr=loop)
    set_assembly_registers(state, inputs)
    state.globals["fetched"] = inputs["fetched"]
    state.globals["written"] = inputs["written"]
    manager = project.factory.simulation_manager(state)
    manager.stashes["found"] = []
    while manager.active:
        manager.move(from_stash="active", to_stash="found", filter_func=lambda end: end.addr in {LOOP, RETURN})
        if manager.active:
            manager.step()
    return [
        Endpoint(
            **assembly_registers(end),
            memory=claripy.Concat(inputs["update"], inputs["pointer0"], inputs["pointer1"], end.globals["written"]),
            continuation=claripy.BVV(1 if end.addr == LOOP else 0, 8),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _step_native(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_load_item_list_step")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, claripy.Concat(inputs["update"], inputs["pointer0"], inputs["pointer1"], inputs["fetched"], inputs["written"]))
    manager = project.factory.simulation_manager(state)
    manager.run()
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=claripy.Concat(end.memory.load(NATIVE_STATE + 8, 3), end.memory.load(NATIVE_STATE + 12, 1)),
            continuation=claripy.If(end.regs.rax[7:0] == 0, claripy.BVV(1, 8), claripy.BVV(0, 8)),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
def test_begin_equivalence() -> None:
    inputs = _inputs("load_item_begin")
    assert_pathwise_equivalent(_begin_assembly(inputs), _begin_native(inputs), (*REGISTERS, "memory", "continuation"))


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
def test_step_inductive_equivalence() -> None:
    inputs = _inputs("load_item_step")
    assert_pathwise_equivalent(_step_assembly(inputs), _step_native(inputs), (*REGISTERS, "memory", "continuation"))


def test_exact_body() -> None:
    location = symbol_location(SYMBOLS, "LoadItemList")
    assert linked_bytes(ROM, location, 24) == bytes.fromhex("3e01eacbcf7cea28d17dea29d1117bcf2a1213feff20f9c9")
