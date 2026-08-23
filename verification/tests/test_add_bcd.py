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
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
ADD = 0xEFFD
FILL = 0xEFFE
RETURN = 0xEFFF
EXPECTED = bytes.fromhex("a7411a8e27121b2b0d20f730083e991312130520fbc9")


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
    written: claripy.ast.BV
    continuation: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class AndA(angr.SimProcedure):
    def __init__(self, target: int):
        super().__init__()
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.f = claripy.BVV(0x10, 8) | claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x40, 8),
            claripy.BVV(0, 8),
        )
        self.jump(self.target)


class LoadLeft(angr.SimProcedure):
    def __init__(self, target: int):
        super().__init__()
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        if self.state.globals.get("entered", False):
            self.jump(ADD)
            return
        self.state.globals["entered"] = True
        self.state.regs.a = self.state.globals["left"]
        self.jump(self.target)


class AdcRight(angr.SimProcedure):
    def __init__(self, target: int):
        super().__init__()
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        left = self.state.regs.a
        right = self.state.globals["right"]
        carry = self.state.regs.f[0]
        wide = (
            claripy.ZeroExt(1, left)
            + claripy.ZeroExt(1, right)
            + claripy.ZeroExt(8, carry)
        )
        result = wide[7:0]
        flags = claripy.If(
            result == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)
        )
        flags |= claripy.If(
            claripy.ZeroExt(1, left & 0x0F)
            + claripy.ZeroExt(1, right & 0x0F)
            + claripy.ZeroExt(8, carry)
            > 0x0F,
            claripy.BVV(0x10, 8),
            claripy.BVV(0, 8),
        )
        flags |= claripy.ZeroExt(7, wide[8])
        self.state.regs.a = result
        self.state.regs.f = flags
        self.jump(self.target)


class DaaAdd(angr.SimProcedure):
    def __init__(self, target: int):
        super().__init__()
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        value = self.state.regs.a
        high = ((self.state.regs.f & 1) != 0) | value.UGT(0x99)
        low = ((self.state.regs.f & 0x10) != 0) | ((value & 0x0F).UGT(9))
        correction = claripy.If(
            high, claripy.BVV(0x60, 8), claripy.BVV(0, 8)
        ) | claripy.If(low, claripy.BVV(6, 8), claripy.BVV(0, 8))
        self.state.regs.a = value + correction
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x40, 8),
            claripy.BVV(0, 8),
        ) | claripy.If(high, claripy.BVV(1, 8), claripy.BVV(0, 8))
        self.jump(self.target)


class Store(angr.SimProcedure):
    def __init__(self, target: int, fill: bool = False):
        super().__init__()
        self.target = target
        self.fill = fill

    def run(self) -> None:  # type: ignore[override]
        if self.fill and self.state.globals.get("fill_entered", False):
            self.jump(FILL)
            return
        if self.fill:
            self.state.globals["fill_entered"] = True
        self.state.globals["written"] = self.state.regs.a
        self.jump(self.target)


class StepBranch(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        more_condition = self.state.regs.c != 0
        fill_condition = (self.state.regs.c == 0) & (
            (self.state.regs.f & 1) != 0
        )
        return_condition = (self.state.regs.c == 0) & (
            (self.state.regs.f & 1) == 0
        )
        more = self.state.copy()
        fill = self.state.copy()
        done = self.state.copy()
        more.add_constraints(more_condition)
        fill.add_constraints(fill_condition)
        done.add_constraints(return_condition)
        fill.regs.a = 0x99
        fill.regs.de = fill.regs.de + 1
        self.successors.add_successor(more, ADD, claripy.BoolV(True), "Ijk_Boring")
        self.successors.add_successor(fill, FILL, claripy.BoolV(True), "Ijk_Boring")
        self.successors.add_successor(done, RETURN, claripy.BoolV(True), "Ijk_Boring")


class FillBranch(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        more_condition = self.state.regs.b != 0
        more = self.state.copy()
        done = self.state.copy()
        more.add_constraints(more_condition)
        done.add_constraints(claripy.Not(more_condition))
        self.successors.add_successor(more, FILL, claripy.BoolV(True), "Ijk_Boring")
        self.successors.add_successor(done, RETURN, claripy.BoolV(True), "Ijk_Boring")


class Boundary(angr.SimProcedure):
    def __init__(self, target: int):
        super().__init__()
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.jump(self.target)


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for name in ("left", "right", "written"):
        values[name] = claripy.BVS(f"{prefix}_{name}", 8)
    return values


def _project() -> tuple[angr.Project, int]:
    location = symbol_location(SYMBOLS, "AddBCD")
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
    return project, location.address


def _setup(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    set_assembly_registers(state, values)
    state.globals["left"] = values["left"]
    state.globals["right"] = values["right"]
    state.globals["written"] = values["written"]


def _collect(manager: angr.SimulationManager) -> list[angr.SimState]:
    manager.stashes["finished"] = []
    while manager.active:
        manager.move(
            from_stash="active",
            to_stash="finished",
            filter_func=lambda state: state.addr in {ADD, FILL, RETURN},
        )
        if manager.active:
            manager.step()
    assert not manager.errored
    return manager.finished


def _endpoint(state: angr.SimState) -> Endpoint:
    return Endpoint(
        **assembly_registers(state),
        written=state.globals["written"],
        continuation=claripy.BVV({ADD: 1, FILL: 2, RETURN: 0}[state.addr], 8),
        constraints=tuple(state.solver.constraints),
    )


def _assembly_begin(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, base = _project()
    project.hook(base, AndA(base + 1), length=1)
    project.hook(base + 2, Boundary(ADD), length=1)
    state = project.factory.blank_state(addr=base)
    _setup(state, values)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=ADD)
    assert not manager.errored
    return [_endpoint(end) for end in manager.found]


def _assembly_step(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, base = _project()
    project.hook(base + 2, LoadLeft(base + 3), length=1)
    project.hook(base + 3, AdcRight(base + 4), length=1)
    project.hook(base + 4, DaaAdd(base + 5), length=1)
    project.hook(base + 5, Store(base + 6), length=1)
    project.hook(base + 8, Sm83DecRegister("c", base + 9), length=1)
    project.hook(base + 9, StepBranch(), length=4)
    state = project.factory.blank_state(addr=base + 2)
    _setup(state, values)
    return [
        _endpoint(end)
        for end in _collect(project.factory.simulation_manager(state))
    ]


def _assembly_fill(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, base = _project()
    project.hook(base + 16, Store(base + 17, fill=True), length=1)
    project.hook(base + 18, Sm83DecRegister("b", base + 19), length=1)
    project.hook(base + 19, FillBranch(), length=2)
    state = project.factory.blank_state(addr=base + 16)
    _setup(state, values)
    return [
        _endpoint(end)
        for end in _collect(project.factory.simulation_manager(state))
    ]


def _native(
    symbol: str, values: dict[str, claripy.ast.BV], stage: str
) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(
        NATIVE_STATE + 8,
        claripy.Concat(values["left"], values["right"], values["written"]),
    )
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    endpoints = []
    for end in manager.deadended:
        if stage == "begin":
            continuation = claripy.BVV(1, 8)
        elif stage == "step":
            continuation = end.regs.rax[7:0]
        else:
            continuation = claripy.If(
                end.regs.rax[7:0] == 0,
                claripy.BVV(2, 8),
                claripy.BVV(0, 8),
            )
        endpoints.append(
            Endpoint(
                **native_registers(end, NATIVE_STATE),
                written=end.memory.load(NATIVE_STATE + 10, 1),
                continuation=continuation,
                constraints=tuple(end.solver.constraints),
            )
        )
    return endpoints


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    "assembly,symbol,stage",
    (
        (_assembly_begin, "port_add_bcd_begin", "begin"),
        (_assembly_step, "port_add_bcd_step", "step"),
        (_assembly_fill, "port_add_bcd_fill_step", "fill"),
    ),
)
def test_add_bcd_pathwise_equivalence(assembly, symbol: str, stage: str) -> None:
    location = symbol_location(SYMBOLS, "AddBCD")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    values = _inputs(symbol)
    assert_pathwise_equivalent(
        assembly(values),
        _native(symbol, values, stage),
        (*REGISTERS, "written", "continuation"),
    )
