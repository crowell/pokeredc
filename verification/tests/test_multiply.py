from __future__ import annotations

from dataclasses import dataclass
from functools import cache
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
from verification.harness.rom import (
    collect_returns,
    linked_bytes,
    rom_window,
    symbol_location,
)
from verification.harness.sm83_shims import (
    Sm83AdcRegister,
    Sm83AddRegister,
    Sm83DecRegister,
    Sm83LoadAHighImmediate,
    Sm83RlRegister,
    Sm83SlaRegister,
    Sm83SrlRegister,
    Sm83StoreAHighImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
STACK = 0xD000
RETURN = 0xFFFF
H_PRODUCT = 0xFF95
H_MULTIPLIER = 0xFF99
H_BUFFER = 0xFF9B
EXPECTED = bytes.fromhex(
    "3e0847afe095e09be09ce09de09ef099cb3fe0993020f09e4ff09881e09ef09d"
    "4ff09789e09df09c4ff09689e09cf09b4ff09589e09b05281af098cb27e098f0"
    "97cb17e097f096cb17e096f095cb17e09518bbf09ee098f09de097f09ce096f0"
    "9be095c9"
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
    product: claripy.ast.BV
    multiplier: claripy.ast.BV
    buffer: claripy.ast.BV
    done: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class Sm83XorA(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x40, 8)
        self.jump(self._next_address)


def inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["product"] = claripy.BVS(f"{prefix}_product", 32)
    values["multiplier"] = claripy.BVS(f"{prefix}_multiplier", 8)
    values["buffer"] = claripy.BVS(f"{prefix}_buffer", 32)
    return values


def _assembly_endpoint(state: angr.SimState, done: int) -> Endpoint:
    return Endpoint(
        **assembly_registers(state),
        product=state.memory.load(H_PRODUCT, 4),
        multiplier=state.memory.load(H_MULTIPLIER, 1),
        buffer=state.memory.load(H_BUFFER, 4),
        done=claripy.BVV(done, 8),
        constraints=tuple(state.solver.constraints),
    )


def _native_endpoint(state: angr.SimState, done: claripy.ast.BV) -> Endpoint:
    return Endpoint(
        **native_registers(state, NATIVE_STATE),
        product=state.memory.load(NATIVE_STATE + 8, 4),
        multiplier=state.memory.load(NATIVE_STATE + 12, 1),
        buffer=state.memory.load(NATIVE_STATE + 13, 4),
        done=done,
        constraints=tuple(state.solver.constraints),
    )


def _setup_assembly(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    set_assembly_registers(state, values)
    state.memory.store(H_PRODUCT, values["product"])
    state.memory.store(H_MULTIPLIER, values["multiplier"])
    state.memory.store(H_BUFFER, values["buffer"])


def _setup_native(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, values["product"])
    state.memory.store(NATIVE_STATE + 12, values["multiplier"])
    state.memory.store(NATIVE_STATE + 13, values["buffer"])


@cache
def _assembly_project() -> tuple[angr.Project, int]:
    location = symbol_location(SYMS, "_Multiply")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
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
    base = location.address
    project.hook(base + 3, Sm83XorA(base + 4), length=1)
    for offset, high in (
        (4, 0x95),
        (6, 0x9B),
        (8, 0x9C),
        (10, 0x9D),
        (12, 0x9E),
        (18, 0x99),
        (28, 0x9E),
        (36, 0x9D),
        (44, 0x9C),
        (52, 0x9B),
        (61, 0x98),
        (67, 0x97),
        (73, 0x96),
        (79, 0x95),
        (85, 0x98),
        (89, 0x97),
        (93, 0x96),
        (97, 0x95),
    ):
        project.hook(
            base + offset,
            Sm83StoreAHighImmediate(high, base + offset + 2),
            length=2,
        )
    for offset, high in (
        (14, 0x99),
        (22, 0x9E),
        (25, 0x98),
        (30, 0x9D),
        (33, 0x97),
        (38, 0x9C),
        (41, 0x96),
        (46, 0x9B),
        (49, 0x95),
        (57, 0x98),
        (63, 0x97),
        (69, 0x96),
        (75, 0x95),
        (83, 0x9E),
        (87, 0x9D),
        (91, 0x9C),
        (95, 0x9B),
    ):
        project.hook(
            base + offset,
            Sm83LoadAHighImmediate(high, base + offset + 2),
            length=2,
        )
    project.hook(base + 16, Sm83SrlRegister("a", base + 18), length=2)
    project.hook(base + 27, Sm83AddRegister("c", base + 28), length=1)
    for offset in (35, 43, 51):
        project.hook(base + offset, Sm83AdcRegister("c", base + offset + 1), length=1)
    project.hook(base + 54, Sm83DecRegister("b", base + 55), length=1)
    project.hook(base + 59, Sm83SlaRegister("a", base + 61), length=2)
    for offset in (65, 71, 77):
        project.hook(base + offset, Sm83RlRegister("a", base + offset + 2), length=2)
    return project, base


@cache
def _native_project() -> angr.Project:
    return angr.Project(ELF, auto_load_libs=False)


def assembly_begin(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, base = _assembly_project()
    state = project.factory.blank_state(addr=base)
    _setup_assembly(state, values)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=lambda end: end.addr == base + 14)
    assert not manager.errored and len(manager.found) == 1
    return [_assembly_endpoint(manager.found[0], 0)]


def native_begin(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = _native_project()
    function = project.loader.find_symbol("port_multiply_begin")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    _setup_native(state, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [_native_endpoint(manager.deadended[0], claripy.BVV(0, 8))]


def assembly_step(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, base = _assembly_project()
    loop = base + 14
    finish = base + 83
    state = project.factory.blank_state(addr=loop)
    _setup_assembly(state, values)
    manager = project.factory.simulation_manager(state)
    manager.step()
    manager.stashes["completed"] = []
    while manager.active:
        manager.move(
            from_stash="active",
            to_stash="completed",
            filter_func=lambda candidate: candidate.addr in (loop, finish),
        )
        if manager.active:
            manager.step()
    assert not manager.errored and len(manager.completed) == 4
    return [
        _assembly_endpoint(end, 1 if end.addr == finish else 0)
        for end in manager.completed
    ]


def native_step(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = _native_project()
    function = project.loader.find_symbol("port_multiply_step")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    _setup_native(state, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 4
    return [
        _native_endpoint(end, end.regs.rax[7:0]) for end in manager.deadended
    ]


def assembly_finish(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, base = _assembly_project()
    state = project.factory.blank_state(addr=base + 83)
    _setup_assembly(state, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    ends = collect_returns(project, state, RETURN)
    assert len(ends) == 1 and ends[0].solver.is_true(ends[0].regs.sp == STACK + 2)
    return [_assembly_endpoint(ends[0], 0)]


def native_finish(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = _native_project()
    function = project.loader.find_symbol("port_multiply_finish")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    _setup_native(state, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [_native_endpoint(manager.deadended[0], claripy.BVV(0, 8))]


OBSERVABLES = (*REGISTERS, "product", "multiplier", "buffer", "done")


def _assert_complete_domain(endpoints: list[Endpoint]) -> None:
    solver = claripy.Solver()
    solver.add(
        claripy.Not(
            claripy.Or(
                *(claripy.And(*endpoint.constraints) for endpoint in endpoints)
            )
        )
    )
    assert not solver.satisfiable()


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(), reason="build")
def test_multiply_pathwise_equivalence() -> None:
    begin_values = inputs("multiply_begin")
    assert_pathwise_equivalent(
        assembly_begin(begin_values), native_begin(begin_values), OBSERVABLES
    )
    step_values = inputs("multiply_step")
    assembly_steps = assembly_step(step_values)
    native_steps = native_step(step_values)
    _assert_complete_domain(assembly_steps)
    _assert_complete_domain(native_steps)
    assert_pathwise_equivalent(
        assembly_steps, native_steps, OBSERVABLES
    )
    finish_values = inputs("multiply_finish")
    assert_pathwise_equivalent(
        assembly_finish(finish_values), native_finish(finish_values), OBSERVABLES
    )
