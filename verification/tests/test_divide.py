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
    Sm83CpImmediate,
    Sm83DecRegister,
    Sm83IncRegister,
    Sm83LoadAHighImmediate,
    Sm83RlRegister,
    Sm83RrRegister,
    Sm83SbcRegister,
    Sm83SlaRegister,
    Sm83SrlRegister,
    Sm83StoreAHighImmediate,
    Sm83SubRegister,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
STACK = 0xD000
RETURN = 0xFFFF
H_DIVIDEND = 0xFF95
H_DIVISOR = 0xFF99
H_BUFFER = 0xFF9A
EXPECTED = bytes.fromhex(
    "afe09ae09be09ce09de09e3e095ff09a4ff0969157f0994ff09599380ce0957a"
    "e096f09e3ce09e18e578fe012845f09ecb27e09ef09dcb17e09df09ccb17e09c"
    "f09bcb17e09b1d20163e085ff09ae099afe09af096e095f097e096f098e0977b"
    "fe01200105f099cb3fe099f09acb1fe09a189bf096e099f09ee098f09de097f0"
    "9ce096f09be095c9"
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
    dividend: claripy.ast.BV
    divisor: claripy.ast.BV
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
    values["dividend"] = claripy.BVS(f"{prefix}_dividend", 32)
    values["divisor"] = claripy.BVS(f"{prefix}_divisor", 8)
    values["buffer"] = claripy.BVS(f"{prefix}_buffer", 40)
    return values


def _assembly_endpoint(state: angr.SimState, done: int) -> Endpoint:
    return Endpoint(
        **assembly_registers(state),
        dividend=state.memory.load(H_DIVIDEND, 4),
        divisor=state.memory.load(H_DIVISOR, 1),
        buffer=state.memory.load(H_BUFFER, 5),
        done=claripy.BVV(done, 8),
        constraints=tuple(state.solver.constraints),
    )


def _native_endpoint(state: angr.SimState, done: claripy.ast.BV) -> Endpoint:
    return Endpoint(
        **native_registers(state, NATIVE_STATE),
        dividend=state.memory.load(NATIVE_STATE + 8, 4),
        divisor=state.memory.load(NATIVE_STATE + 12, 1),
        buffer=state.memory.load(NATIVE_STATE + 13, 5),
        done=done,
        constraints=tuple(state.solver.constraints),
    )


def _setup_assembly(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    set_assembly_registers(state, values)
    state.memory.store(H_DIVIDEND, values["dividend"])
    state.memory.store(H_DIVISOR, values["divisor"])
    state.memory.store(H_BUFFER, values["buffer"])


def _setup_native(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, values["dividend"])
    state.memory.store(NATIVE_STATE + 12, values["divisor"])
    state.memory.store(NATIVE_STATE + 13, values["buffer"])


@cache
def _assembly_project() -> tuple[angr.Project, int]:
    location = symbol_location(SYMS, "_Divide")
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
    project.hook(base, Sm83XorA(base + 1), length=1)
    project.hook(base + 80, Sm83XorA(base + 81), length=1)
    for offset, high in (
        (1, 0x9A),
        (3, 0x9B),
        (5, 0x9C),
        (7, 0x9D),
        (9, 0x9E),
        (29, 0x95),
        (32, 0x96),
        (37, 0x9E),
        (50, 0x9E),
        (56, 0x9D),
        (62, 0x9C),
        (68, 0x9B),
        (78, 0x99),
        (81, 0x9A),
        (85, 0x95),
        (89, 0x96),
        (93, 0x97),
        (105, 0x99),
        (111, 0x9A),
        (117, 0x99),
        (121, 0x98),
        (125, 0x97),
        (129, 0x96),
        (133, 0x95),
    ):
        project.hook(
            base + offset,
            Sm83StoreAHighImmediate(high, base + offset + 2),
            length=2,
        )
    for offset, high in (
        (14, 0x9A),
        (17, 0x96),
        (21, 0x99),
        (24, 0x95),
        (34, 0x9E),
        (46, 0x9E),
        (52, 0x9D),
        (58, 0x9C),
        (64, 0x9B),
        (76, 0x9A),
        (83, 0x96),
        (87, 0x97),
        (91, 0x98),
        (101, 0x99),
        (107, 0x9A),
        (115, 0x96),
        (119, 0x9E),
        (123, 0x9D),
        (127, 0x9C),
        (131, 0x9B),
    ):
        project.hook(
            base + offset,
            Sm83LoadAHighImmediate(high, base + offset + 2),
            length=2,
        )
    project.hook(base + 19, Sm83SubRegister("c", base + 20), length=1)
    project.hook(base + 26, Sm83SbcRegister("c", base + 27), length=1)
    project.hook(base + 36, Sm83IncRegister("a", base + 37), length=1)
    project.hook(base + 42, Sm83CpImmediate(1, base + 44), length=2)
    project.hook(base + 48, Sm83SlaRegister("a", base + 50), length=2)
    for offset in (54, 60, 66):
        project.hook(base + offset, Sm83RlRegister("a", base + offset + 2), length=2)
    project.hook(base + 70, Sm83DecRegister("e", base + 71), length=1)
    project.hook(base + 96, Sm83CpImmediate(1, base + 98), length=2)
    project.hook(base + 100, Sm83DecRegister("b", base + 101), length=1)
    project.hook(base + 103, Sm83SrlRegister("a", base + 105), length=2)
    project.hook(base + 109, Sm83RrRegister("a", base + 111), length=2)
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
    function = project.loader.find_symbol("port_divide_begin")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    _setup_native(state, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [_native_endpoint(manager.deadended[0], claripy.BVV(0, 8))]


def _collect_recurrence(
    manager: angr.SimulationManager, boundaries: tuple[int, int]
) -> list[angr.SimState]:
    manager.step()
    manager.stashes["completed"] = []
    while manager.active:
        manager.move(
            from_stash="active",
            to_stash="completed",
            filter_func=lambda candidate: candidate.addr in boundaries,
        )
        if manager.active:
            manager.step()
    assert not manager.errored
    return manager.completed


def assembly_subtract(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, base = _assembly_project()
    loop = base + 14
    shift = base + 41
    state = project.factory.blank_state(addr=loop)
    _setup_assembly(state, values)
    ends = _collect_recurrence(project.factory.simulation_manager(state), (loop, shift))
    assert len(ends) == 2
    return [_assembly_endpoint(end, 1 if end.addr == loop else 0) for end in ends]


def native_subtract(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = _native_project()
    function = project.loader.find_symbol("port_divide_subtract_step")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    _setup_native(state, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 2
    return [_native_endpoint(end, end.regs.rax[7:0]) for end in manager.deadended]


def assembly_shift(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, base = _assembly_project()
    loop = base + 14
    finish = base + 115
    state = project.factory.blank_state(addr=base + 41)
    _setup_assembly(state, values)
    ends = _collect_recurrence(project.factory.simulation_manager(state), (loop, finish))
    assert len(ends) == 4
    return [_assembly_endpoint(end, 1 if end.addr == finish else 0) for end in ends]


def native_shift(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = _native_project()
    function = project.loader.find_symbol("port_divide_shift_step")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    _setup_native(state, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 4
    return [_native_endpoint(end, end.regs.rax[7:0]) for end in manager.deadended]


def assembly_finish(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, base = _assembly_project()
    state = project.factory.blank_state(addr=base + 115)
    _setup_assembly(state, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    ends = collect_returns(project, state, RETURN)
    assert len(ends) == 1 and ends[0].solver.is_true(ends[0].regs.sp == STACK + 2)
    return [_assembly_endpoint(ends[0], 0)]


def native_finish(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = _native_project()
    function = project.loader.find_symbol("port_divide_finish")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    _setup_native(state, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [_native_endpoint(manager.deadended[0], claripy.BVV(0, 8))]


OBSERVABLES = (*REGISTERS, "dividend", "divisor", "buffer", "done")


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
def test_divide_pathwise_equivalence() -> None:
    begin_values = inputs("divide_begin")
    assert_pathwise_equivalent(
        assembly_begin(begin_values), native_begin(begin_values), OBSERVABLES
    )

    subtract_values = inputs("divide_subtract")
    assembly_subtracts = assembly_subtract(subtract_values)
    native_subtracts = native_subtract(subtract_values)
    _assert_complete_domain(assembly_subtracts)
    _assert_complete_domain(native_subtracts)
    assert_pathwise_equivalent(
        assembly_subtracts, native_subtracts, OBSERVABLES
    )

    shift_values = inputs("divide_shift")
    assembly_shifts = assembly_shift(shift_values)
    native_shifts = native_shift(shift_values)
    _assert_complete_domain(assembly_shifts)
    _assert_complete_domain(native_shifts)
    assert_pathwise_equivalent(assembly_shifts, native_shifts, OBSERVABLES)

    finish_values = inputs("divide_finish")
    assert_pathwise_equivalent(
        assembly_finish(finish_values), native_finish(finish_values), OBSERVABLES
    )
