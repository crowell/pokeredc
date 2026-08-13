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
from verification.harness.sm83_shims import Sm83SubAtHl


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
BOUNDARY = 0xEFFF


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
    result: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class SaveHl(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["saved_h"] = self.state.regs.h
        self.state.globals["saved_l"] = self.state.regs.l
        self.jump(self._next_address)


class XorA(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = 0
        self.state.regs.f = 0x40
        self.jump(self._next_address)


class StoreQuotientHld(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["quotient"] = self.state.regs.a
        self.state.regs.hl = self.state.regs.hl - 1
        self.jump(self._next_address)


class LoadHld(angr.SimProcedure):
    def __init__(self, key: str, next_address: int) -> None:
        super().__init__()
        self._key = key
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals[self._key]
        self.state.regs.hl = self.state.regs.hl - 1
        self.jump(self._next_address)


class AndA(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.f = 0x10 | claripy.If(
            self.state.regs.a == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)
        )
        self.jump(self._next_address)


class IncQuotient(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        old = self.state.globals["quotient"]
        result = old + 1
        self.state.globals["quotient"] = result
        self.state.regs.f = (self.state.regs.f & 1) | claripy.If(
            result == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)
        ) | claripy.If(
            (old & 0x0F) == 0x0F, claripy.BVV(0x10, 8), claripy.BVV(0, 8)
        )
        self.jump(self._next_address)


class RestoreHl(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = self.state.globals["saved_h"]
        self.state.regs.l = self.state.globals["saved_l"]
        self.jump(BOUNDARY)


class Boundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(BOUNDARY)


def project() -> tuple[angr.Project, int]:
    location = symbol_location(SYMBOLS, "DivideBytes")
    loaded = angr.Project(
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
    return loaded, location.address


def inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for name in ("dividend", "divisor", "quotient", "saved_h", "saved_l"):
        values[name] = claripy.BVS(f"{prefix}_{name}", 8)
    return values


def memory(state: angr.SimState) -> claripy.ast.BV:
    return claripy.Concat(
        state.globals["dividend"],
        state.globals["divisor"],
        state.globals["quotient"],
        state.globals["saved_h"],
        state.globals["saved_l"],
    )


def endpoint(
    state: angr.SimState,
    result: int,
    constraints: tuple[claripy.ast.Bool, ...] = (),
) -> Endpoint:
    return Endpoint(
        **assembly_registers(state),
        memory=memory(state),
        result=claripy.BVV(result, 8),
        constraints=tuple(state.solver.constraints) + constraints,
    )


def initial_state(
    loaded: angr.Project, address: int, values: dict[str, claripy.ast.BV]
) -> angr.SimState:
    state = loaded.factory.blank_state(addr=address)
    set_assembly_registers(state, values)
    for name in ("dividend", "divisor", "quotient", "saved_h", "saved_l"):
        state.globals[name] = values[name]
    return state


def assembly_begin(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    loaded, base = project()
    loaded.hook(base, SaveHl(base + 1), length=1)
    loaded.hook(base + 4, XorA(base + 5), length=1)
    loaded.hook(base + 5, StoreQuotientHld(base + 6), length=1)
    loaded.hook(base + 6, LoadHld("divisor", base + 7), length=1)
    loaded.hook(base + 7, AndA(BOUNDARY), length=1)
    state = initial_state(loaded, base, values)
    manager = loaded.factory.simulation_manager(state)
    manager.explore(find=BOUNDARY)
    assert not manager.errored and len(manager.found) == 1
    common = manager.found[0]
    zero = endpoint(common, 1, (common.regs.a == 0,))
    nonzero_state = common.copy()
    nonzero_state.regs.a = nonzero_state.globals["dividend"]
    nonzero_state.regs.hl = nonzero_state.regs.hl + 1
    nonzero = endpoint(nonzero_state, 0, (common.regs.a != 0,))
    return [zero, nonzero]


def assembly_step(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    loaded, base = project()
    start = base + 11
    loaded.hook(start, Sm83SubAtHl(BOUNDARY), length=1)
    state = initial_state(loaded, start, values)
    state.memory.store(state.regs.hl, values["divisor"])
    manager = loaded.factory.simulation_manager(state)
    manager.explore(find=BOUNDARY)
    assert not manager.errored and len(manager.found) == 1
    after_sub = manager.found[0]
    done = endpoint(after_sub, 1, ((after_sub.regs.f & 1) != 0,))

    continuation = after_sub.copy()
    continuation.add_constraints((continuation.regs.f & 1) == 0)
    continuation.regs.pc = base + 14
    continuation_project, _ = project()
    continuation_project.hook(
        base + 15, IncQuotient(base + 16), length=1
    )
    continuation_project.hook(base + 17, Boundary(), length=2)
    continuation_manager = continuation_project.factory.simulation_manager(
        continuation
    )
    continuation_manager.explore(find=BOUNDARY)
    assert not continuation_manager.errored
    assert len(continuation_manager.found) == 1
    again = endpoint(continuation_manager.found[0], 0)
    return [done, again]


def assembly_finish(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    loaded, base = project()
    loaded.hook(base + 19, RestoreHl(), length=1)
    state = initial_state(loaded, base + 19, values)
    manager = loaded.factory.simulation_manager(state)
    manager.explore(find=BOUNDARY)
    assert not manager.errored and len(manager.found) == 1
    return [endpoint(manager.found[0], 0)]


def native(symbol: str, values: dict[str, claripy.ast.BV], returns: bool) -> list[Endpoint]:
    loaded = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = loaded.loader.find_symbol(symbol)
    assert function is not None
    state = loaded.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(
        NATIVE_STATE + 8,
        claripy.Concat(
            values["dividend"],
            values["divisor"],
            values["quotient"],
            values["saved_h"],
            values["saved_l"],
        ),
    )
    manager = loaded.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=end.memory.load(NATIVE_STATE + 8, 5),
            result=end.regs.rax[7:0] if returns else claripy.BVV(0, 8),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native port not built")
@pytest.mark.parametrize(
    "assembly_phase,c_symbol,returns",
    [
        (assembly_begin, "port_divide_bytes_begin", True),
        (assembly_step, "port_divide_bytes_step", True),
        (assembly_finish, "port_divide_bytes_finish", False),
    ],
)
def test_phase_equivalence(assembly_phase, c_symbol: str, returns: bool) -> None:
    values = inputs(c_symbol)
    assert_pathwise_equivalent(
        assembly_phase(values),
        native(c_symbol, values, returns),
        (*REGISTERS, "memory", "result"),
    )


def test_exact_body() -> None:
    location = symbol_location(SYMBOLS, "DivideBytes")
    assert linked_bytes(ROM, location, 21) == bytes.fromhex(
        "e521e7ffaf323aa728092a96380523342b18f8e1c9"
    )
