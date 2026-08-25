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
    Sm83LoadAHighImmediate,
    Sm83StoreAHighImmediate,
    Sm83StoreAImmediate,
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
H_LOADED_BANK = 0xFFB8
MAPPER_BANK = 0x2000
DIVIDE_BANK = 0x0D
DIVIDE_ADDRESS = 0x7DA5
EXPECTED = bytes.fromhex(
    "e5d5c5f0b8f53e0de0b8ea0020cda57df1e0b8ea0020c1d1e1c9"
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
    loaded_bank: claripy.ast.BV
    mapper_bank: claripy.ast.BV
    call: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _divide_outputs(
    byte_count: claripy.ast.BV,
    dividend: claripy.ast.BV,
    divisor: claripy.ast.BV,
) -> tuple[claripy.ast.BV, claripy.ast.BV, claripy.ast.BV]:
    numerator = claripy.If(
        byte_count == 2,
        claripy.ZeroExt(16, dividend[31:16]),
        claripy.If(
            byte_count == 3,
            claripy.ZeroExt(8, dividend[31:8]),
            dividend,
        ),
    )
    wide_divisor = claripy.ZeroExt(24, divisor)
    quotient = numerator // wide_divisor
    remainder = (numerator % wide_divisor)[7:0]
    buffer = claripy.Concat(divisor, quotient)
    return quotient, remainder, buffer


def _call_snapshot(
    registers: dict[str, claripy.ast.BV],
    dividend: claripy.ast.BV,
    divisor: claripy.ast.BV,
    buffer: claripy.ast.BV,
    loaded_bank: claripy.ast.BV,
    mapper_bank: claripy.ast.BV,
) -> claripy.ast.BV:
    return claripy.Concat(
        *(registers[name] for name in REGISTERS),
        dividend,
        divisor,
        buffer,
        loaded_bank,
        mapper_bank,
    )


class AssemblyDivide(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        registers = assembly_registers(self.state)
        dividend = self.state.memory.load(H_DIVIDEND, 4)
        divisor = self.state.memory.load(H_DIVISOR, 1)
        buffer = self.state.memory.load(H_BUFFER, 5)
        self.state.globals["call"] = _call_snapshot(
            registers,
            dividend,
            divisor,
            buffer,
            self.state.memory.load(H_LOADED_BANK, 1),
            self.state.memory.load(MAPPER_BANK, 1),
        )
        quotient, remainder, buffer = _divide_outputs(
            registers["b"], dividend, divisor
        )
        self.state.memory.store(H_DIVIDEND, quotient)
        self.state.memory.store(H_DIVISOR, remainder)
        self.state.memory.store(H_BUFFER, buffer)
        self.jump(self._continuation)


class NativeDivide(angr.SimProcedure):
    def run(self, address: claripy.ast.BV) -> None:  # type: ignore[override]
        registers = {
            name: self.state.memory.load(address + offset, 1)
            for offset, name in enumerate(REGISTERS)
        }
        dividend = self.state.memory.load(address + 8, 4)
        divisor = self.state.memory.load(address + 12, 1)
        buffer = self.state.memory.load(address + 13, 5)
        self.state.globals["call"] = _call_snapshot(
            registers,
            dividend,
            divisor,
            buffer,
            self.state.memory.load(address + 18, 1),
            self.state.memory.load(address + 19, 1),
        )
        quotient, remainder, buffer = _divide_outputs(
            registers["b"], dividend, divisor
        )
        self.state.memory.store(address + 8, quotient)
        self.state.memory.store(address + 12, remainder)
        self.state.memory.store(address + 13, buffer)


def inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["dividend"] = claripy.BVS(f"{prefix}_dividend", 32)
    values["divisor"] = claripy.BVS(f"{prefix}_divisor", 8)
    values["buffer"] = claripy.BVS(f"{prefix}_buffer", 40)
    values["loaded_bank"] = claripy.BVS(f"{prefix}_loaded_bank", 8)
    values["mapper_bank"] = claripy.BVS(f"{prefix}_mapper_bank", 8)
    return values


def _constrain_contract(
    state: angr.SimState, values: dict[str, claripy.ast.BV]
) -> None:
    state.solver.add(values["b"] >= 2)
    state.solver.add(values["b"] <= 4)
    state.solver.add(values["divisor"] != 0)


@cache
def _assembly_project() -> tuple[angr.Project, int]:
    location = symbol_location(SYMS, "Divide")
    divide = symbol_location(SYMS, "_Divide")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    assert divide.bank == DIVIDE_BANK
    assert divide.address == DIVIDE_ADDRESS
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
    project.hook(base + 3, Sm83LoadAHighImmediate(0xB8, base + 5), length=2)
    project.hook(base + 8, Sm83StoreAHighImmediate(0xB8, base + 10), length=2)
    project.hook(base + 10, Sm83StoreAImmediate(MAPPER_BANK, base + 13), length=3)
    project.hook(base + 13, AssemblyDivide(base + 16), length=3)
    project.hook(base + 17, Sm83StoreAHighImmediate(0xB8, base + 19), length=2)
    project.hook(base + 19, Sm83StoreAImmediate(MAPPER_BANK, base + 22), length=3)
    return project, base


@cache
def _native_project() -> tuple[angr.Project, int]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_divide_wrapper")
    divide = project.loader.find_symbol("port_divide")
    assert function is not None and divide is not None
    project.hook(divide.rebased_addr, NativeDivide())
    return project, function.rebased_addr


def assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, function = _assembly_project()
    state = project.factory.blank_state(addr=function)
    set_assembly_registers(state, values)
    state.memory.store(H_DIVIDEND, values["dividend"])
    state.memory.store(H_DIVISOR, values["divisor"])
    state.memory.store(H_BUFFER, values["buffer"])
    state.memory.store(H_LOADED_BANK, values["loaded_bank"])
    state.memory.store(MAPPER_BANK, values["mapper_bank"])
    state.globals["call"] = claripy.BVV(0, 160)
    _constrain_contract(state, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    ends = collect_returns(project, state, RETURN)
    assert len(ends) == 1 and ends[0].solver.is_true(ends[0].regs.sp == STACK + 2)
    return [
        Endpoint(
            **assembly_registers(end),
            dividend=end.memory.load(H_DIVIDEND, 4),
            divisor=end.memory.load(H_DIVISOR, 1),
            buffer=end.memory.load(H_BUFFER, 5),
            loaded_bank=end.memory.load(H_LOADED_BANK, 1),
            mapper_bank=end.memory.load(MAPPER_BANK, 1),
            call=end.globals["call"],
            constraints=tuple(end.solver.constraints),
        )
        for end in ends
    ]


def native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, function = _native_project()
    state = project.factory.call_state(function, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, values["dividend"])
    state.memory.store(NATIVE_STATE + 12, values["divisor"])
    state.memory.store(NATIVE_STATE + 13, values["buffer"])
    state.memory.store(NATIVE_STATE + 18, values["loaded_bank"])
    state.memory.store(NATIVE_STATE + 19, values["mapper_bank"])
    state.globals["call"] = claripy.BVV(0, 160)
    _constrain_contract(state, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            dividend=end.memory.load(NATIVE_STATE + 8, 4),
            divisor=end.memory.load(NATIVE_STATE + 12, 1),
            buffer=end.memory.load(NATIVE_STATE + 13, 5),
            loaded_bank=end.memory.load(NATIVE_STATE + 18, 1),
            mapper_bank=end.memory.load(NATIVE_STATE + 19, 1),
            call=end.globals["call"],
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


OBSERVABLES = (
    *REGISTERS,
    "dividend",
    "divisor",
    "buffer",
    "loaded_bank",
    "mapper_bank",
    "call",
)


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(), reason="build")
def test_divide_wrapper_pathwise_equivalence() -> None:
    values = inputs("divide_wrapper")
    assert_pathwise_equivalent(assembly(values), native(values), OBSERVABLES)
