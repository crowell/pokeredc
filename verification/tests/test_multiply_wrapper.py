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
    sm83_flags_to_z80,
    symbol_location,
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
MULTIPLY_BANK = 0x0D
MULTIPLY_ADDRESS = 0x7D41
BANKSWITCH_RETURN = 0x35E4
EXPECTED = bytes.fromhex("e5c521417d060dcdd635c1e1c9")


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
    loaded_bank: claripy.ast.BV
    mapper_bank: claripy.ast.BV
    call: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _flag(condition: claripy.ast.Bool, value: int) -> claripy.ast.BV:
    return claripy.If(condition, claripy.BVV(value, 8), claripy.BVV(0, 8))


def _add(
    left: claripy.ast.BV,
    right: claripy.ast.BV,
    carry: claripy.ast.BV,
) -> tuple[claripy.ast.BV, claripy.ast.BV]:
    wide = (
        claripy.ZeroExt(1, left)
        + claripy.ZeroExt(1, right)
        + claripy.ZeroExt(8, carry)
    )
    result = wide[7:0]
    flags = (
        _flag(result == 0, 0x80)
        | _flag(
            claripy.ZeroExt(1, left[3:0])
            + claripy.ZeroExt(1, right[3:0])
            + claripy.ZeroExt(4, carry)
            > 0x0F,
            0x20,
        )
        | _flag(wide[8:8] == 1, 0x10)
    )
    return result, flags


def _shift_left(
    value: claripy.ast.BV, carry: claripy.ast.BV
) -> tuple[claripy.ast.BV, claripy.ast.BV]:
    result = claripy.Concat(value[6:0], carry)
    flags = _flag(result == 0, 0x80) | _flag(value[7:7] == 1, 0x10)
    return result, flags


def _multiply_transition(
    registers: dict[str, claripy.ast.BV],
    product_in: claripy.ast.BV,
    multiplier_in: claripy.ast.BV,
) -> tuple[dict[str, claripy.ast.BV], claripy.ast.BV, claripy.ast.BV, claripy.ast.BV]:
    output = dict(registers)
    product = [product_in[31 - i * 8 : 24 - i * 8] for i in range(4)]
    buffer = [claripy.BVV(0, 8) for _ in range(4)]
    multiplier = multiplier_in
    output["a"] = claripy.BVV(0, 8)
    output["b"] = claripy.BVV(8, 8)
    output["f"] = claripy.BVV(0x80, 8)
    product[0] = claripy.BVV(0, 8)

    for iteration in range(8):
        old_multiplier = multiplier
        multiplier = claripy.LShR(old_multiplier, 1)
        output["a"] = multiplier
        output["f"] = _flag(multiplier == 0, 0x80) | _flag(
            old_multiplier[0:0] == 1, 0x10
        )
        add_enabled = old_multiplier[0:0] == 1
        next_buffer = list(buffer)
        add_flags = output["f"]
        for index in range(3, -1, -1):
            carry = (
                claripy.BVV(0, 1)
                if index == 3
                else add_flags[4:4]
            )
            result, add_flags = _add(product[index], buffer[index], carry)
            next_buffer[index] = result
            output["c"] = claripy.If(
                add_enabled, buffer[index], output["c"]
            )
            output["a"] = claripy.If(add_enabled, result, output["a"])
            output["f"] = claripy.If(add_enabled, add_flags, output["f"])
        buffer = [
            claripy.If(add_enabled, next_buffer[index], buffer[index])
            for index in range(4)
        ]

        old_b = output["b"]
        output["b"] = old_b - 1
        output["f"] = (
            (output["f"] & 0x10)
            | claripy.BVV(0x40, 8)
            | _flag(output["b"] == 0, 0x80)
            | _flag(old_b[3:0] == 0, 0x20)
        )
        if iteration == 7:
            break

        shift_flags = output["f"]
        shifted = list(product)
        for index in range(3, -1, -1):
            carry = (
                claripy.BVV(0, 1)
                if index == 3
                else shift_flags[4:4]
            )
            shifted[index], shift_flags = _shift_left(product[index], carry)
            output["a"] = shifted[index]
            output["f"] = shift_flags
        product = shifted

    for index in range(3, -1, -1):
        output["a"] = buffer[index]
        product[index] = buffer[index]
    return (
        output,
        claripy.Concat(*product),
        multiplier,
        claripy.Concat(*buffer),
    )


def _call_snapshot(
    registers: dict[str, claripy.ast.BV],
    product: claripy.ast.BV,
    multiplier: claripy.ast.BV,
    buffer: claripy.ast.BV,
    loaded_bank: claripy.ast.BV,
    mapper_bank: claripy.ast.BV,
) -> claripy.ast.BV:
    return claripy.Concat(
        *(registers[name] for name in REGISTERS),
        product,
        multiplier,
        buffer,
        loaded_bank,
        mapper_bank,
    )


class AssemblyMultiply(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        caller = assembly_registers(self.state)
        callback = dict(caller)
        callback["a"] = claripy.BVV(MULTIPLY_BANK, 8)
        callback["b"] = claripy.BVV(BANKSWITCH_RETURN >> 8, 8)
        callback["c"] = claripy.BVV(BANKSWITCH_RETURN & 0xFF, 8)
        product = self.state.memory.load(H_PRODUCT, 4)
        multiplier = self.state.memory.load(H_MULTIPLIER, 1)
        buffer = self.state.memory.load(H_BUFFER, 4)
        self.state.globals["call"] = _call_snapshot(
            callback,
            product,
            multiplier,
            buffer,
            claripy.BVV(MULTIPLY_BANK, 8),
            claripy.BVV(MULTIPLY_BANK, 8),
        )
        output, product, multiplier, buffer = _multiply_transition(
            callback, product, multiplier
        )
        self.state.regs.a = self.state.globals["loaded_bank"]
        self.state.regs.f = sm83_flags_to_z80(output["f"])
        self.state.regs.d = output["d"]
        self.state.regs.e = output["e"]
        self.state.memory.store(H_PRODUCT, product)
        self.state.memory.store(H_MULTIPLIER, multiplier)
        self.state.memory.store(H_BUFFER, buffer)
        self.state.globals["mapper_bank"] = self.state.globals["loaded_bank"]
        self.jump(self._continuation)


class NativeMultiply(angr.SimProcedure):
    def run(self, address: claripy.ast.BV) -> None:  # type: ignore[override]
        registers = {
            name: self.state.memory.load(address + offset, 1)
            for offset, name in enumerate(REGISTERS)
        }
        product = self.state.memory.load(address + 8, 4)
        multiplier = self.state.memory.load(address + 12, 1)
        buffer = self.state.memory.load(address + 13, 4)
        self.state.globals["call"] = _call_snapshot(
            registers,
            product,
            multiplier,
            buffer,
            self.state.memory.load(address + 17, 1),
            self.state.memory.load(address + 18, 1),
        )
        output, product, multiplier, buffer = _multiply_transition(
            registers, product, multiplier
        )
        self.state.memory.store(
            address,
            claripy.Concat(
                *(output[name] for name in REGISTERS),
                product,
                multiplier,
                buffer,
            ),
        )


def inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["product"] = claripy.BVS(f"{prefix}_product", 32)
    values["multiplier"] = claripy.BVS(f"{prefix}_multiplier", 8)
    values["buffer"] = claripy.BVS(f"{prefix}_buffer", 32)
    values["loaded_bank"] = claripy.BVS(f"{prefix}_loaded_bank", 8)
    values["mapper_bank"] = claripy.BVS(f"{prefix}_mapper_bank", 8)
    return values


@cache
def _assembly_project() -> tuple[angr.Project, int]:
    location = symbol_location(SYMS, "Multiply")
    multiply = symbol_location(SYMS, "_Multiply")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    assert multiply.bank == MULTIPLY_BANK
    assert multiply.address == MULTIPLY_ADDRESS
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
        location.address + 7,
        AssemblyMultiply(location.address + 10),
        length=3,
    )
    return project, location.address


@cache
def _native_project() -> tuple[angr.Project, int]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_multiply_wrapper")
    multiply = project.loader.find_symbol("port_multiply")
    assert function is not None and multiply is not None
    project.hook(multiply.rebased_addr, NativeMultiply())
    return project, function.rebased_addr


def assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, function = _assembly_project()
    state = project.factory.blank_state(addr=function)
    set_assembly_registers(state, values)
    state.memory.store(H_PRODUCT, values["product"])
    state.memory.store(H_MULTIPLIER, values["multiplier"])
    state.memory.store(H_BUFFER, values["buffer"])
    state.globals["loaded_bank"] = values["loaded_bank"]
    state.globals["mapper_bank"] = values["mapper_bank"]
    state.globals["call"] = claripy.BVV(0, 152)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    ends = collect_returns(project, state, RETURN)
    assert len(ends) == 1 and ends[0].solver.is_true(ends[0].regs.sp == STACK + 2)
    return [
        Endpoint(
            **assembly_registers(end),
            product=end.memory.load(H_PRODUCT, 4),
            multiplier=end.memory.load(H_MULTIPLIER, 1),
            buffer=end.memory.load(H_BUFFER, 4),
            loaded_bank=end.globals["loaded_bank"],
            mapper_bank=end.globals["mapper_bank"],
            call=end.globals["call"],
            constraints=tuple(end.solver.constraints),
        )
        for end in ends
    ]


def native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, function = _native_project()
    state = project.factory.call_state(function, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, values["product"])
    state.memory.store(NATIVE_STATE + 12, values["multiplier"])
    state.memory.store(NATIVE_STATE + 13, values["buffer"])
    state.memory.store(NATIVE_STATE + 17, values["loaded_bank"])
    state.memory.store(NATIVE_STATE + 18, values["mapper_bank"])
    state.globals["call"] = claripy.BVV(0, 152)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            product=end.memory.load(NATIVE_STATE + 8, 4),
            multiplier=end.memory.load(NATIVE_STATE + 12, 1),
            buffer=end.memory.load(NATIVE_STATE + 13, 4),
            loaded_bank=end.memory.load(NATIVE_STATE + 17, 1),
            mapper_bank=end.memory.load(NATIVE_STATE + 18, 1),
            call=end.globals["call"],
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


OBSERVABLES = (
    *REGISTERS,
    "product",
    "multiplier",
    "buffer",
    "loaded_bank",
    "mapper_bank",
    "call",
)


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(), reason="build")
def test_multiply_wrapper_pathwise_equivalence() -> None:
    values = inputs("multiply_wrapper")
    assert_pathwise_equivalent(assembly(values), native(values), OBSERVABLES)
