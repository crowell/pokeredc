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
from verification.harness.sm83_shims import (
    Sm83LoadAHighImmediate,
    Sm83RrRegister,
    Sm83SrlRegister,
    Sm83StoreAAtHlIncrement,
    Sm83StoreAHighImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMS = ROOT / "pokered.sym"
NS = 0x100000
STACK = 0xE000
RETURN = 0xFFFF
H_MATH = 0xFF95
H_DIVISOR = 0xFF99
H_BUFFER = 0xFF9A
H_LOADED = 0xFFB8
MAPPER = 0x2000
EXPECTED = bytes.fromhex(
    "e5af2196ff22782279223630cdac387aa7281acb3acb1bcb3acb1bf09747"
    "f098cb38cb1fcb38cb1fe09878e0977be0990604cdb938f0985fe1a7c01e"
    "01c9"
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
    math: claripy.ast.BV
    divisor: claripy.ast.BV
    buffer: claripy.ast.BV
    loaded: claripy.ast.BV
    mapper: claripy.ast.BV
    multiply_call: claripy.ast.BV
    divide_call: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _regs(state: angr.SimState) -> claripy.ast.BV:
    values = assembly_registers(state)
    return claripy.Concat(*(values[name] for name in REGISTERS))


def _snapshot(
    registers: claripy.ast.BV,
    math: claripy.ast.BV,
    divisor: claripy.ast.BV,
    buffer: claripy.ast.BV,
    loaded: claripy.ast.BV,
    mapper: claripy.ast.BV,
) -> claripy.ast.BV:
    return claripy.Concat(registers, math, divisor, buffer, loaded, mapper)


class XorA(angr.SimProcedure):
    def __init__(self, nxt: int) -> None:
        super().__init__(); self.nxt = nxt

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = 0
        self.state.regs.f = 0x40
        self.jump(self.nxt)


class AndA(angr.SimProcedure):
    def __init__(self, nxt: int) -> None:
        super().__init__(); self.nxt = nxt

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.f = claripy.BVV(0x10, 8) | claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x40, 8),
            claripy.BVV(0, 8),
        )
        self.jump(self.nxt)


class CopyRegister(angr.SimProcedure):
    def __init__(self, dst: str, src: str, nxt: int) -> None:
        super().__init__(); self.dst = dst; self.src = src; self.nxt = nxt

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.dst, getattr(self.state.regs, self.src))
        self.jump(self.nxt)


class StoreImmediateAtHL(angr.SimProcedure):
    def __init__(self, value: int, nxt: int) -> None:
        super().__init__(); self.value = value; self.nxt = nxt

    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(self.state.regs.hl, claripy.BVV(self.value, 8))
        self.jump(self.nxt)


class LoadRegisterImmediate(angr.SimProcedure):
    def __init__(self, register: str, value: int, nxt: int) -> None:
        super().__init__(); self.register = register; self.value = value; self.nxt = nxt

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.register, self.value)
        self.jump(self.nxt)


def _return_target(state: angr.SimState) -> claripy.ast.BV:
    target = state.memory.load(state.regs.sp, 2, endness="Iend_LE")
    state.regs.sp += 2
    return target


class AssemblyMultiply(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        math = self.state.memory.load(H_MATH, 4)
        multiplier = self.state.memory.load(H_DIVISOR, 1)
        loaded = self.state.memory.load(H_LOADED, 1)
        self.state.globals["multiply_call"] = _snapshot(
            _regs(self.state), math, multiplier,
            self.state.memory.load(H_BUFFER + 1, 4), loaded,
            self.state.memory.load(MAPPER, 1),
        )
        product = claripy.ZeroExt(8, math[23:0]) * claripy.ZeroExt(24, multiplier)
        self.state.memory.store(H_MATH, product)
        self.state.memory.store(H_DIVISOR, claripy.BVV(0, 8))
        self.state.memory.store(H_BUFFER + 1, product)
        self.state.memory.store(MAPPER, loaded)
        self.state.regs.a = loaded
        self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0xC0, 8))
        self.jump(_return_target(self.state))


class NativeMultiply(angr.SimProcedure):
    def run(self, address: claripy.ast.BV) -> None:  # type: ignore[override]
        registers = self.state.memory.load(address, 8)
        math = self.state.memory.load(address + 8, 4)
        multiplier = self.state.memory.load(address + 12, 1)
        loaded = self.state.memory.load(address + 17, 1)
        self.state.globals["multiply_call"] = _snapshot(
            registers, math, multiplier, self.state.memory.load(address + 13, 4),
            loaded, self.state.memory.load(address + 18, 1),
        )
        product = claripy.ZeroExt(8, math[23:0]) * claripy.ZeroExt(24, multiplier)
        self.state.memory.store(address, loaded)
        self.state.memory.store(address + 1, claripy.BVV(0xC0, 8))
        self.state.memory.store(address + 8, product)
        self.state.memory.store(address + 12, claripy.BVV(0, 8))
        self.state.memory.store(address + 13, product)
        self.state.memory.store(address + 18, loaded)


def _divide_outputs(
    dividend: claripy.ast.BV, divisor: claripy.ast.BV
) -> tuple[claripy.ast.BV, claripy.ast.BV, claripy.ast.BV]:
    quotient = dividend // claripy.ZeroExt(24, divisor)
    remainder = (dividend % claripy.ZeroExt(24, divisor))[7:0]
    return quotient, remainder, claripy.Concat(divisor, quotient)


class AssemblyDivide(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        math = self.state.memory.load(H_MATH, 4)
        divisor = self.state.memory.load(H_DIVISOR, 1)
        loaded = self.state.memory.load(H_LOADED, 1)
        self.state.globals["divide_call"] = _snapshot(
            _regs(self.state), math, divisor, self.state.memory.load(H_BUFFER, 5),
            loaded, self.state.memory.load(MAPPER, 1),
        )
        quotient, remainder, buffer = _divide_outputs(math, divisor)
        self.state.memory.store(H_MATH, quotient)
        self.state.memory.store(H_DIVISOR, remainder)
        self.state.memory.store(H_BUFFER, buffer)
        self.state.memory.store(MAPPER, loaded)
        self.state.regs.a = loaded
        self.jump(_return_target(self.state))


class NativeDivide(angr.SimProcedure):
    def run(self, address: claripy.ast.BV) -> None:  # type: ignore[override]
        registers = self.state.memory.load(address, 8)
        math = self.state.memory.load(address + 8, 4)
        divisor = self.state.memory.load(address + 12, 1)
        loaded = self.state.memory.load(address + 18, 1)
        self.state.globals["divide_call"] = _snapshot(
            registers, math, divisor, self.state.memory.load(address + 13, 5),
            loaded, self.state.memory.load(address + 19, 1),
        )
        quotient, remainder, buffer = _divide_outputs(math, divisor)
        self.state.memory.store(address, loaded)
        self.state.memory.store(address + 8, quotient)
        self.state.memory.store(address + 12, remainder)
        self.state.memory.store(address + 13, buffer)
        self.state.memory.store(address + 19, loaded)


def _inputs() -> dict[str, claripy.ast.BV]:
    values = symbolic_registers("get_hp_bar_length")
    values["math"] = claripy.BVS("get_hp_bar_length_math", 32)
    values["divisor"] = claripy.BVS("get_hp_bar_length_divisor", 8)
    values["buffer"] = claripy.BVS("get_hp_bar_length_buffer", 40)
    values["loaded"] = claripy.BVS("get_hp_bar_length_loaded", 8)
    values["mapper"] = claripy.BVS("get_hp_bar_length_mapper", 8)
    return values


def _setup(state: angr.SimState, values: dict[str, claripy.ast.BV], native: bool) -> None:
    if native:
        store_native_registers(state, NS, values)
        state.memory.store(NS + 8, values["math"])
        state.memory.store(NS + 12, values["divisor"])
        state.memory.store(NS + 13, values["buffer"])
        state.memory.store(NS + 18, values["loaded"])
        state.memory.store(NS + 19, values["mapper"])
    else:
        set_assembly_registers(state, values)
        state.memory.store(H_MATH, values["math"])
        state.memory.store(H_DIVISOR, values["divisor"])
        state.memory.store(H_BUFFER, values["buffer"])
        state.memory.store(H_LOADED, values["loaded"])
        state.memory.store(MAPPER, values["mapper"])
    state.globals["multiply_call"] = claripy.BVV(0, 152)
    state.globals["divide_call"] = claripy.BVV(0, 160)
    state.add_constraints(claripy.Concat(values["d"], values["e"]) != 0)


def _endpoint(state: angr.SimState, native: bool) -> Endpoint:
    registers = native_registers(state, NS) if native else assembly_registers(state)
    base = NS if native else 0
    return Endpoint(
        **registers,
        math=state.memory.load(base + (8 if native else H_MATH), 4),
        divisor=state.memory.load(base + (12 if native else H_DIVISOR), 1),
        buffer=state.memory.load(base + (13 if native else H_BUFFER), 5),
        loaded=state.memory.load(NS + 18 if native else H_LOADED, 1),
        mapper=state.memory.load(NS + 19 if native else MAPPER, 1),
        multiply_call=state.globals["multiply_call"],
        divide_call=state.globals["divide_call"],
        constraints=tuple(state.solver.constraints),
    )


@cache
def _assembly_project() -> tuple[angr.Project, int]:
    location = symbol_location(SYMS, "GetHPBarLength")
    multiply = symbol_location(SYMS, "Multiply")
    divide = symbol_location(SYMS, "Divide")
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    b = location.address
    project.hook(b + 1, XorA(b + 2), length=1)
    project.hook(b + 5, Sm83StoreAAtHlIncrement(b + 6), length=1)
    project.hook(b + 6, CopyRegister("a", "b", b + 7), length=1)
    project.hook(b + 7, Sm83StoreAAtHlIncrement(b + 8), length=1)
    project.hook(b + 8, CopyRegister("a", "c", b + 9), length=1)
    project.hook(b + 9, Sm83StoreAAtHlIncrement(b + 10), length=1)
    project.hook(b + 10, StoreImmediateAtHL(0x30, b + 12), length=2)
    project.hook(multiply.address, AssemblyMultiply())
    project.hook(b + 15, CopyRegister("a", "d", b + 16), length=1)
    project.hook(b + 16, AndA(b + 17), length=1)
    for offset, reg in ((19, "d"), (23, "d"), (32, "b"), (36, "b")):
        project.hook(b + offset, Sm83SrlRegister(reg, b + offset + 2), length=2)
    for offset, reg in ((21, "e"), (25, "e"), (34, "a"), (38, "a")):
        project.hook(b + offset, Sm83RrRegister(reg, b + offset + 2), length=2)
    project.hook(b + 27, Sm83LoadAHighImmediate(0x97, b + 29), length=2)
    project.hook(b + 29, CopyRegister("b", "a", b + 30), length=1)
    project.hook(b + 30, Sm83LoadAHighImmediate(0x98, b + 32), length=2)
    project.hook(b + 40, Sm83StoreAHighImmediate(0x98, b + 42), length=2)
    project.hook(b + 42, CopyRegister("a", "b", b + 43), length=1)
    project.hook(b + 43, Sm83StoreAHighImmediate(0x97, b + 45), length=2)
    project.hook(b + 45, CopyRegister("a", "e", b + 46), length=1)
    project.hook(b + 46, Sm83StoreAHighImmediate(0x99, b + 48), length=2)
    project.hook(divide.address, AssemblyDivide())
    project.hook(b + 53, Sm83LoadAHighImmediate(0x98, b + 55), length=2)
    project.hook(b + 55, CopyRegister("e", "a", b + 56), length=1)
    project.hook(b + 57, AndA(b + 58), length=1)
    project.hook(b + 59, LoadRegisterImmediate("e", 1, b + 61), length=2)
    return project, b


@cache
def _native_project() -> tuple[angr.Project, int]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_get_hp_bar_length_private")
    multiply = project.loader.find_symbol("port_multiply_wrapper")
    divide = project.loader.find_symbol("port_divide_wrapper")
    assert function is not None and multiply is not None and divide is not None
    project.hook(multiply.rebased_addr, NativeMultiply())
    project.hook(divide.rebased_addr, NativeDivide())
    return project, function.rebased_addr


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, function = _assembly_project()
    state = project.factory.blank_state(addr=function)
    _setup(state, values, False)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    endpoints = [_endpoint(end, False) for end in collect_returns(project, state, RETURN)]
    assert len(endpoints) == 4
    return endpoints


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, function = _native_project()
    state = project.factory.call_state(function, NS)
    _setup(state, values, True)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 4
    return [_endpoint(end, True) for end in manager.deadended]


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(), reason="build")
def test_get_hp_bar_length_pathwise_equivalence() -> None:
    location = symbol_location(SYMS, "GetHPBarLength")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    values = _inputs()
    assert_pathwise_equivalent(
        _assembly(values), _native(values),
        (*REGISTERS, "math", "divisor", "buffer", "loaded", "mapper",
         "multiply_call", "divide_call"),
    )
