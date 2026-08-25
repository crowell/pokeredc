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
W_PREDEF = 0xCC4F
EXPECTED = bytes.fromhex("cd943e")


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
    predef: claripy.ast.BV
    math: claripy.ast.BV
    divisor: claripy.ast.BV
    buffer: claripy.ast.BV
    loaded: claripy.ast.BV
    mapper: claripy.ast.BV
    predef_call: claripy.ast.BV
    hp_call: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _snapshot(*values: claripy.ast.BV) -> claripy.ast.BV:
    return claripy.Concat(*values)


def _register_vector(registers: dict[str, claripy.ast.BV]) -> claripy.ast.BV:
    return claripy.Concat(*(registers[name] for name in REGISTERS))


def _return_target(state: angr.SimState) -> claripy.ast.BV:
    target = state.memory.load(state.regs.sp, 2, endness="Iend_LE")
    state.regs.sp += 2
    return target


def _predef_registers(
    registers: dict[str, claripy.ast.BV], predef: claripy.ast.BV
) -> dict[str, claripy.ast.BV]:
    output = dict(registers)
    output["a"] = predef[7:0]
    output["h"] = predef[47:40]
    output["l"] = predef[39:32]
    output["d"] = predef[31:24]
    output["e"] = predef[23:16]
    output["b"] = predef[15:8]
    output["c"] = predef[7:0]
    return output


def _hp_outputs(
    registers: dict[str, claripy.ast.BV], math: claripy.ast.BV,
    loaded: claripy.ast.BV,
) -> tuple[dict[str, claripy.ast.BV], claripy.ast.BV, claripy.ast.BV,
           claripy.ast.BV, claripy.ast.BV]:
    del math
    multiplicand = claripy.Concat(
        claripy.BVV(0, 8), registers["b"], registers["c"]
    )
    product = claripy.ZeroExt(8, multiplicand) * claripy.BVV(0x30, 32)
    max_hp = claripy.Concat(registers["d"], registers["e"])
    scaled_max = claripy.LShR(max_hp, 2)
    scaled_product = claripy.LShR(product[15:0], 2)
    wide_max = claripy.If(registers["d"] == 0, max_hp, scaled_max)
    dividend = claripy.If(
        registers["d"] == 0,
        product,
        claripy.Concat(product[31:16], scaled_product),
    )
    divisor = wide_max[7:0]
    quotient = dividend // claripy.ZeroExt(24, divisor)
    remainder = (dividend % claripy.ZeroExt(24, divisor))[7:0]
    pixels = quotient[7:0]
    output = dict(registers)
    output["a"] = pixels
    output["f"] = claripy.BVV(0x20, 8) | claripy.If(
        pixels == 0, claripy.BVV(0x80, 8), claripy.BVV(0, 8)
    )
    output["b"] = claripy.BVV(4, 8)
    output["d"] = wide_max[15:8]
    output["e"] = claripy.If(pixels == 0, claripy.BVV(1, 8), pixels)
    return output, quotient, remainder, claripy.Concat(divisor, quotient), loaded


class AssemblyPredef(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        registers = assembly_registers(self.state)
        predef = self.state.memory.load(W_PREDEF, 6)
        self.state.globals["predef_call"] = _snapshot(
            _register_vector(registers), predef
        )
        set_assembly_registers(
            self.state, _predef_registers(registers, predef)
        )
        self.jump(_return_target(self.state))


class NativePredef(angr.SimProcedure):
    def run(self, address: claripy.ast.BV) -> None:  # type: ignore[override]
        registers = {
            name: self.state.memory.load(address + offset, 1)
            for offset, name in enumerate(REGISTERS)
        }
        predef = self.state.memory.load(address + 8, 6)
        self.state.globals["predef_call"] = _snapshot(
            _register_vector(registers), predef
        )
        output = _predef_registers(registers, predef)
        self.state.memory.store(address, _register_vector(output))


class AssemblyGetHPBarLength(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        registers = assembly_registers(self.state)
        math = self.state.memory.load(H_MATH, 4)
        loaded = self.state.memory.load(H_LOADED, 1)
        self.state.globals["hp_call"] = _snapshot(
            _register_vector(registers), math,
            self.state.memory.load(H_DIVISOR, 1),
            self.state.memory.load(H_BUFFER, 5), loaded,
            self.state.memory.load(MAPPER, 1),
        )
        output, math, divisor, buffer, mapper = _hp_outputs(
            registers, math, loaded
        )
        set_assembly_registers(self.state, output)
        self.state.memory.store(H_MATH, math)
        self.state.memory.store(H_DIVISOR, divisor)
        self.state.memory.store(H_BUFFER, buffer)
        self.state.memory.store(MAPPER, mapper)
        self.jump(_return_target(self.state))


class NativeGetHPBarLength(angr.SimProcedure):
    def run(self, address: claripy.ast.BV) -> None:  # type: ignore[override]
        registers = {
            name: self.state.memory.load(address + offset, 1)
            for offset, name in enumerate(REGISTERS)
        }
        math = self.state.memory.load(address + 8, 4)
        loaded = self.state.memory.load(address + 18, 1)
        self.state.globals["hp_call"] = _snapshot(
            _register_vector(registers), math,
            self.state.memory.load(address + 12, 1),
            self.state.memory.load(address + 13, 5), loaded,
            self.state.memory.load(address + 19, 1),
        )
        output, math, divisor, buffer, mapper = _hp_outputs(
            registers, math, loaded
        )
        self.state.memory.store(address, _register_vector(output))
        self.state.memory.store(address + 8, math)
        self.state.memory.store(address + 12, divisor)
        self.state.memory.store(address + 13, buffer)
        self.state.memory.store(address + 19, mapper)


def _inputs() -> dict[str, claripy.ast.BV]:
    values = symbolic_registers("hp_bar_length")
    values["predef"] = claripy.BVS("hp_bar_length_predef", 48)
    values["math"] = claripy.BVS("hp_bar_length_math", 32)
    values["divisor"] = claripy.BVS("hp_bar_length_divisor", 8)
    values["buffer"] = claripy.BVS("hp_bar_length_buffer", 40)
    values["loaded"] = claripy.BVS("hp_bar_length_loaded", 8)
    values["mapper"] = claripy.BVS("hp_bar_length_mapper", 8)
    return values


def _setup(
    state: angr.SimState, values: dict[str, claripy.ast.BV], native: bool
) -> None:
    if native:
        store_native_registers(state, NS, values)
        state.memory.store(NS + 8, values["predef"])
        state.memory.store(NS + 14, values["math"])
        state.memory.store(NS + 18, values["divisor"])
        state.memory.store(NS + 19, values["buffer"])
        state.memory.store(NS + 24, values["loaded"])
        state.memory.store(NS + 25, values["mapper"])
    else:
        set_assembly_registers(state, values)
        state.memory.store(W_PREDEF, values["predef"])
        state.memory.store(H_MATH, values["math"])
        state.memory.store(H_DIVISOR, values["divisor"])
        state.memory.store(H_BUFFER, values["buffer"])
        state.memory.store(H_LOADED, values["loaded"])
        state.memory.store(MAPPER, values["mapper"])
    state.globals["predef_call"] = claripy.BVV(0, 112)
    state.globals["hp_call"] = claripy.BVV(0, 160)
    state.add_constraints(values["predef"][31:16] != 0)


def _endpoint(state: angr.SimState, native: bool) -> Endpoint:
    registers = native_registers(state, NS) if native else assembly_registers(state)
    return Endpoint(
        **registers,
        predef=state.memory.load(NS + 8 if native else W_PREDEF, 6),
        math=state.memory.load(NS + 14 if native else H_MATH, 4),
        divisor=state.memory.load(NS + 18 if native else H_DIVISOR, 1),
        buffer=state.memory.load(NS + 19 if native else H_BUFFER, 5),
        loaded=state.memory.load(NS + 24 if native else H_LOADED, 1),
        mapper=state.memory.load(NS + 25 if native else MAPPER, 1),
        predef_call=state.globals["predef_call"],
        hp_call=state.globals["hp_call"],
        constraints=tuple(state.solver.constraints),
    )


@cache
def _assembly_project() -> tuple[angr.Project, int]:
    location = symbol_location(SYMS, "HPBarLength")
    predef = symbol_location(SYMS, "GetPredefRegisters")
    get_hp = symbol_location(SYMS, "GetHPBarLength")
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    project.hook(predef.address, AssemblyPredef())
    project.hook(get_hp.address, AssemblyGetHPBarLength())
    return project, location.address


@cache
def _native_project() -> tuple[angr.Project, int]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_hp_bar_length_private")
    predef = project.loader.find_symbol("port_get_predef_registers")
    get_hp = project.loader.find_symbol("port_get_hp_bar_length_private")
    assert function is not None and predef is not None and get_hp is not None
    project.hook(predef.rebased_addr, NativePredef())
    project.hook(get_hp.rebased_addr, NativeGetHPBarLength())
    return project, function.rebased_addr


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, function = _assembly_project()
    state = project.factory.blank_state(addr=function)
    _setup(state, values, False)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    endpoints = [_endpoint(end, False) for end in collect_returns(project, state, RETURN)]
    assert len(endpoints) == 1
    return endpoints


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, function = _native_project()
    state = project.factory.call_state(function, NS)
    _setup(state, values, True)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [_endpoint(end, True) for end in manager.deadended]


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(), reason="build")
def test_hp_bar_length_pathwise_equivalence() -> None:
    location = symbol_location(SYMS, "HPBarLength")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    values = _inputs()
    assert_pathwise_equivalent(
        _assembly(values), _native(values),
        (*REGISTERS, "predef", "math", "divisor", "buffer", "loaded",
         "mapper", "predef_call", "hp_call"),
    )
