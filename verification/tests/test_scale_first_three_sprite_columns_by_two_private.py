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
    Sm83AddHlRegisterPair,
    Sm83DecRegister,
    Sm83SwapRegister,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMS = ROOT / "pokered.sym"
NS = 0x100000
STACK = 0xD000
RETURN = 0xFFFF
SOURCE_DE = 0xA1E3
DESTINATION_HL = 0xA14F
EXPECTED = bytes.fromhex(
    "06030e1cc51a01c9ffcd977e1a1bcb37013700cd977ec10d20ea"
    "1b1b1b1b7801c8ff09470520dbc9"
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
    source: claripy.ast.BV
    destination: claripy.ast.BV
    iterations: claripy.ast.BV
    pixel_calls: claripy.ast.BV
    calls: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _register_vector(registers: dict[str, claripy.ast.BV]) -> claripy.ast.BV:
    return claripy.Concat(*(registers[name] for name in REGISTERS))


def _return_target(state: angr.SimState) -> claripy.ast.BV:
    target = state.memory.load(state.regs.sp, 2, endness="Iend_LE")
    state.regs.sp += 2
    return target


def _scale_transition(
    registers: dict[str, claripy.ast.BV],
) -> tuple[dict[str, claripy.ast.BV], claripy.ast.BV]:
    pixels = registers["a"] & 0x0F
    duplicated = (
        (pixels & 1) * 3
        | (pixels & 2) * 6
        | (pixels & 4) * 12
        | (pixels & 8) * 24
    )
    destination = claripy.Concat(registers["h"], registers["l"]) - 1
    bc = claripy.Concat(registers["b"], registers["c"])
    wide = claripy.ZeroExt(1, destination) + claripy.ZeroExt(1, bc)
    result = destination + bc
    flags = claripy.If(
        claripy.UGT(
            claripy.ZeroExt(1, destination[11:0])
            + claripy.ZeroExt(1, bc[11:0]),
            claripy.BVV(0xFFF, 13),
        ),
        claripy.BVV(0x20, 8),
        claripy.BVV(0, 8),
    ) | claripy.If(
        wide[16] == 1, claripy.BVV(0x10, 8), claripy.BVV(0, 8)
    )
    output = dict(registers)
    output["a"] = duplicated
    output["f"] = flags
    output["h"] = result[15:8]
    output["l"] = result[7:0]
    return output, duplicated


def _record_call(state: angr.SimState, registers: dict[str, claripy.ast.BV]) -> None:
    index = state.globals["call_count"]
    state.globals["calls"][index] = _register_vector(registers)
    state.globals["call_count"] = index + 1


class AssemblyScalePixels(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        registers = assembly_registers(self.state)
        _record_call(self.state, registers)
        output, written = _scale_transition(registers)
        address = claripy.Concat(registers["h"], registers["l"])
        self.state.memory.store(address, written)
        self.state.memory.store(address - 1, written)
        set_assembly_registers(self.state, output)
        self.jump(_return_target(self.state))


class NativeScalePixels(angr.SimProcedure):
    def run(self, address: claripy.ast.BV) -> None:  # type: ignore[override]
        registers = {
            name: self.state.memory.load(address + offset, 1)
            for offset, name in enumerate(REGISTERS)
        }
        _record_call(self.state, registers)
        output, written = _scale_transition(registers)
        self.state.memory.store(address, _register_vector(output))
        self.state.memory.store(address + 8, written)
        self.state.memory.store(address + 9, written)


class CountedDec(angr.SimProcedure):
    def __init__(self, register: str, nxt: int, count: bool = False) -> None:
        super().__init__()
        self.register = register
        self.nxt = nxt
        self.count = count

    def run(self) -> None:  # type: ignore[override]
        value = getattr(self.state.regs, self.register)
        result = value - 1
        flags = self.state.regs.f & 0x01
        flags |= claripy.BVV(0x02, 8)
        flags |= claripy.If(result == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        flags |= claripy.If(
            value[3:0] == 0, claripy.BVV(0x10, 8), claripy.BVV(0, 8)
        )
        setattr(self.state.regs, self.register, result)
        self.state.regs.f = flags
        if self.count:
            self.state.globals["iterations"] += 1
        self.jump(self.nxt)


class ForkNZ(angr.SimProcedure):
    def __init__(self, taken: int, fallthrough: int) -> None:
        super().__init__()
        self.taken = taken
        self.fallthrough = fallthrough

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        condition = (self.state.regs.f & 0x40) == 0
        if self.state.solver.is_true(condition):
            self.jump(self.taken)
            return
        if self.state.solver.is_false(condition):
            self.jump(self.fallthrough)
            return
        for target, guard in (
            (self.taken, condition),
            (self.fallthrough, claripy.Not(condition)),
        ):
            successor = self.state.copy()
            successor.solver.add(guard)
            successor.regs.ip = target
            self.successors.add_successor(successor, target, guard, "Ijk_Boring")


def _inputs() -> dict[str, claripy.ast.BV]:
    values = symbolic_registers("scale_first_three_columns")
    values["source"] = claripy.BVS("scale_first_three_columns_source", 84 * 8)
    values["destination"] = claripy.BVS(
        "scale_first_three_columns_destination", 336 * 8
    )
    values["iterations"] = claripy.BVS("scale_first_three_columns_iterations", 8)
    values["pixel_calls"] = claripy.BVS("scale_first_three_columns_calls", 8)
    return values


def _bytes(value: claripy.ast.BV, count: int) -> list[claripy.ast.BV]:
    return [value[(count - index) * 8 - 1:(count - index - 1) * 8]
            for index in range(count)]


def _source_addresses() -> list[int]:
    return [SOURCE_DE - column * 32 - row
            for column in range(3) for row in range(28)]


def _setup_globals(state: angr.SimState) -> None:
    state.globals["calls"] = [claripy.BVV(0, 64) for _ in range(168)]
    state.globals["call_count"] = 0
    state.globals["iterations"] = 0


@cache
def _assembly_project() -> tuple[angr.Project, int]:
    location = symbol_location(SYMS, "ScaleFirstThreeSpriteColumnsByTwo")
    scale = symbol_location(SYMS, "ScalePixelsByTwo")
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    base = location.address
    project.hook(scale.address, AssemblyScalePixels())
    project.hook(base + 14, Sm83SwapRegister("a", base + 16), length=2)
    project.hook(base + 23, CountedDec("c", base + 24, True), length=1)
    project.hook(base + 24, ForkNZ(base + 4, base + 26), length=2)
    project.hook(base + 34, Sm83AddHlRegisterPair("bc", base + 35), length=1)
    project.hook(base + 36, Sm83DecRegister("b", base + 37), length=1)
    project.hook(base + 37, ForkNZ(base + 2, base + 39), length=2)
    return project, base


@cache
def _native_project() -> tuple[angr.Project, int]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol(
        "port_scale_first_three_sprite_columns_by_two_private"
    )
    scale = project.loader.find_symbol("port_scale_pixels_by_two")
    assert function is not None and scale is not None
    project.hook(scale.rebased_addr, NativeScalePixels())
    return project, function.rebased_addr


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, function = _assembly_project()
    state = project.factory.blank_state(addr=function)
    registers = dict(values)
    registers["d"] = claripy.BVV(SOURCE_DE >> 8, 8)
    registers["e"] = claripy.BVV(SOURCE_DE & 0xFF, 8)
    registers["h"] = claripy.BVV(DESTINATION_HL >> 8, 8)
    registers["l"] = claripy.BVV(DESTINATION_HL & 0xFF, 8)
    set_assembly_registers(state, registers)
    for address, byte in zip(
        _source_addresses(), _bytes(values["source"], 84), strict=True
    ):
        state.memory.store(address, byte)
    for index, byte in enumerate(_bytes(values["destination"], 336)):
        state.memory.store(DESTINATION_HL - index, byte)
    _setup_globals(state)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    ends = collect_returns(project, state, RETURN)
    assert len(ends) == 1
    end = ends[0]
    return [Endpoint(
        **assembly_registers(end),
        source=claripy.Concat(
            *(end.memory.load(address, 1) for address in _source_addresses())
        ),
        destination=claripy.Concat(
            *(end.memory.load(DESTINATION_HL - i, 1) for i in range(336))
        ),
        iterations=claripy.BVV(end.globals["iterations"], 8),
        pixel_calls=claripy.BVV(end.globals["call_count"], 8),
        calls=claripy.Concat(*end.globals["calls"]),
        constraints=tuple(end.solver.constraints),
    )]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, function = _native_project()
    state = project.factory.call_state(function, NS)
    registers = dict(values)
    registers["d"] = claripy.BVV(SOURCE_DE >> 8, 8)
    registers["e"] = claripy.BVV(SOURCE_DE & 0xFF, 8)
    registers["h"] = claripy.BVV(DESTINATION_HL >> 8, 8)
    registers["l"] = claripy.BVV(DESTINATION_HL & 0xFF, 8)
    store_native_registers(state, NS, registers)
    state.memory.store(NS + 8, values["source"])
    state.memory.store(NS + 92, values["destination"])
    state.memory.store(NS + 428, values["iterations"])
    state.memory.store(NS + 429, values["pixel_calls"])
    _setup_globals(state)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    end = manager.deadended[0]
    return [Endpoint(
        **native_registers(end, NS),
        source=end.memory.load(NS + 8, 84),
        destination=end.memory.load(NS + 92, 336),
        iterations=end.memory.load(NS + 428, 1),
        pixel_calls=end.memory.load(NS + 429, 1),
        calls=claripy.Concat(*end.globals["calls"]),
        constraints=tuple(end.solver.constraints),
    )]


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(), reason="build")
def test_scale_first_three_sprite_columns_by_two_pathwise_equivalence() -> None:
    location = symbol_location(SYMS, "ScaleFirstThreeSpriteColumnsByTwo")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    values = _inputs()
    assert_pathwise_equivalent(
        _assembly(values), _native(values),
        (*REGISTERS, "source", "destination", "iterations", "pixel_calls",
         "calls"),
    )
