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
STACK = 0xD000
RETURN = 0xFFFF
BUFFER0 = 0xA000
BUFFER1 = 0xA188
BUFFER2 = 0xA310
COUNTER = 0xFF8B
EXPECTED = bytes.fromhex("1103a22187a1cd7d7ecd557e118ba3210fa3cd7d7e")


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
    counter: claripy.ast.BV
    buffer0: claripy.ast.BV
    buffer1: claripy.ast.BV
    buffer2: claripy.ast.BV
    last_iterations: claripy.ast.BV
    first_iterations: claripy.ast.BV
    first_pixel_calls: claripy.ast.BV
    last_calls: claripy.ast.BV
    first_calls: claripy.ast.BV
    call_order: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _register_vector(registers: dict[str, claripy.ast.BV]) -> claripy.ast.BV:
    return claripy.Concat(*(registers[name] for name in REGISTERS))


def _return_target(state: angr.SimState) -> claripy.ast.BV:
    target = state.memory.load(state.regs.sp, 2, endness="Iend_LE")
    state.regs.sp += 2
    return target


def _bytes(value: claripy.ast.BV, count: int) -> list[claripy.ast.BV]:
    return [value[(count - index) * 8 - 1:(count - index - 1) * 8]
            for index in range(count)]


def _duplicate(value: claripy.ast.BV) -> claripy.ast.BV:
    pixels = value & 0x0F
    return (
        (pixels & 1) * 3
        | (pixels & 2) * 6
        | (pixels & 4) * 12
        | (pixels & 8) * 24
    )


def _last_registers(
    registers: dict[str, claripy.ast.BV]
) -> dict[str, claripy.ast.BV]:
    de = claripy.Concat(registers["d"], registers["e"]) - 32
    hl = claripy.Concat(registers["h"], registers["l"]) - 56
    last_hl = claripy.Concat(registers["h"], registers["l"]) - 54
    addend = last_hl - 1
    carry = claripy.ZeroExt(1, addend) + claripy.BVV(0xFFFF, 17)
    output = dict(registers)
    output["a"] = claripy.BVV(0, 8)
    output["f"] = claripy.BVV(0xC0, 8) | claripy.If(
        carry[16] == 1, claripy.BVV(0x10, 8), claripy.BVV(0, 8)
    )
    output["b"] = claripy.BVV(0xFF, 8)
    output["c"] = claripy.BVV(0xFF, 8)
    output["d"] = de[15:8]
    output["e"] = de[7:0]
    output["h"] = hl[15:8]
    output["l"] = hl[7:0]
    return output


def _first_registers(
    registers: dict[str, claripy.ast.BV]
) -> dict[str, claripy.ast.BV]:
    de = claripy.Concat(registers["d"], registers["e"]) - 96
    original_hl = claripy.Concat(registers["h"], registers["l"])
    before_final_add = original_hl - 280
    carry = claripy.ZeroExt(1, before_final_add) + claripy.BVV(0xFFC8, 17)
    hl = original_hl - 336
    output = dict(registers)
    output["a"] = claripy.BVV(1, 8)
    output["f"] = claripy.BVV(0xC0, 8) | claripy.If(
        carry[16] == 1, claripy.BVV(0x10, 8), claripy.BVV(0, 8)
    )
    output["b"] = claripy.BVV(0, 8)
    output["c"] = claripy.BVV(0xC8, 8)
    output["d"] = de[15:8]
    output["e"] = de[7:0]
    output["h"] = hl[15:8]
    output["l"] = hl[7:0]
    return output


def _last_destination(source: claripy.ast.BV) -> claripy.ast.BV:
    output = []
    for byte in _bytes(source, 28):
        duplicated = _duplicate(byte >> 4)
        output.extend((duplicated, duplicated))
    return claripy.Concat(*output)


def _first_destination(source: claripy.ast.BV) -> claripy.ast.BV:
    source_bytes = _bytes(source, 84)
    output = [claripy.BVV(0, 8) for _ in range(336)]
    for column in range(3):
        for row in range(28):
            byte = source_bytes[column * 28 + row]
            low = _duplicate(byte)
            high = _duplicate(byte >> 4)
            index = column * 112 + row * 2
            output[index] = low
            output[index + 1] = low
            output[index + 56] = high
            output[index + 57] = high
    return claripy.Concat(*output)


def _record(state: angr.SimState, kind: int, snapshot: claripy.ast.BV) -> None:
    key = "last_calls" if kind == 1 else "first_calls"
    index_key = "last_count" if kind == 1 else "first_count"
    index = state.globals[index_key]
    state.globals[key][index] = snapshot
    state.globals[index_key] = index + 1
    state.globals["order"].append(claripy.BVV(kind, 8))


class AssemblyLast(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        registers = assembly_registers(self.state)
        de = claripy.Concat(registers["d"], registers["e"])
        hl = claripy.Concat(registers["h"], registers["l"])
        source = claripy.Concat(*(self.state.memory.load(de - i, 1) for i in range(28)))
        destination = claripy.Concat(
            *(self.state.memory.load(hl - i, 1) for i in range(56))
        )
        _record(self.state, 1, claripy.Concat(
            _register_vector(registers), self.state.memory.load(COUNTER, 1),
            source, destination,
        ))
        output = _last_registers(registers)
        written = _last_destination(source)
        for index, byte in enumerate(_bytes(written, 56)):
            self.state.memory.store(hl - index, byte)
        self.state.memory.store(COUNTER, claripy.BVV(0, 8))
        set_assembly_registers(self.state, output)
        self.state.globals["last_iterations"].append(claripy.BVV(28, 8))
        self.jump(_return_target(self.state))


class NativeLast(angr.SimProcedure):
    def run(self, address: claripy.ast.BV) -> None:  # type: ignore[override]
        registers = {
            name: self.state.memory.load(address + offset, 1)
            for offset, name in enumerate(REGISTERS)
        }
        source = self.state.memory.load(address + 9, 28)
        destination = self.state.memory.load(address + 37, 56)
        _record(self.state, 1, claripy.Concat(
            _register_vector(registers), self.state.memory.load(address + 8, 1),
            source, destination,
        ))
        self.state.memory.store(address, _register_vector(_last_registers(registers)))
        self.state.memory.store(address + 8, claripy.BVV(0, 8))
        self.state.memory.store(address + 37, _last_destination(source))
        self.state.memory.store(address + 93, claripy.BVV(28, 8))


class AssemblyFirst(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        registers = assembly_registers(self.state)
        de = claripy.Concat(registers["d"], registers["e"])
        hl = claripy.Concat(registers["h"], registers["l"])
        source = claripy.Concat(*(
            self.state.memory.load(de - column * 32 - row, 1)
            for column in range(3) for row in range(28)
        ))
        destination = claripy.Concat(
            *(self.state.memory.load(hl - i, 1) for i in range(336))
        )
        _record(self.state, 2, claripy.Concat(
            _register_vector(registers), source, destination,
        ))
        written = _first_destination(source)
        for index, byte in enumerate(_bytes(written, 336)):
            self.state.memory.store(hl - index, byte)
        set_assembly_registers(self.state, _first_registers(registers))
        self.state.globals["first_iterations"].append(claripy.BVV(84, 8))
        self.state.globals["first_pixel_calls"].append(claripy.BVV(168, 8))
        self.jump(_return_target(self.state))


class NativeFirst(angr.SimProcedure):
    def run(self, address: claripy.ast.BV) -> None:  # type: ignore[override]
        registers = {
            name: self.state.memory.load(address + offset, 1)
            for offset, name in enumerate(REGISTERS)
        }
        source = self.state.memory.load(address + 8, 84)
        destination = self.state.memory.load(address + 92, 336)
        _record(self.state, 2, claripy.Concat(
            _register_vector(registers), source, destination,
        ))
        self.state.memory.store(address, _register_vector(_first_registers(registers)))
        self.state.memory.store(address + 92, _first_destination(source))
        self.state.memory.store(address + 428, claripy.BVV(84, 8))
        self.state.memory.store(address + 429, claripy.BVV(168, 8))


def _inputs() -> dict[str, claripy.ast.BV]:
    values = symbolic_registers("scale_sprite_by_two")
    values["counter"] = claripy.BVS("scale_sprite_by_two_counter", 8)
    for index in range(3):
        values[f"buffer{index}"] = claripy.BVS(
            f"scale_sprite_by_two_buffer{index}", 392 * 8
        )
    values["last_iterations"] = claripy.BVS("scale_sprite_last_iterations", 16)
    values["first_iterations"] = claripy.BVS("scale_sprite_first_iterations", 16)
    values["first_pixel_calls"] = claripy.BVS("scale_sprite_first_calls", 16)
    return values


def _setup_globals(state: angr.SimState) -> None:
    state.globals["last_calls"] = [claripy.BVV(0, 744) for _ in range(2)]
    state.globals["first_calls"] = [claripy.BVV(0, 3424) for _ in range(2)]
    state.globals["last_count"] = 0
    state.globals["first_count"] = 0
    state.globals["order"] = []
    state.globals["last_iterations"] = []
    state.globals["first_iterations"] = []
    state.globals["first_pixel_calls"] = []


@cache
def _assembly_project() -> tuple[angr.Project, int]:
    location = symbol_location(SYMS, "ScaleSpriteByTwo")
    last = symbol_location(SYMS, "ScaleLastSpriteColumnByTwo")
    first = symbol_location(SYMS, "ScaleFirstThreeSpriteColumnsByTwo")
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    project.hook(last.address, AssemblyLast())
    project.hook(first.address, AssemblyFirst())
    return project, location.address


@cache
def _native_project() -> tuple[angr.Project, int]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_scale_sprite_by_two_private")
    last = project.loader.find_symbol("port_scale_last_sprite_column_by_two_private")
    first = project.loader.find_symbol(
        "port_scale_first_three_sprite_columns_by_two_private"
    )
    assert function is not None and last is not None and first is not None
    project.hook(last.rebased_addr, NativeLast())
    project.hook(first.rebased_addr, NativeFirst())
    return project, function.rebased_addr


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, function = _assembly_project()
    state = project.factory.blank_state(addr=function)
    set_assembly_registers(state, values)
    state.memory.store(COUNTER, values["counter"])
    state.memory.store(BUFFER0, values["buffer0"])
    state.memory.store(BUFFER1, values["buffer1"])
    state.memory.store(BUFFER2, values["buffer2"])
    _setup_globals(state)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    ends = collect_returns(project, state, RETURN)
    assert len(ends) == 1
    end = ends[0]
    return [Endpoint(
        **assembly_registers(end),
        counter=end.memory.load(COUNTER, 1),
        buffer0=end.memory.load(BUFFER0, 392),
        buffer1=end.memory.load(BUFFER1, 392),
        buffer2=end.memory.load(BUFFER2, 392),
        last_iterations=claripy.Concat(*end.globals["last_iterations"]),
        first_iterations=claripy.Concat(*end.globals["first_iterations"]),
        first_pixel_calls=claripy.Concat(*end.globals["first_pixel_calls"]),
        last_calls=claripy.Concat(*end.globals["last_calls"]),
        first_calls=claripy.Concat(*end.globals["first_calls"]),
        call_order=claripy.Concat(*end.globals["order"]),
        constraints=tuple(end.solver.constraints),
    )]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, function = _native_project()
    state = project.factory.call_state(function, NS)
    store_native_registers(state, NS, values)
    state.memory.store(NS + 8, values["counter"])
    state.memory.store(NS + 9, values["buffer0"])
    state.memory.store(NS + 401, values["buffer1"])
    state.memory.store(NS + 793, values["buffer2"])
    state.memory.store(NS + 1185, values["last_iterations"])
    state.memory.store(NS + 1187, values["first_iterations"])
    state.memory.store(NS + 1189, values["first_pixel_calls"])
    _setup_globals(state)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    end = manager.deadended[0]
    return [Endpoint(
        **native_registers(end, NS),
        counter=end.memory.load(NS + 8, 1),
        buffer0=end.memory.load(NS + 9, 392),
        buffer1=end.memory.load(NS + 401, 392),
        buffer2=end.memory.load(NS + 793, 392),
        last_iterations=end.memory.load(NS + 1185, 2),
        first_iterations=end.memory.load(NS + 1187, 2),
        first_pixel_calls=end.memory.load(NS + 1189, 2),
        last_calls=claripy.Concat(*end.globals["last_calls"]),
        first_calls=claripy.Concat(*end.globals["first_calls"]),
        call_order=claripy.Concat(*end.globals["order"]),
        constraints=tuple(end.solver.constraints),
    )]


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(), reason="build")
def test_scale_sprite_by_two_pathwise_equivalence() -> None:
    location = symbol_location(SYMS, "ScaleSpriteByTwo")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    values = _inputs()
    assert_pathwise_equivalent(
        _assembly(values), _native(values),
        (*REGISTERS, "counter", "buffer0", "buffer1", "buffer2",
         "last_iterations", "first_iterations", "first_pixel_calls",
         "last_calls", "first_calls", "call_order"),
    )
