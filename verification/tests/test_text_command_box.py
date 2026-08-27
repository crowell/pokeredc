from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.registers import (
    REGISTERS,
    assembly_registers,
    native_registers,
    set_assembly_registers,
    store_native_registers,
    symbolic_registers,
)
from verification.harness.rom import linked_bytes, rom_window, symbol_location

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMS = ROOT / "pokered.sym"
NS = 0x100000
NM = 0x200000
STACK = 0xD000
TEXT = 0xD360
TILEMAP = 0xC3A0
TILEMAP_SIZE = 360
CONT = 0x1B55
EXPECTED = bytes.fromhex("e12a5f2a572a472a4fe5626bcd2219e118cb")
CALL_SIZE = len(REGISTERS) + TILEMAP_SIZE


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
    operands: claripy.ast.BV
    tilemap: claripy.ast.BV
    call_input: claripy.ast.BV
    call_count: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def inputs(tag: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(tag)
    values["operands"] = claripy.BVS(f"{tag}_operands", 32)
    values["tilemap"] = claripy.BVS(f"{tag}_tilemap", TILEMAP_SIZE * 8)
    values["post_tilemap"] = claripy.BVS(
        f"{tag}_post_tilemap", TILEMAP_SIZE * 8
    )
    for register in REGISTERS:
        values[f"post_{register}"] = (
            claripy.Concat(
                claripy.BVS(f"{tag}_post_flags", 4), claripy.BVV(0, 4)
            )
            if register == "f"
            else claripy.BVS(f"{tag}_post_{register}", 8)
        )
    return values


def setup(state, values, base: int) -> None:
    state.memory.store(base + TEXT, values["operands"])
    state.memory.store(base + TILEMAP, values["tilemap"])
    low = values["operands"][31:24]
    high = values["operands"][23:16]
    height = values["operands"][15:8]
    width = values["operands"][7:0]
    address = claripy.Concat(high, low)
    last = (
        claripy.ZeroExt(8, address)
        + claripy.ZeroExt(16, height + 1) * 20
        + claripy.ZeroExt(16, width)
        + 1
    )
    state.solver.add(
        address >= TILEMAP,
        address < TILEMAP + TILEMAP_SIZE,
        height >= 1,
        height <= 18,
        width >= 1,
        width <= 18,
        last < TILEMAP + TILEMAP_SIZE,
    )
    state.globals["call_input"] = claripy.BVV(0, CALL_SIZE * 8)
    state.globals["call_count"] = claripy.BVV(0, 8)
    state.globals["post_tilemap"] = values["post_tilemap"]
    for register in REGISTERS:
        state.globals[f"post_{register}"] = values[f"post_{register}"]


def apply_border(state, base: int, get_registers, set_registers) -> None:
    registers = get_registers()
    state.globals["call_input"] = claripy.Concat(
        *(registers[name] for name in REGISTERS),
        state.memory.load(base + TILEMAP, TILEMAP_SIZE),
    )
    state.globals["call_count"] += 1
    state.memory.store(base + TILEMAP, state.globals["post_tilemap"])
    for register in REGISTERS:
        registers[register] = state.globals[f"post_{register}"]
    set_registers(registers)


class PopHL(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__()
        self.next_address = next_address

    def run(self):
        sp = self.state.solver.eval(self.state.regs.sp)
        registers = assembly_registers(self.state)
        registers["l"] = self.state.memory.load(sp, 1)
        registers["h"] = self.state.memory.load(sp + 1, 1)
        set_assembly_registers(self.state, registers)
        self.state.regs.sp = sp + 2
        self.jump(self.next_address)


class PushHL(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__()
        self.next_address = next_address

    def run(self):
        sp = self.state.solver.eval(self.state.regs.sp)
        registers = assembly_registers(self.state)
        self.state.memory.store(sp - 1, registers["h"])
        self.state.memory.store(sp - 2, registers["l"])
        self.state.regs.sp = sp - 2
        self.jump(self.next_address)


class LoadAAtHLIncrement(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__()
        self.next_address = next_address

    def run(self):
        registers = assembly_registers(self.state)
        pointer = claripy.Concat(registers["h"], registers["l"])
        registers["a"] = self.state.memory.load(pointer, 1)
        pointer += 1
        registers["h"] = pointer[15:8]
        registers["l"] = pointer[7:0]
        set_assembly_registers(self.state, registers)
        self.jump(self.next_address)


class CopyRegister(angr.SimProcedure):
    def __init__(self, destination: str, source: str, next_address: int):
        super().__init__()
        self.destination = destination
        self.source = source
        self.next_address = next_address

    def run(self):
        registers = assembly_registers(self.state)
        registers[self.destination] = registers[self.source]
        set_assembly_registers(self.state, registers)
        self.jump(self.next_address)


class AssemblyBorder(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__()
        self.next_address = next_address

    def run(self):
        apply_border(
            self.state,
            0,
            lambda: assembly_registers(self.state),
            lambda registers: set_assembly_registers(self.state, registers),
        )
        self.jump(self.next_address)


class NativeBorder(angr.SimProcedure):
    def run(self, pointer, memory):
        def get_registers():
            return {
                name: self.state.memory.load(pointer + index, 1)
                for index, name in enumerate(REGISTERS)
            }

        def set_registers(registers):
            self.state.memory.store(
                pointer, claripy.Concat(*(registers[name] for name in REGISTERS))
            )

        apply_border(self.state, NM, get_registers, set_registers)


class Jump(angr.SimProcedure):
    def run(self):
        self.jump(CONT)


def endpoint(state, base: int) -> Endpoint:
    registers = native_registers(state, NS) if base else assembly_registers(state)
    return Endpoint(
        **registers,
        operands=state.memory.load(base + TEXT, 4),
        tilemap=state.memory.load(base + TILEMAP, TILEMAP_SIZE),
        call_input=state.globals["call_input"],
        call_count=state.globals["call_count"],
        constraints=tuple(state.solver.constraints),
    )


def assembly(values) -> Endpoint:
    location = symbol_location(SYMS, "TextCommand_BOX")
    assert location.bank == 0
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    project = angr.Project(
        rom_window(ROM, 0),
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
    project.hook(base, PopHL(base + 1), length=1)
    for offset in (1, 3, 5, 7):
        project.hook(base + offset, LoadAAtHLIncrement(base + offset + 1), length=1)
    for offset, destination in ((2, "e"), (4, "d"), (6, "b"), (8, "c")):
        project.hook(
            base + offset, CopyRegister(destination, "a", base + offset + 1), length=1
        )
    project.hook(base + 9, PushHL(base + 10), length=1)
    project.hook(base + 10, CopyRegister("h", "d", base + 11), length=1)
    project.hook(base + 11, CopyRegister("l", "e", base + 12), length=1)
    project.hook(base + 12, AssemblyBorder(base + 15), length=3)
    project.hook(base + 15, PopHL(base + 16), length=1)
    project.hook(base + 16, Jump(), length=2)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.regs.sp = STACK - 2
    state.memory.store(STACK - 2, claripy.BVV(TEXT & 0xFF, 8))
    state.memory.store(STACK - 1, claripy.BVV(TEXT >> 8, 8))
    setup(state, values, 0)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=CONT)
    assert not manager.errored
    assert len(manager.found) == 1
    return endpoint(manager.found[0], 0)


def native(values) -> Endpoint:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_text_command_box")
    border = project.loader.find_symbol("port_text_box_border")
    assert function is not None and border is not None
    project.hook(border.rebased_addr, NativeBorder())
    state = project.factory.call_state(function.rebased_addr, NS, NM)
    store_native_registers(state, NS, values)
    state.memory.store(NS + 6, claripy.BVV(TEXT >> 8, 8))
    state.memory.store(NS + 7, claripy.BVV(TEXT & 0xFF, 8))
    setup(state, values, NM)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    return endpoint(manager.deadended[0], NM)


def assert_equal(solver, left, right, label: str) -> None:
    difference = left != right
    if not claripy.is_false(difference) and solver.satisfiable(
        extra_constraints=(difference,)
    ):
        raise AssertionError(f"{label} differs")


def assert_chunks(solver, left, right, bits: int, label: str) -> None:
    for offset in range(0, bits, 64):
        high = bits - 1 - offset
        low = max(0, high - 63)
        assert_equal(solver, left[high:low], right[high:low], f"{label} {low}:{high}")


def assert_equivalent(left: Endpoint, right: Endpoint) -> None:
    solver = claripy.Solver()
    solver.add(left.constraints)
    solver.add(right.constraints)
    assert solver.satisfiable()
    for name in (*REGISTERS, "operands", "call_count"):
        assert_equal(solver, getattr(left, name), getattr(right, name), name)
    assert_chunks(solver, left.tilemap, right.tilemap, TILEMAP_SIZE * 8, "tilemap")
    assert_chunks(
        solver, left.call_input, right.call_input, CALL_SIZE * 8, "call_input"
    )
    assert solver.is_true(left.call_count == 1)
    assert solver.is_true(right.call_count == 1)


@pytest.mark.skipif(
    not ELF.exists() or not ROM.exists() or not SYMS.exists(), reason="build"
)
def test_text_command_box_pathwise_equivalence():
    values = inputs("text_command_box")
    assert_equivalent(assembly(values), native(values))
