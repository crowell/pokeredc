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
from verification.harness.rom import (
    linked_bytes,
    rom_window,
    sm83_flags_to_z80,
    symbol_location,
)
from verification.harness.sm83_shims import Sm83LoadAAtHlIncrement, Sm83SwapRegister

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
TEXT = 0xD360
SOURCE = 0xD100
DESTINATION = 0xC3A0
DESTINATION_SIZE = 7
CONTINUE = 0x1B55

H_PAST_LEADING_ZEROES = 0xFF95
HRAM_SIZE = 10
EXPECTED = bytes.fromhex(
    "e12a5f2a572ae5606947e60f4f78e6f0cb37cbf747cd5f3c444de1c3551b"
)
FORMATS = tuple((byte_count, digits) for byte_count in (1, 2, 3) for digits in range(2, 8))


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
    source: claripy.ast.BV
    hram: claripy.ast.BV
    destination: claripy.ast.BV
    call_input: claripy.ast.BV
    call_count: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class PopPair(angr.SimProcedure):
    def __init__(self, high: str, low: str, next_address: int):
        super().__init__()
        self.high = high
        self.low = low
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.low, self.state.memory.load(self.state.regs.sp, 1))
        setattr(
            self.state.regs,
            self.high,
            self.state.memory.load(self.state.regs.sp + 1, 1),
        )
        self.state.regs.sp += 2
        self.jump(self.next_address)


class PushPair(angr.SimProcedure):
    def __init__(self, high: str, low: str, next_address: int):
        super().__init__()
        self.high = high
        self.low = low
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.sp -= 1
        self.state.memory.store(self.state.regs.sp, getattr(self.state.regs, self.high))
        self.state.regs.sp -= 1
        self.state.memory.store(self.state.regs.sp, getattr(self.state.regs, self.low))
        self.jump(self.next_address)


class CopyRegister(angr.SimProcedure):
    def __init__(self, destination: str, source: str, next_address: int):
        super().__init__()
        self.destination = destination
        self.source = source
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.destination, getattr(self.state.regs, self.source))
        self.jump(self.next_address)


class AndImmediate(angr.SimProcedure):
    """Correct SM83 AND: H is set, unlike the generic Z80 p-code model."""

    def __init__(self, value: int, next_address: int):
        super().__init__()
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a &= self.value
        self.state.regs.f = claripy.BVV(0x10, 8) | claripy.If(
            self.state.regs.a == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)
        )
        self.jump(self.next_address)


class SetBit(angr.SimProcedure):
    def __init__(self, bit: int, register: str, next_address: int):
        super().__init__()
        self.bit = bit
        self.register = register
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        setattr(
            self.state.regs,
            self.register,
            getattr(self.state.regs, self.register) | (1 << self.bit),
        )
        self.jump(self.next_address)


class AssemblyPrintNumber(angr.SimProcedure):
    """Complete proven PrintNumber boundary, including every ordered write."""

    def __init__(self, next_address: int, digits: int):
        super().__init__()
        self.next_address = next_address
        self.digits = digits

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        registers = assembly_registers(self.state)
        call_input = claripy.Concat(
            *(registers[register] for register in REGISTERS),
            self.state.memory.load(H_PAST_LEADING_ZEROES, HRAM_SIZE),
            self.state.memory.load(SOURCE, 3),
            self.state.memory.load(DESTINATION, DESTINATION_SIZE),
        )
        for count in range(1, self.digits + 1):
            end = self.state.copy()
            end.globals["call_input"] = call_input
            end.globals["call_count"] += 1
            end.add_constraints(end.globals["post_write_count"] == count)
            output_registers = {
                register: end.globals[f"post_{register}"] for register in REGISTERS
            }
            set_assembly_registers(end, output_registers)
            end.memory.store(H_PAST_LEADING_ZEROES, end.globals["post_hram"])
            for index in range(count):
                end.memory.store(
                    DESTINATION + index, end.globals[f"post_write_{index}"]
                )
            self.successors.add_successor(
                end, self.next_address, claripy.BoolV(True), "Ijk_Boring"
            )


class NativePrintNumber(angr.SimProcedure):
    def __init__(self, digits: int):
        super().__init__()
        self.digits = digits

    def run(self, number: claripy.ast.BV) -> None:  # type: ignore[override]
        self.state.globals["call_input"] = claripy.Concat(
            self.state.memory.load(number, 8),
            self.state.memory.load(number + 8, 10),
            self.state.memory.load(number + 18, 3),
            self.state.memory.load(NATIVE_MEMORY + DESTINATION, DESTINATION_SIZE),
        )
        self.state.globals["call_count"] += 1
        self.state.memory.store(
            number,
            claripy.Concat(
                *(self.state.globals[f"post_{register}"] for register in REGISTERS)
            ),
        )
        self.state.memory.store(number + 8, self.state.globals["post_hram"])
        self.state.memory.store(number + 29, claripy.BVV(1, 8))
        self.state.memory.store(number + 30, self.state.globals["post_write_count"])
        for index in range(DESTINATION_SIZE):
            self.state.memory.store(
                number + 31 + index, self.state.globals[f"post_write_{index}"]
            )
            self.state.memory.store(
                number + 38 + index, claripy.BVV(DESTINATION >> 8, 8)
            )
            self.state.memory.store(
                number + 45 + index,
                claripy.BVV((DESTINATION + index) & 0xFF, 8),
            )
        self.state.add_constraints(
            self.state.globals["post_write_count"] >= 1,
            self.state.globals["post_write_count"] <= self.digits,
        )


class Continue(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(CONTINUE)


def inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["h"] = claripy.BVV(TEXT >> 8, 8)
    values["l"] = claripy.BVV(TEXT & 0xFF, 8)
    values["b"] = claripy.BVV(DESTINATION >> 8, 8)
    values["c"] = claripy.BVV(DESTINATION & 0xFF, 8)
    values["source"] = claripy.BVS(f"{prefix}_source", 24)
    values["hram"] = claripy.BVS(f"{prefix}_hram", HRAM_SIZE * 8)
    values["destination"] = claripy.BVS(
        f"{prefix}_destination", DESTINATION_SIZE * 8
    )
    values["post_hram"] = claripy.BVS(f"{prefix}_post_hram", HRAM_SIZE * 8)
    values["post_write_count"] = claripy.BVS(f"{prefix}_post_write_count", 8)
    for register in REGISTERS:
        values[f"post_{register}"] = (
            claripy.Concat(
                claripy.BVS(f"{prefix}_post_flags", 4), claripy.BVV(0, 4)
            )
            if register == "f"
            else claripy.BVS(f"{prefix}_post_{register}", 8)
        )
    for index in range(DESTINATION_SIZE):
        values[f"post_write_{index}"] = claripy.BVS(
            f"{prefix}_post_write_{index}", 8
        )
    return values


def setup(
    state: angr.SimState,
    values: dict[str, claripy.ast.BV],
    byte_count: int,
    digits: int,
    base: int,
) -> None:
    operands = bytes((SOURCE & 0xFF, SOURCE >> 8, (digits << 4) | byte_count))
    state.memory.store(base + TEXT, operands)
    state.memory.store(base + SOURCE, values["source"])
    state.memory.store(base + H_PAST_LEADING_ZEROES, values["hram"])
    state.memory.store(base + DESTINATION, values["destination"])
    state.globals["call_input"] = claripy.BVV(0, (8 + 10 + 3 + 7) * 8)
    state.globals["call_count"] = claripy.BVV(0, 8)
    for key, value in values.items():
        if key.startswith("post_"):
            state.globals[key] = value
    state.solver.add(
        values["post_write_count"] >= 1,
        values["post_write_count"] <= digits,
    )


def endpoint(state: angr.SimState, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    registers = native_registers(state, NATIVE_STATE) if native else assembly_registers(state)
    return Endpoint(
        **registers,
        operands=state.memory.load(base + TEXT, 3),
        source=state.memory.load(base + SOURCE, 3),
        hram=state.memory.load(base + H_PAST_LEADING_ZEROES, HRAM_SIZE),
        destination=state.memory.load(base + DESTINATION, DESTINATION_SIZE),
        call_input=state.globals["call_input"],
        call_count=state.globals["call_count"],
        constraints=tuple(state.solver.constraints),
    )


def assembly(
    values: dict[str, claripy.ast.BV], byte_count: int, digits: int
) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "TextCommand_NUM")
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
    project.hook(base, PopPair("h", "l", base + 1), length=1)
    for offset in (1, 3, 5):
        project.hook(base + offset, Sm83LoadAAtHlIncrement(base + offset + 1), length=1)
    for offset, destination in ((2, "e"), (4, "d"), (9, "b"), (12, "c"), (20, "b"), (24, "b"), (25, "c")):
        source = "a" if offset in (2, 4, 9, 12, 20) else ("h" if offset == 24 else "l")
        project.hook(
            base + offset,
            CopyRegister(destination, source, base + offset + 1),
            length=1,
        )
    project.hook(base + 6, PushPair("h", "l", base + 7), length=1)
    project.hook(base + 7, CopyRegister("h", "b", base + 8), length=1)
    project.hook(base + 8, CopyRegister("l", "c", base + 9), length=1)
    project.hook(base + 10, AndImmediate(0x0F, base + 12), length=2)
    project.hook(base + 13, CopyRegister("a", "b", base + 14), length=1)
    project.hook(base + 14, AndImmediate(0xF0, base + 16), length=2)
    project.hook(base + 16, Sm83SwapRegister("a", base + 18), length=2)
    project.hook(base + 18, SetBit(6, "a", base + 20), length=2)
    project.hook(base + 21, AssemblyPrintNumber(base + 24, digits), length=3)
    project.hook(base + 26, PopPair("h", "l", base + 27), length=1)
    project.hook(base + 27, Continue(), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.regs.sp = STACK - 2
    state.memory.store(STACK - 2, claripy.BVV(TEXT & 0xFF, 8))
    state.memory.store(STACK - 1, claripy.BVV(TEXT >> 8, 8))
    setup(state, values, byte_count, digits, 0)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=CONTINUE)
    assert not manager.errored and len(manager.found) == digits
    return [endpoint(end, False) for end in manager.found]


def native(
    values: dict[str, claripy.ast.BV], byte_count: int, digits: int
) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_text_command_num")
    callee = project.loader.find_symbol("port_print_number")
    assert function is not None and callee is not None
    project.hook(callee.rebased_addr, NativePrintNumber(digits))
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    setup(state, values, byte_count, digits, NATIVE_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == digits
    return [endpoint(end, True) for end in manager.deadended]


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(), reason="build")
@pytest.mark.parametrize(
    "byte_count,digits",
    FORMATS,
    ids=lambda value: str(value),
)
def test_text_command_num_pathwise_equivalence(byte_count: int, digits: int) -> None:
    values = inputs(f"text_command_num_{byte_count}_{digits}")
    assert_pathwise_equivalent(
        assembly(values, byte_count, digits),
        native(values, byte_count, digits),
        (
            *REGISTERS,
            "operands",
            "source",
            "hram",
            "destination",
            "call_input",
            "call_count",
        ),
    )
