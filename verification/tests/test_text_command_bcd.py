from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS, assembly_registers, native_registers, set_assembly_registers, store_native_registers, symbolic_registers
from verification.harness.rom import linked_bytes, rom_window, symbol_location

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMS = ROOT / "pokered.sym"
NS = 0x100000
NM = 0x200000
STACK = 0xd000
TEXTPTR = 0xd360
CONT = 0x1b55
HANDLER = 0x1ba5
EXPECTED = bytes.fromhex("e12a5f2a572ae560694fcdcd15444de1189e")


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
    call_input: claripy.ast.BV
    call_count: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def inputs(tag: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(tag)
    values["operands"] = claripy.BVS(f"{tag}_operands", 24)
    for register in REGISTERS:
        if register == "f":
            values[f"post_{register}"] = claripy.Concat(
                claripy.BVS(f"{tag}_post_flags", 4), claripy.BVV(0, 4)
            )
        else:
            values[f"post_{register}"] = claripy.BVS(
                f"{tag}_post_{register}", 8
            )
    return values


def setup(state, values: dict[str, claripy.ast.BV], native: bool) -> None:
    base = NM if native else 0
    state.memory.store(base + TEXTPTR, values["operands"])
    state.globals["call_input"] = None
    state.globals["call_count"] = claripy.BVV(0, 8)
    for register in REGISTERS:
        state.globals[f"post_{register}"] = values[f"post_{register}"]


class PopHL(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next = next_address

    def run(self) -> None:
        sp = self.state.solver.eval(self.state.regs.sp)
        registers = assembly_registers(self.state)
        registers["l"] = self.state.memory.load(sp, 1)
        registers["h"] = self.state.memory.load(sp + 1, 1)
        set_assembly_registers(self.state, registers)
        self.state.regs.sp = claripy.BVV(sp + 2, 16)
        self.jump(self._next)


class PushHL(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next = next_address

    def run(self) -> None:
        sp = self.state.solver.eval(self.state.regs.sp)
        registers = assembly_registers(self.state)
        self.state.memory.store(sp - 1, registers["h"])
        self.state.memory.store(sp - 2, registers["l"])
        self.state.regs.sp = claripy.BVV(sp - 2, 16)
        self.jump(self._next)


class LoadAAtHLIncrement(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next = next_address

    def run(self) -> None:
        registers = assembly_registers(self.state)
        pointer = claripy.Concat(registers["h"], registers["l"])
        registers["a"] = self.state.memory.load(pointer, 1)
        pointer += 1
        registers["h"] = pointer[15:8]
        registers["l"] = pointer[7:0]
        set_assembly_registers(self.state, registers)
        self.jump(self._next)


class CopyRegister(angr.SimProcedure):
    def __init__(self, destination: str, source: str, next_address: int) -> None:
        super().__init__()
        self._destination = destination
        self._source = source
        self._next = next_address

    def run(self) -> None:
        registers = assembly_registers(self.state)
        registers[self._destination] = registers[self._source]
        set_assembly_registers(self.state, registers)
        self.jump(self._next)


class AssemblyPrintBCDNumber(angr.SimProcedure):
    """Complete proven-callee boundary at the handler's call site."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next = next_address

    def run(self) -> None:
        registers = assembly_registers(self.state)
        self.state.globals["call_input"] = claripy.Concat(
            *(registers[name] for name in REGISTERS)
        )
        self.state.globals["call_count"] += 1
        for name in REGISTERS:
            registers[name] = self.state.globals[f"post_{name}"]
        set_assembly_registers(self.state, registers)
        self.jump(self._next)


class NativePrintBCDNumber(angr.SimProcedure):
    """Matching boundary at the real C callee entry."""

    def run(self, registers, memory) -> None:
        del memory
        self.state.globals["call_input"] = self.state.memory.load(registers, 8)
        self.state.globals["call_count"] += 1
        self.state.memory.store(
            registers,
            claripy.Concat(
                *(self.state.globals[f"post_{name}"] for name in REGISTERS)
            ),
        )


class Jump(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__()
        self._target = target

    def run(self) -> None:
        self.jump(self._target)


def endpoint(state, native: bool) -> Endpoint:
    registers = native_registers(state, NS) if native else assembly_registers(state)
    base = NM if native else 0
    return Endpoint(
        **registers,
        operands=state.memory.load(base + TEXTPTR, 3),
        call_input=state.globals["call_input"],
        call_count=state.globals["call_count"],
        constraints=tuple(state.solver.constraints),
    )


def assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMS, "TextCommand_BCD")
    next_command = symbol_location(SYMS, "NextTextCommand")
    assert location.bank == 0 and location.address == HANDLER
    assert next_command.address == CONT
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
    project.hook(base + 0x00, PopHL(base + 0x01), length=1)
    project.hook(base + 0x01, LoadAAtHLIncrement(base + 0x02), length=1)
    project.hook(base + 0x02, CopyRegister("e", "a", base + 0x03), length=1)
    project.hook(base + 0x03, LoadAAtHLIncrement(base + 0x04), length=1)
    project.hook(base + 0x04, CopyRegister("d", "a", base + 0x05), length=1)
    project.hook(base + 0x05, LoadAAtHLIncrement(base + 0x06), length=1)
    project.hook(base + 0x06, PushHL(base + 0x07), length=1)
    project.hook(base + 0x07, CopyRegister("h", "b", base + 0x08), length=1)
    project.hook(base + 0x08, CopyRegister("l", "c", base + 0x09), length=1)
    project.hook(base + 0x09, CopyRegister("c", "a", base + 0x0a), length=1)
    project.hook(base + 0x0a, AssemblyPrintBCDNumber(base + 0x0d), length=3)
    project.hook(base + 0x0d, CopyRegister("b", "h", base + 0x0e), length=1)
    project.hook(base + 0x0e, CopyRegister("c", "l", base + 0x0f), length=1)
    project.hook(base + 0x0f, PopHL(base + 0x10), length=1)
    project.hook(base + 0x10, Jump(CONT), length=2)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    setup(state, values, False)
    stack = STACK - 2
    state.regs.sp = stack
    state.memory.store(stack, claripy.BVV(TEXTPTR & 0xff, 8))
    state.memory.store(stack + 1, claripy.BVV(TEXTPTR >> 8, 8))
    manager = project.factory.simulation_manager(state)
    manager.explore(find=CONT, num_find=1)
    assert not manager.errored and len(manager.found) == 1
    return [endpoint(end, False) for end in manager.found]


def native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    callee = project.loader.find_symbol("port_print_bcd_number")
    function = project.loader.find_symbol("port_text_command_bcd")
    assert callee is not None and function is not None
    project.hook(callee.rebased_addr, NativePrintBCDNumber())
    state = project.factory.call_state(function.rebased_addr, NS, NM)
    store_native_registers(state, NS, values)
    state.memory.store(NS + 6, claripy.BVV(TEXTPTR >> 8, 8))
    state.memory.store(NS + 7, claripy.BVV(TEXTPTR & 0xff, 8))
    setup(state, values, True)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [endpoint(end, True) for end in manager.deadended]


@pytest.mark.skipif(
    not ELF.exists() or not ROM.exists() or not SYMS.exists(), reason="build"
)
def test_text_command_bcd_pathwise_equivalence() -> None:
    values = inputs("text_command_bcd")
    assert_pathwise_equivalent(
        assembly(values),
        native(values),
        (*REGISTERS, "operands", "call_input", "call_count"),
    )
