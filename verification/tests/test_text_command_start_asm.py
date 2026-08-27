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

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
SENTINEL = 0xFFFF

H_JOYHELD = 0xFFB4
W_STATUSFLAGS5 = 0xD730
W_JOYIGNORE = 0xCD6B

NEXT_TEXT_COMMAND = 0x1B55

HANDLER_EXPECTED = bytes.fromhex("e111551bd5e9")


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
    joy_held: claripy.ast.BV
    status: claripy.ast.BV
    ignore: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


MEMORY_INPUTS = (
    ("joy_held", H_JOYHELD),
    ("status", W_STATUSFLAGS5),
    ("ignore", W_JOYIGNORE),
)


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    # The popped text pointer is opaque to the trampoline: it is read off the
    # stack and passed through into HL unchanged. Shared symbolically so the
    # proof holds for every text-pointer value, on both sides.
    values["pushed_hl"] = claripy.BVS(f"{prefix}_pushed_hl", 16)
    for name, _address in MEMORY_INPUTS:
        values[name] = claripy.BVS(f"{prefix}_{name}", 8)
    return values


def _setup(state: angr.SimState, values: dict[str, claripy.ast.BV], native: bool) -> None:
    base = NATIVE_MEMORY if native else 0
    for name, address in MEMORY_INPUTS:
        state.memory.store(base + address, values[name])


def _endpoint(state: angr.SimState, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    registers = (
        native_registers(state, NATIVE_STATE) if native else assembly_registers(state)
    )
    return Endpoint(
        **registers,
        joy_held=state.memory.load(base + H_JOYHELD, 1),
        status=state.memory.load(base + W_STATUSFLAGS5, 1),
        ignore=state.memory.load(base + W_JOYIGNORE, 1),
        constraints=tuple(state.solver.constraints),
    )


class PopHL(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        sp = self.state.solver.eval(self.state.regs.sp)
        self.state.regs.l = self.state.memory.load(sp, 1)
        self.state.regs.h = self.state.memory.load(sp + 1, 1)
        self.state.regs.hl = claripy.Concat(self.state.regs.h, self.state.regs.l)
        self.state.regs.sp = claripy.BVV(sp + 2, 16)
        self.jump(self.next_address)


class PushDE(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        sp = self.state.solver.eval(self.state.regs.sp)
        self.state.memory.store(sp - 1, self.state.regs.d)
        self.state.memory.store(sp - 2, self.state.regs.e)
        self.state.regs.sp = claripy.BVV(sp - 2, 16)
        self.jump(self.next_address)


class LoadDEImmediate(angr.SimProcedure):
    def __init__(self, value: int, next_address: int) -> None:
        super().__init__()
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.d = claripy.BVV(self.value >> 8, 8)
        self.state.regs.e = claripy.BVV(self.value & 0xFF, 8)
        self.jump(self.next_address)


class JmpHL(angr.SimProcedure):
    """Terminal of the trampoline: it jumps to the embedded assembly at HL.
    The embedded code is a boundary (arbitrary, out of unit scope); we capture
    the trampoline's observable setup and stop at the sentinel continuation."""

    def __init__(self, terminal: int) -> None:
        super().__init__()
        self.terminal = terminal

    def run(self) -> None:  # type: ignore[override]
        self.jump(self.terminal)


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    handler = symbol_location(SYMBOLS, "TextCommand_START_ASM")
    assert handler.bank == 0
    assert handler.address == 0x1BF9
    assert linked_bytes(ROM, handler, len(HANDLER_EXPECTED)) == HANDLER_EXPECTED

    project = angr.Project(
        rom_window(ROM, handler.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": handler.address,
        },
    )
    base = handler.address
    project.hook(base + 0, PopHL(base + 1), length=1)
    project.hook(base + 1, LoadDEImmediate(NEXT_TEXT_COMMAND, base + 4), length=3)
    project.hook(base + 4, PushDE(base + 5), length=1)
    project.hook(base + 5, JmpHL(SENTINEL), length=1)

    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _setup(state, values, native=False)
    # The dispatcher pushes the text pointer before entering the handler.
    state.regs.sp = STACK - 2
    state.memory.store(STACK - 2, values["pushed_hl"][7:0])
    state.memory.store(STACK - 1, values["pushed_hl"][15:8])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=SENTINEL)
    if manager.errored:
        for es in manager.errored:
            print("ASM ERRORED:", es.error)
    assert len(manager.found) == 1, len(manager.found)
    assert not manager.errored
    return [_endpoint(final, native=False) for final in manager.found]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_text_command_start_asm")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, values, native=True)
    # The dispatcher passes the text pointer in HL on entry.
    state.memory.store(NATIVE_STATE + 6, values["pushed_hl"][15:8])
    state.memory.store(NATIVE_STATE + 7, values["pushed_hl"][7:0])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert len(manager.deadended) == 1, len(manager.deadended)
    return [_endpoint(final, native=True) for final in manager.deadended]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(
    not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`"
)
def test_text_command_start_asm_pathwise_equivalence() -> None:
    values = _inputs("text_command_start_asm")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (
            *REGISTERS,
            "joy_held",
            "status",
            "ignore",
        ),
    )
