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
from verification.harness.rom import collect_returns, rom_window, symbol_location

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xEFFF
DESTINATION = 0xC400
CONT_CHAR_TEXT = 0x1A8C
CONT_FAR_TEXT = 0x66A3
W_LINK_STATE = 0xD12B
ARROW_SLOT = 0xC4F2
W_LETTER_PRINTING_DELAY_FLAGS = 0xD358
TX_END = 0x50


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
    memory: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class LoadHL(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.hl = claripy.BVV(CONT_CHAR_TEXT, 16)
        self.jump(self.state.addr + 3)


class ProcessorBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        # Model the complete nested processor on the fixed far stream: its
        # terminal TX_END restores the original delay-flags A/F pair.
        self.state.regs.a = self.state.memory.load(W_LETTER_PRINTING_DELAY_FLAGS, 1)
        self.jump(self.state.addr + 3)


class PushDE(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        sp = self.state.regs.sp - 2
        self.state.memory.store(sp, self.state.regs.e, endness="Iend_LE")
        self.state.memory.store(sp + 1, self.state.regs.d, endness="Iend_LE")
        self.state.regs.sp = sp
        self.jump(self.state.addr + 1)


class PopDE(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        sp = self.state.regs.sp
        self.state.regs.e = self.state.memory.load(sp, 1)
        self.state.regs.d = self.state.memory.load(sp + 1, 1)
        self.state.regs.sp = sp + 2
        self.jump(self.state.addr + 1)


class IncrementDE(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.de = self.state.regs.de + 1
        self.jump(self.state.addr + 1)


class Continuation(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.jump(RETURN)


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    return symbolic_registers(prefix)


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        state.memory.load(base + DESTINATION, 1),
        *(state.memory.load(base + CONT_CHAR_TEXT + i, 1) for i in range(5)),
        state.memory.load(base + W_LINK_STATE, 1),
        state.memory.load(base + ARROW_SLOT, 1),
    )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "ContText")
    assert location.address == 0x1A7C
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    q = location.address
    project.hook(q, PushDE(), length=1)
    project.hook(q + 3, LoadHL(), length=3)
    project.hook(q + 6, ProcessorBoundary(), length=3)
    project.hook(q + 11, PopDE(), length=1)
    project.hook(q + 12, IncrementDE(), length=1)
    project.hook(q + 13, Continuation(), length=3)
    state = project.factory.blank_state(addr=q)
    set_assembly_registers(state, values)
    state.regs.sp = STACK
    state.memory.store(DESTINATION, values["a"])
    state.memory.store(W_LINK_STATE, claripy.BVV(0, 8))
    state.memory.store(ARROW_SLOT, claripy.BVV(0x7F, 8))
    state.memory.store(W_LETTER_PRINTING_DELAY_FLAGS, values["a"])
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    return [
        Endpoint(**assembly_registers(end), memory=_memory(end, 0),
                 constraints=tuple(end.solver.constraints))
        for end in collect_returns(project, state, RETURN)
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_cont_text_handler")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, values["d"])
    state.memory.store(NATIVE_STATE + 9, values["e"])
    state.memory.store(NATIVE_MEMORY + DESTINATION, values["a"])
    state.memory.store(NATIVE_MEMORY + W_LINK_STATE, claripy.BVV(0, 8))
    state.memory.store(NATIVE_MEMORY + ARROW_SLOT, claripy.BVV(0x7F, 8))
    state.memory.store(NATIVE_MEMORY + W_LETTER_PRINTING_DELAY_FLAGS, values["a"])
    state.memory.store(NATIVE_MEMORY + CONT_FAR_TEXT, claripy.BVV(TX_END, 8))
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [
        Endpoint(**native_registers(end, NATIVE_STATE), memory=_memory(end, NATIVE_MEMORY),
                 constraints=tuple(end.solver.constraints))
        for end in manager.deadended
    ]


@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_cont_text_handler_pathwise_equivalence() -> None:
    values = _inputs("cont_text_handler")
    values["h"] = claripy.BVV(DESTINATION >> 8, 8)
    values["l"] = claripy.BVV(DESTINATION & 0xFF, 8)
    values["d"] = claripy.BVS("cont_text_handler_saved_d", 8)
    values["e"] = claripy.BVS("cont_text_handler_saved_e", 8)
    assert_pathwise_equivalent(
        _assembly(values), _native(values), (*REGISTERS, "memory")
    )
