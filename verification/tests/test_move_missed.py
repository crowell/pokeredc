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
from verification.harness.sm83_shims import Sm83CpImmediate


ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xE000
RETURN = 0xFFFF
W_MOVE_DIDNT_MISS = 0xCCF4
W_TEXT_BOX_ID = 0xD125
BUT_IT_FAILED_TEXT = 0x7B59
EXPECTED = bytes.fromhex("1afe44d0c34e7b")


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
    conditional_call: claripy.ast.BV
    print_call: claripy.ast.BV
    trace: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _capture_assembly_registers(state: angr.SimState) -> claripy.ast.BV:
    registers = assembly_registers(state)
    return claripy.Concat(*(registers[name] for name in REGISTERS))


class LoadAtDe(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self.state.regs.de, 1)
        self.jump(self._continuation)


class ConditionalEntry(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["conditional_call"] = claripy.Concat(
            _capture_assembly_registers(self.state),
            self.state.memory.load(W_MOVE_DIDNT_MISS, 1),
        )
        self.state.globals["trace"] = claripy.BVV(1, 8)
        self.state.regs.a = self.state.memory.load(W_MOVE_DIDNT_MISS, 1)
        self.jump(self._continuation)


class AndA(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x50, 8),
            claripy.BVV(0x10, 8),
        )
        self.jump(self._continuation)


class AssemblyPrintFailure(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.globals["print_call"] = _capture_assembly_registers(self.state)
        self.state.globals["trace"] = claripy.BVV(2, 8)
        self.state.regs.h = BUT_IT_FAILED_TEXT >> 8
        self.state.regs.l = BUT_IT_FAILED_TEXT & 0xFF
        self.state.memory.store(W_TEXT_BOX_ID, claripy.BVV(1, 8))
        self.state.regs.b = 0xC4
        self.state.regs.c = 0xB9
        self.jump(RETURN)


class NativeConditional(angr.SimProcedure):
    def run(self, address: claripy.ast.BV) -> claripy.ast.BV:  # type: ignore[override]
        self.state.globals["conditional_call"] = self.state.memory.load(address, 9)
        self.state.globals["trace"] = claripy.BVV(1, 8)
        value = self.state.memory.load(address + 8, 1)
        flags = claripy.If(
            value == 0, claripy.BVV(0xA0, 8), claripy.BVV(0x20, 8)
        )
        self.state.memory.store(address, value)
        self.state.memory.store(address + 1, flags)
        return claripy.If(value == 0, claripy.BVV(1, 8), claripy.BVV(0, 8))


class NativePrintFailure(angr.SimProcedure):
    def run(
        self, address: claripy.ast.BV, memory: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        assert not memory.symbolic and self.state.solver.eval(memory) == NATIVE_MEMORY
        self.state.globals["print_call"] = self.state.memory.load(address, 8)
        self.state.globals["trace"] = claripy.BVV(2, 8)
        self.state.memory.store(address + 2, claripy.BVV(0xC4B9, 16))
        self.state.memory.store(address + 6, claripy.BVV(BUT_IT_FAILED_TEXT, 16))
        self.state.memory.store(memory + W_TEXT_BOX_ID, claripy.BVV(1, 8))


def _inputs(prefix: str, effect_address: int) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["d"] = claripy.BVV(effect_address >> 8, 8)
    values["e"] = claripy.BVV(effect_address & 0xFF, 8)
    values["move_effect"] = claripy.BVS(f"{prefix}_move_effect", 8)
    values["move_didnt_miss"] = claripy.BVS(f"{prefix}_move_didnt_miss", 8)
    values["text_box"] = claripy.BVS(f"{prefix}_text_box", 8)
    return values


def _setup(
    state: angr.SimState,
    values: dict[str, claripy.ast.BV],
    effect_address: int,
    native: bool,
) -> None:
    memory_base = NATIVE_MEMORY if native else 0
    state.memory.store(memory_base + effect_address, values["move_effect"])
    state.memory.store(
        memory_base + W_MOVE_DIDNT_MISS, values["move_didnt_miss"]
    )
    state.memory.store(memory_base + W_TEXT_BOX_ID, values["text_box"])
    state.globals["conditional_call"] = claripy.BVV(0, 72)
    state.globals["print_call"] = claripy.BVV(0, 64)
    state.globals["trace"] = claripy.BVV(0, 8)


def _endpoint(
    state: angr.SimState, effect_address: int, native: bool
) -> Endpoint:
    memory_base = NATIVE_MEMORY if native else 0
    registers = (
        native_registers(state, NATIVE_STATE)
        if native
        else assembly_registers(state)
    )
    return Endpoint(
        **registers,
        memory=claripy.Concat(
            state.memory.load(memory_base + effect_address, 1),
            state.memory.load(memory_base + W_MOVE_DIDNT_MISS, 1),
            state.memory.load(memory_base + W_TEXT_BOX_ID, 1),
        ),
        conditional_call=state.globals["conditional_call"],
        print_call=state.globals["print_call"],
        trace=state.globals["trace"],
        constraints=tuple(state.solver.constraints),
    )


@cache
def _assembly_project() -> tuple[angr.Project, int]:
    location = symbol_location(SYMS, "MoveMissed")
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
    conditional = symbol_location(SYMS, "ConditionalPrintButItFailed").address
    print_failure = symbol_location(SYMS, "PrintButItFailedText_").address
    project.hook(base, LoadAtDe(base + 1), length=1)
    project.hook(base + 1, Sm83CpImmediate(0x44, base + 3), length=2)
    project.hook(conditional, ConditionalEntry(conditional + 3), length=3)
    project.hook(conditional + 3, AndA(conditional + 4), length=1)
    project.hook(print_failure, AssemblyPrintFailure(), length=1)
    return project, base


@cache
def _native_project() -> tuple[angr.Project, int]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_move_missed")
    conditional = project.loader.find_symbol("port_conditional_print_but_it_failed")
    print_failure = project.loader.find_symbol("port_print_but_it_failed_text_")
    assert function is not None and conditional is not None and print_failure is not None
    project.hook(conditional.rebased_addr, NativeConditional())
    project.hook(print_failure.rebased_addr, NativePrintFailure())
    return project, function.rebased_addr


def _assembly(
    values: dict[str, claripy.ast.BV], effect_address: int
) -> list[Endpoint]:
    project, base = _assembly_project()
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _setup(state, values, effect_address, False)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    return [
        _endpoint(end, effect_address, False)
        for end in collect_returns(project, state, RETURN)
    ]


def _native(values: dict[str, claripy.ast.BV], effect_address: int) -> list[Endpoint]:
    project, function = _native_project()
    state = project.factory.call_state(function, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, values, effect_address, True)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [_endpoint(end, effect_address, True) for end in manager.deadended]


@pytest.mark.skipif(
    not ELF.exists() or not ROM.exists() or not SYMS.exists(), reason="build"
)
@pytest.mark.parametrize(
    "effect_address", (0xCFD3, 0xCFCD), ids=("player", "enemy")
)
def test_move_missed_pathwise_equivalence(effect_address: int) -> None:
    values = _inputs(f"move_missed_{effect_address:04x}", effect_address)
    assert_pathwise_equivalent(
        _assembly(values, effect_address),
        _native(values, effect_address),
        (*REGISTERS, "memory", "conditional_call", "print_call", "trace"),
    )
