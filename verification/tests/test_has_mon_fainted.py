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
from verification.harness.sm83_shims import Sm83LoadAAtHlIncrement


ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xE000
RETURN = 0xFFFF
W_WHICH_POKEMON = 0xCF92
W_FIRST_MONS_NOT_OUT_YET = 0xD11D
W_PARTY_MON_1_HP = 0xD16C
W_TEXT_BOX_ID = 0xD125
PARTY_STRUCT_LENGTH = 0x2C
PARTY_COUNT = 6
EXPECTED = bytes.fromhex(
    "fa92cf216cd1012c00cd873a2ab6c0fa1dd1a7200621b44acd493cafc9"
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
    memory: claripy.ast.BV
    add_call: claripy.ast.BV
    print_call: claripy.ast.BV
    trace: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _register_bytes(state: angr.SimState) -> claripy.ast.BV:
    registers = assembly_registers(state)
    return claripy.Concat(*(registers[name] for name in REGISTERS))


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        state.memory.load(base + W_WHICH_POKEMON, 1),
        *(
            state.memory.load(
                base + W_PARTY_MON_1_HP + index * PARTY_STRUCT_LENGTH, 2
            )
            for index in range(PARTY_COUNT)
        ),
        state.memory.load(base + W_FIRST_MONS_NOT_OUT_YET, 1),
        state.memory.load(base + W_TEXT_BOX_ID, 1),
    )


def _add_transition(
    count: claripy.ast.BV, hl: claripy.ast.BV
) -> tuple[claripy.ast.BV, claripy.ast.BV]:
    result = hl + claripy.ZeroExt(8, count) * PARTY_STRUCT_LENGTH
    flags = claripy.If(
        count == 0, claripy.BVV(0xA0, 8), claripy.BVV(0xC0, 8)
    )
    return result, flags


class LoadAbsolute(angr.SimProcedure):
    def __init__(self, address: int, continuation: int) -> None:
        super().__init__()
        self._address = address
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self._address, 1)
        self.jump(self._continuation)


class AssemblyAddNTimes(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["add_call"] = _register_bytes(self.state)
        self.state.globals["trace"] = self.state.globals["trace"] * 16 + 1
        result, flags = _add_transition(self.state.regs.a, self.state.regs.hl)
        self.state.regs.a = 0
        self.state.regs.f = claripy.If(
            flags == 0xA0, claripy.BVV(0x50, 8), claripy.BVV(0x42, 8)
        )
        self.state.regs.hl = result
        self.jump(self._continuation)


class NativeAddNTimes(angr.SimProcedure):
    def run(self, address: claripy.ast.BV) -> None:  # type: ignore[override]
        self.state.globals["add_call"] = self.state.memory.load(address, 8)
        self.state.globals["trace"] = self.state.globals["trace"] * 16 + 1
        count = self.state.memory.load(address, 1)
        hl = self.state.memory.load(address + 6, 2)
        result, flags = _add_transition(count, hl)
        self.state.memory.store(address, claripy.BVV(0, 8))
        self.state.memory.store(address + 1, flags)
        self.state.memory.store(address + 6, result)


class OrAtHL(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a |= self.state.memory.load(self.state.regs.hl, 1)
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x40, 8),
            claripy.BVV(0, 8),
        )
        self.jump(self._continuation)


class AndA(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.f = claripy.BVV(0x10, 8) | claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x40, 8),
            claripy.BVV(0, 8),
        )
        self.jump(self._continuation)


class AssemblyPrint(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["print_call"] = _register_bytes(self.state)
        self.state.globals["trace"] = self.state.globals["trace"] * 16 + 2
        self.state.memory.store(W_TEXT_BOX_ID, claripy.BVV(1, 8))
        self.state.regs.b = 0xC4
        self.state.regs.c = 0xB9
        self.jump(self._continuation)


class NativePrint(angr.SimProcedure):
    def run(
        self, address: claripy.ast.BV, memory: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        assert not memory.symbolic and self.state.solver.eval(memory) == NATIVE_MEMORY
        self.state.globals["print_call"] = self.state.memory.load(address, 8)
        self.state.globals["trace"] = self.state.globals["trace"] * 16 + 2
        self.state.memory.store(address + 2, claripy.BVV(0xC4B9, 16))
        self.state.memory.store(memory + W_TEXT_BOX_ID, claripy.BVV(1, 8))


class XorA(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = 0
        self.state.regs.f = 0x40
        self.jump(self._continuation)


def _inputs() -> dict[str, claripy.ast.BV]:
    values = symbolic_registers("has_mon_fainted")
    values["which"] = claripy.BVS("has_mon_fainted_which", 8)
    values["first"] = claripy.BVS("has_mon_fainted_first", 8)
    values["textbox"] = claripy.BVS("has_mon_fainted_textbox", 8)
    for index in range(PARTY_COUNT):
        values[f"hp_high_{index}"] = claripy.BVS(
            f"has_mon_fainted_hp_high_{index}", 8
        )
        values[f"hp_low_{index}"] = claripy.BVS(
            f"has_mon_fainted_hp_low_{index}", 8
        )
    return values


def _setup(
    state: angr.SimState, values: dict[str, claripy.ast.BV], native: bool
) -> None:
    base = NATIVE_MEMORY if native else 0
    state.memory.store(base + W_WHICH_POKEMON, values["which"])
    state.memory.store(base + W_FIRST_MONS_NOT_OUT_YET, values["first"])
    state.memory.store(base + W_TEXT_BOX_ID, values["textbox"])
    for index in range(PARTY_COUNT):
        address = base + W_PARTY_MON_1_HP + index * PARTY_STRUCT_LENGTH
        state.memory.store(address, values[f"hp_high_{index}"])
        state.memory.store(address + 1, values[f"hp_low_{index}"])
    state.globals["add_call"] = claripy.BVV(0, 64)
    state.globals["print_call"] = claripy.BVV(0, 64)
    state.globals["trace"] = claripy.BVV(0, 16)
    state.add_constraints(values["which"] < PARTY_COUNT)


def _endpoint(state: angr.SimState, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    registers = (
        native_registers(state, NATIVE_STATE)
        if native
        else assembly_registers(state)
    )
    return Endpoint(
        **registers,
        memory=_memory(state, base),
        add_call=state.globals["add_call"],
        print_call=state.globals["print_call"],
        trace=state.globals["trace"],
        constraints=tuple(state.solver.constraints),
    )


@cache
def _assembly_project() -> tuple[angr.Project, int]:
    location = symbol_location(SYMS, "HasMonFainted")
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
    project.hook(base, LoadAbsolute(W_WHICH_POKEMON, base + 3), length=3)
    project.hook(base + 9, AssemblyAddNTimes(base + 12), length=3)
    project.hook(base + 12, Sm83LoadAAtHlIncrement(base + 13), length=1)
    project.hook(base + 13, OrAtHL(base + 14), length=1)
    project.hook(
        base + 15,
        LoadAbsolute(W_FIRST_MONS_NOT_OUT_YET, base + 18),
        length=3,
    )
    project.hook(base + 18, AndA(base + 19), length=1)
    project.hook(base + 24, AssemblyPrint(base + 27), length=3)
    project.hook(base + 27, XorA(base + 28), length=1)
    return project, base


@cache
def _native_project() -> tuple[angr.Project, int]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_has_mon_fainted")
    add = project.loader.find_symbol("port_add_n_times")
    print_text = project.loader.find_symbol("port_print_text")
    assert function is not None and add is not None and print_text is not None
    project.hook(add.rebased_addr, NativeAddNTimes())
    project.hook(print_text.rebased_addr, NativePrint())
    return project, function.rebased_addr


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, base = _assembly_project()
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _setup(state, values, False)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    return [_endpoint(end, False) for end in collect_returns(project, state, RETURN)]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, function = _native_project()
    state = project.factory.call_state(function, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, values, True)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [_endpoint(end, True) for end in manager.deadended]


@pytest.mark.skipif(
    not ELF.exists() or not ROM.exists() or not SYMS.exists(), reason="build"
)
def test_has_mon_fainted_pathwise_equivalence() -> None:
    location = symbol_location(SYMS, "HasMonFainted")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    values = _inputs()
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "memory", "add_call", "print_call", "trace"),
    )
