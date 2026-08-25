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
    Sm83AdcRegister,
    Sm83CpImmediate,
    Sm83DecRegister,
    Sm83LoadAHighImmediate,
    Sm83LoadAImmediate,
    Sm83SrlRegister,
    Sm83StoreAAtHlIncrement,
    Sm83StoreAHighImmediate,
    Sm83StoreAImmediate,
)


ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xE000
RETURN = 0xFFFF
W_ENEMY_MON_BASE_STATS = 0xD002
W_ENEMY_MON_BASE_EXP = 0xD008
W_PARTY_GAIN_EXP_FLAGS = 0xD058
W_TEMP_BYTE_VALUE = 0xD11E
H_DIVIDEND = 0xFF95
H_DIVISOR = 0xFF99
H_BUFFER = 0xFF9A
H_LOADED_BANK = 0xFFB8
MAPPER_BANK = 0x2000
DATA_LENGTH = W_ENEMY_MON_BASE_EXP + 1 - W_ENEMY_MON_BASE_STATS
CALL_BITS = 160
CALL_COUNT = DATA_LENGTH
CALLS_BITS = CALL_BITS * CALL_COUNT
EXPECTED = bytes.fromhex(
    "fa58d047af0e081600afcb388a570d20f8fe02d8ea1ed12102d00e07afe0"
    "957ee096fa1ed1e0990602cdb938f098220d20eac9"
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
    loaded_bank: claripy.ast.BV
    mapper_bank: claripy.ast.BV
    calls: claripy.ast.BV
    call_count: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _register_bytes(state: angr.SimState) -> claripy.ast.BV:
    registers = assembly_registers(state)
    return claripy.Concat(*(registers[name] for name in REGISTERS))


def _call_snapshot(
    registers: claripy.ast.BV,
    dividend: claripy.ast.BV,
    divisor: claripy.ast.BV,
    buffer: claripy.ast.BV,
    loaded_bank: claripy.ast.BV,
    mapper_bank: claripy.ast.BV,
) -> claripy.ast.BV:
    return claripy.Concat(
        registers,
        dividend,
        divisor,
        buffer,
        loaded_bank,
        mapper_bank,
    )


def _append_call(state: angr.SimState, snapshot: claripy.ast.BV) -> None:
    state.globals["calls"] = (
        state.globals["calls"] << CALL_BITS
    ) | claripy.ZeroExt(CALLS_BITS - CALL_BITS, snapshot)
    state.globals["call_count"] += 1


def _divide_outputs(
    dividend: claripy.ast.BV, divisor: claripy.ast.BV
) -> tuple[claripy.ast.BV, claripy.ast.BV, claripy.ast.BV]:
    numerator = claripy.ZeroExt(16, dividend[31:16])
    wide_divisor = claripy.ZeroExt(24, divisor)
    quotient = numerator // wide_divisor
    remainder = (numerator % wide_divisor)[7:0]
    return quotient, remainder, claripy.Concat(divisor, quotient)


class XorA(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = 0
        self.state.regs.f = 0x40
        self.jump(self._continuation)


class CopyRegister(angr.SimProcedure):
    def __init__(
        self, destination: str, source: str, continuation: int
    ) -> None:
        super().__init__()
        self._destination = destination
        self._source = source
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        setattr(
            self.state.regs,
            self._destination,
            getattr(self.state.regs, self._source),
        )
        self.jump(self._continuation)


class LoadAAtHL(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self.state.regs.hl, 1)
        self.jump(self._continuation)


class AssemblyDivideWrapper(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        dividend = self.state.memory.load(H_DIVIDEND, 4)
        divisor = self.state.memory.load(H_DIVISOR, 1)
        buffer = self.state.memory.load(H_BUFFER, 5)
        loaded_bank = self.state.memory.load(H_LOADED_BANK, 1)
        _append_call(
            self.state,
            _call_snapshot(
                _register_bytes(self.state),
                dividend,
                divisor,
                buffer,
                loaded_bank,
                self.state.memory.load(MAPPER_BANK, 1),
            ),
        )
        quotient, remainder, output_buffer = _divide_outputs(
            dividend, divisor
        )
        self.state.memory.store(H_DIVIDEND, quotient)
        self.state.memory.store(H_DIVISOR, remainder)
        self.state.memory.store(H_BUFFER, output_buffer)
        self.state.memory.store(MAPPER_BANK, loaded_bank)
        self.state.regs.a = loaded_bank
        target = self.state.memory.load(
            self.state.regs.sp, 2, endness="Iend_LE"
        )
        self.state.regs.sp += 2
        self.jump(target)


class NativeDivideWrapper(angr.SimProcedure):
    def run(self, address: claripy.ast.BV) -> None:  # type: ignore[override]
        registers = self.state.memory.load(address, 8)
        dividend = self.state.memory.load(address + 8, 4)
        divisor = self.state.memory.load(address + 12, 1)
        buffer = self.state.memory.load(address + 13, 5)
        loaded_bank = self.state.memory.load(address + 18, 1)
        _append_call(
            self.state,
            _call_snapshot(
                registers,
                dividend,
                divisor,
                buffer,
                loaded_bank,
                self.state.memory.load(address + 19, 1),
            ),
        )
        quotient, remainder, output_buffer = _divide_outputs(
            dividend, divisor
        )
        self.state.memory.store(address, loaded_bank)
        self.state.memory.store(address + 8, quotient)
        self.state.memory.store(address + 12, remainder)
        self.state.memory.store(address + 13, output_buffer)
        self.state.memory.store(address + 19, loaded_bank)


def _inputs() -> dict[str, claripy.ast.BV]:
    values = symbolic_registers("divide_exp_data")
    values["party_flags"] = claripy.BVS("divide_exp_data_party_flags", 8)
    values["temp"] = claripy.BVS("divide_exp_data_temp", 8)
    values["dividend"] = claripy.BVS("divide_exp_data_dividend", 32)
    values["divisor"] = claripy.BVS("divide_exp_data_divisor", 8)
    values["buffer"] = claripy.BVS("divide_exp_data_buffer", 40)
    values["loaded_bank"] = claripy.BVS("divide_exp_data_loaded_bank", 8)
    values["mapper_bank"] = claripy.BVS("divide_exp_data_mapper_bank", 8)
    for index in range(DATA_LENGTH):
        values[f"data_{index}"] = claripy.BVS(
            f"divide_exp_data_data_{index}", 8
        )
    return values


def _setup(
    state: angr.SimState, values: dict[str, claripy.ast.BV], native: bool
) -> None:
    base = NATIVE_MEMORY if native else 0
    state.memory.store(base + W_PARTY_GAIN_EXP_FLAGS, values["party_flags"])
    state.memory.store(base + W_TEMP_BYTE_VALUE, values["temp"])
    for index in range(DATA_LENGTH):
        state.memory.store(
            base + W_ENEMY_MON_BASE_STATS + index, values[f"data_{index}"]
        )
    state.memory.store(base + H_DIVIDEND, values["dividend"])
    state.memory.store(base + H_DIVISOR, values["divisor"])
    state.memory.store(base + H_BUFFER, values["buffer"])
    state.globals["calls"] = claripy.BVV(0, CALLS_BITS)
    state.globals["call_count"] = claripy.BVV(0, 8)
    if native:
        state.memory.store(NATIVE_STATE + 8, values["loaded_bank"])
        state.memory.store(NATIVE_STATE + 9, values["mapper_bank"])
    else:
        state.memory.store(H_LOADED_BANK, values["loaded_bank"])
        state.memory.store(MAPPER_BANK, values["mapper_bank"])


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        state.memory.load(base + W_PARTY_GAIN_EXP_FLAGS, 1),
        state.memory.load(base + W_TEMP_BYTE_VALUE, 1),
        state.memory.load(base + W_ENEMY_MON_BASE_STATS, DATA_LENGTH),
        state.memory.load(base + H_DIVIDEND, 4),
        state.memory.load(base + H_DIVISOR, 1),
        state.memory.load(base + H_BUFFER, 5),
    )


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
        loaded_bank=state.memory.load(
            NATIVE_STATE + 8 if native else H_LOADED_BANK, 1
        ),
        mapper_bank=state.memory.load(
            NATIVE_STATE + 9 if native else MAPPER_BANK, 1
        ),
        calls=state.globals["calls"],
        call_count=state.globals["call_count"],
        constraints=tuple(state.solver.constraints),
    )


@cache
def _assembly_project() -> tuple[angr.Project, int]:
    location = symbol_location(SYMS, "DivideExpDataByNumMonsGainingExp")
    divide = symbol_location(SYMS, "Divide")
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
    project.hook(
        base,
        Sm83LoadAImmediate(W_PARTY_GAIN_EXP_FLAGS, base + 3),
        length=3,
    )
    project.hook(base + 3, CopyRegister("b", "a", base + 4), length=1)
    project.hook(base + 4, XorA(base + 5), length=1)
    project.hook(base + 9, XorA(base + 10), length=1)
    project.hook(base + 10, Sm83SrlRegister("b", base + 12), length=2)
    project.hook(base + 12, Sm83AdcRegister("d", base + 13), length=1)
    project.hook(base + 13, CopyRegister("d", "a", base + 14), length=1)
    project.hook(base + 14, Sm83DecRegister("c", base + 15), length=1)
    project.hook(base + 17, Sm83CpImmediate(2, base + 19), length=2)
    project.hook(
        base + 20, Sm83StoreAImmediate(W_TEMP_BYTE_VALUE, base + 23), length=3
    )
    project.hook(base + 28, XorA(base + 29), length=1)
    project.hook(
        base + 29, Sm83StoreAHighImmediate(0x95, base + 31), length=2
    )
    project.hook(base + 31, LoadAAtHL(base + 32), length=1)
    project.hook(
        base + 32, Sm83StoreAHighImmediate(0x96, base + 34), length=2
    )
    project.hook(
        base + 34, Sm83LoadAImmediate(W_TEMP_BYTE_VALUE, base + 37), length=3
    )
    project.hook(
        base + 37, Sm83StoreAHighImmediate(0x99, base + 39), length=2
    )
    project.hook(divide.address, AssemblyDivideWrapper())
    project.hook(
        base + 44, Sm83LoadAHighImmediate(0x98, base + 46), length=2
    )
    project.hook(
        base + 46, Sm83StoreAAtHlIncrement(base + 47), length=1
    )
    project.hook(base + 47, Sm83DecRegister("c", base + 48), length=1)
    return project, base


@cache
def _native_project() -> tuple[angr.Project, int]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol(
        "port_divide_exp_data_by_num_mons_gaining_exp"
    )
    divide = project.loader.find_symbol("port_divide_wrapper")
    assert function is not None and divide is not None
    project.hook(divide.rebased_addr, NativeDivideWrapper())
    return project, function.rebased_addr


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, function = _assembly_project()
    state = project.factory.blank_state(addr=function)
    set_assembly_registers(state, values)
    _setup(state, values, False)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    endpoints = [
        _endpoint(end, False)
        for end in collect_returns(project, state, RETURN)
    ]
    assert len(endpoints) == 2
    return endpoints


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, function = _native_project()
    state = project.factory.call_state(function, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, values, True)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 2
    return [_endpoint(end, True) for end in manager.deadended]


@pytest.mark.skipif(
    not ELF.exists() or not ROM.exists() or not SYMS.exists(), reason="build"
)
def test_divide_exp_data_pathwise_equivalence() -> None:
    location = symbol_location(SYMS, "DivideExpDataByNumMonsGainingExp")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    values = _inputs()
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (
            *REGISTERS,
            "memory",
            "loaded_bank",
            "mapper_bank",
            "calls",
            "call_count",
        ),
    )
