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
    Sm83LoadAAtHlDecrement,
    Sm83LoadAAtHlIncrement,
    Sm83LoadAHighImmediate,
    Sm83StoreAHighImmediate,
    Sm83SubRegister,
)


ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
STACK = 0xE000
RETURN = 0xFFFF
W_ENEMY_MON_MAX_HP = 0xCFF4
W_ENEMY_MON_HP = 0xCFE6
H_DIVIDEND = 0xFF95
H_DIVISOR = 0xFF99
H_BUFFER = 0xFF9A
H_LOADED_BANK = 0xFFB8
MAPPER_BANK = 0x2000
EXPECTED = bytes.fromhex(
    "e09921f4cf2ae0957ee0960602cdb938f0984ff0974721e7cf3a5f7e577a"
    "90c07b91c9"
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
    max_hp: claripy.ast.BV
    hp: claripy.ast.BV
    dividend: claripy.ast.BV
    divisor: claripy.ast.BV
    buffer: claripy.ast.BV
    loaded_bank: claripy.ast.BV
    mapper_bank: claripy.ast.BV
    call: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _register_bytes(state: angr.SimState) -> claripy.ast.BV:
    registers = assembly_registers(state)
    return claripy.Concat(*(registers[name] for name in REGISTERS))


def _snapshot(
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


def _divide_outputs(
    dividend: claripy.ast.BV, divisor: claripy.ast.BV
) -> tuple[claripy.ast.BV, claripy.ast.BV, claripy.ast.BV]:
    numerator = claripy.ZeroExt(16, dividend[31:16])
    wide_divisor = claripy.ZeroExt(24, divisor)
    quotient = numerator // wide_divisor
    remainder = (numerator % wide_divisor)[7:0]
    return quotient, remainder, claripy.Concat(divisor, quotient)


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
        self.state.globals["call"] = _snapshot(
            _register_bytes(self.state),
            dividend,
            divisor,
            buffer,
            loaded_bank,
            self.state.memory.load(MAPPER_BANK, 1),
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
        self.state.globals["call"] = _snapshot(
            registers,
            dividend,
            divisor,
            buffer,
            loaded_bank,
            self.state.memory.load(address + 19, 1),
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
    values = symbolic_registers("ai_hp_fraction")
    values["max_hp"] = claripy.BVS("ai_hp_fraction_max_hp", 16)
    values["hp"] = claripy.BVS("ai_hp_fraction_hp", 16)
    values["dividend"] = claripy.BVS("ai_hp_fraction_dividend", 32)
    values["divisor_scratch"] = claripy.BVS(
        "ai_hp_fraction_divisor_scratch", 8
    )
    values["buffer"] = claripy.BVS("ai_hp_fraction_buffer", 40)
    values["loaded_bank"] = claripy.BVS("ai_hp_fraction_loaded_bank", 8)
    values["mapper_bank"] = claripy.BVS("ai_hp_fraction_mapper_bank", 8)
    return values


def _setup_assembly(
    state: angr.SimState, values: dict[str, claripy.ast.BV]
) -> None:
    set_assembly_registers(state, values)
    state.memory.store(W_ENEMY_MON_MAX_HP, values["max_hp"])
    state.memory.store(W_ENEMY_MON_HP, values["hp"])
    state.memory.store(H_DIVIDEND, values["dividend"])
    state.memory.store(H_DIVISOR, values["divisor_scratch"])
    state.memory.store(H_BUFFER, values["buffer"])
    state.memory.store(H_LOADED_BANK, values["loaded_bank"])
    state.memory.store(MAPPER_BANK, values["mapper_bank"])
    state.globals["call"] = claripy.BVV(0, 160)
    state.add_constraints(values["a"] != 0)


def _setup_native(
    state: angr.SimState, values: dict[str, claripy.ast.BV]
) -> None:
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, values["max_hp"])
    state.memory.store(NATIVE_STATE + 10, values["hp"])
    state.memory.store(NATIVE_STATE + 12, values["dividend"])
    state.memory.store(NATIVE_STATE + 16, values["divisor_scratch"])
    state.memory.store(NATIVE_STATE + 17, values["buffer"])
    state.memory.store(NATIVE_STATE + 22, values["loaded_bank"])
    state.memory.store(NATIVE_STATE + 23, values["mapper_bank"])
    state.globals["call"] = claripy.BVV(0, 160)
    state.add_constraints(values["a"] != 0)


def _endpoint(state: angr.SimState, native: bool) -> Endpoint:
    registers = (
        native_registers(state, NATIVE_STATE)
        if native
        else assembly_registers(state)
    )
    if native:
        return Endpoint(
            **registers,
            max_hp=state.memory.load(NATIVE_STATE + 8, 2),
            hp=state.memory.load(NATIVE_STATE + 10, 2),
            dividend=state.memory.load(NATIVE_STATE + 12, 4),
            divisor=state.memory.load(NATIVE_STATE + 16, 1),
            buffer=state.memory.load(NATIVE_STATE + 17, 5),
            loaded_bank=state.memory.load(NATIVE_STATE + 22, 1),
            mapper_bank=state.memory.load(NATIVE_STATE + 23, 1),
            call=state.globals["call"],
            constraints=tuple(state.solver.constraints),
        )
    return Endpoint(
        **registers,
        max_hp=state.memory.load(W_ENEMY_MON_MAX_HP, 2),
        hp=state.memory.load(W_ENEMY_MON_HP, 2),
        dividend=state.memory.load(H_DIVIDEND, 4),
        divisor=state.memory.load(H_DIVISOR, 1),
        buffer=state.memory.load(H_BUFFER, 5),
        loaded_bank=state.memory.load(H_LOADED_BANK, 1),
        mapper_bank=state.memory.load(MAPPER_BANK, 1),
        call=state.globals["call"],
        constraints=tuple(state.solver.constraints),
    )


@cache
def _assembly_project() -> tuple[angr.Project, int]:
    location = symbol_location(SYMS, "AICheckIfHPBelowFraction")
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
        base, Sm83StoreAHighImmediate(0x99, base + 2), length=2
    )
    project.hook(base + 5, Sm83LoadAAtHlIncrement(base + 6), length=1)
    project.hook(
        base + 6, Sm83StoreAHighImmediate(0x95, base + 8), length=2
    )
    project.hook(base + 8, LoadAAtHL(base + 9), length=1)
    project.hook(
        base + 9, Sm83StoreAHighImmediate(0x96, base + 11), length=2
    )
    project.hook(divide.address, AssemblyDivideWrapper())
    project.hook(
        base + 16, Sm83LoadAHighImmediate(0x98, base + 18), length=2
    )
    project.hook(base + 18, CopyRegister("c", "a", base + 19), length=1)
    project.hook(
        base + 19, Sm83LoadAHighImmediate(0x97, base + 21), length=2
    )
    project.hook(base + 21, CopyRegister("b", "a", base + 22), length=1)
    project.hook(base + 25, Sm83LoadAAtHlDecrement(base + 26), length=1)
    project.hook(base + 26, CopyRegister("e", "a", base + 27), length=1)
    project.hook(base + 27, LoadAAtHL(base + 28), length=1)
    project.hook(base + 28, CopyRegister("d", "a", base + 29), length=1)
    project.hook(base + 29, CopyRegister("a", "d", base + 30), length=1)
    project.hook(base + 30, Sm83SubRegister("b", base + 31), length=1)
    project.hook(base + 32, CopyRegister("a", "e", base + 33), length=1)
    project.hook(base + 33, Sm83SubRegister("c", base + 34), length=1)
    return project, base


@cache
def _native_project() -> tuple[angr.Project, int]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol(
        "port_ai_check_if_hp_below_fraction_private"
    )
    divide = project.loader.find_symbol("port_divide_wrapper")
    assert function is not None and divide is not None
    project.hook(divide.rebased_addr, NativeDivideWrapper())
    return project, function.rebased_addr


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, function = _assembly_project()
    state = project.factory.blank_state(addr=function)
    _setup_assembly(state, values)
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
    state = project.factory.call_state(function, NATIVE_STATE)
    _setup_native(state, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 2
    return [_endpoint(end, True) for end in manager.deadended]


@pytest.mark.skipif(
    not ELF.exists() or not ROM.exists() or not SYMS.exists(), reason="build"
)
def test_ai_check_if_hp_below_fraction_pathwise_equivalence() -> None:
    location = symbol_location(SYMS, "AICheckIfHPBelowFraction")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    values = _inputs()
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (
            *REGISTERS,
            "max_hp",
            "hp",
            "dividend",
            "divisor",
            "buffer",
            "loaded_bank",
            "mapper_bank",
            "call",
        ),
    )
