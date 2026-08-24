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
    linked_bytes,
    rom_window,
    sm83_flags_to_z80,
    symbol_location,
)
from verification.harness.sm83_shims import Sm83LoadAHighImmediate

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
STACK = 0xFF80
RETURN = 0xFFFF
H_RANDOM_ADD = 0xFFD3
H_RANDOM_SUB = 0xFFD4
RANDOM_UNDERSCORE_BANK = 0x04
RANDOM_UNDERSCORE_ADDRESS = 0x7A8F
EXPECTED = bytes.fromhex("e5d5c50604218f7acdd635f0d3c1d1e1c9")


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
    random_add: claripy.ast.BV
    random_sub: claripy.ast.BV
    div_first: claripy.ast.BV
    div_second: claripy.ast.BV
    loaded_bank: claripy.ast.BV
    rom_bank: claripy.ast.BV
    call: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _random_transition(
    registers: dict[str, claripy.ast.BV],
    random_add: claripy.ast.BV,
    random_sub: claripy.ast.BV,
    div_first: claripy.ast.BV,
    div_second: claripy.ast.BV,
) -> tuple[dict[str, claripy.ast.BV], claripy.ast.BV, claripy.ast.BV]:
    carry_in = registers["f"][4:4]
    first_wide = (
        claripy.ZeroExt(1, random_add)
        + claripy.ZeroExt(1, div_first)
        + claripy.ZeroExt(8, carry_in)
    )
    add_out = first_wide[7:0]
    first_carry = first_wide[8:8]
    borrow_amount = claripy.ZeroExt(1, div_second) + claripy.ZeroExt(
        8, first_carry
    )
    sub_out = (claripy.ZeroExt(1, random_sub) - borrow_amount)[7:0]
    half_borrow = claripy.ZeroExt(1, random_sub[3:0]) < (
        claripy.ZeroExt(1, div_second[3:0]) + claripy.ZeroExt(4, first_carry)
    )
    borrow = claripy.ZeroExt(1, random_sub) < borrow_amount
    flags = (
        claripy.BVV(0x40, 8)
        | claripy.If(sub_out == 0, claripy.BVV(0x80, 8), claripy.BVV(0, 8))
        | claripy.If(half_borrow, claripy.BVV(0x20, 8), claripy.BVV(0, 8))
        | claripy.If(borrow, claripy.BVV(0x10, 8), claripy.BVV(0, 8))
    )
    output = dict(registers)
    output["a"] = sub_out
    output["f"] = flags
    output["b"] = div_second
    return output, add_out, sub_out


def _assembly_call_snapshot(state: angr.SimState) -> claripy.ast.BV:
    registers = assembly_registers(state)
    return claripy.Concat(
        *(registers[name] for name in REGISTERS),
        state.memory.load(H_RANDOM_ADD, 1),
        state.memory.load(H_RANDOM_SUB, 1),
        state.globals["div_first"],
        state.globals["div_second"],
        state.globals["loaded_bank"],
        state.globals["rom_bank"],
    )


class AssemblyFarRandom(angr.SimProcedure):
    """Proven Bankswitch + Random_ transition at the farcall boundary."""

    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["call"] = _assembly_call_snapshot(self.state)
        registers = assembly_registers(self.state)
        output, random_add, random_sub = _random_transition(
            registers,
            self.state.memory.load(H_RANDOM_ADD, 1),
            self.state.memory.load(H_RANDOM_SUB, 1),
            self.state.globals["div_first"],
            self.state.globals["div_second"],
        )
        self.state.regs.a = output["a"]
        self.state.regs.f = sm83_flags_to_z80(output["f"])
        self.state.regs.b = output["b"]
        self.state.memory.store(H_RANDOM_ADD, random_add)
        self.state.memory.store(H_RANDOM_SUB, random_sub)
        self.jump(self._continuation)


class NativeRandomUnderscore(angr.SimProcedure):
    def run(self, state_address: claripy.ast.BV) -> None:  # type: ignore[override]
        self.state.globals["call"] = claripy.Concat(
            self.state.memory.load(state_address, 12),
            self.state.globals["loaded_bank"],
            self.state.globals["rom_bank"],
        )
        registers = {
            name: self.state.memory.load(state_address + offset, 1)
            for offset, name in enumerate(REGISTERS)
        }
        output, random_add, random_sub = _random_transition(
            registers,
            self.state.memory.load(state_address + 8, 1),
            self.state.memory.load(state_address + 9, 1),
            self.state.memory.load(state_address + 10, 1),
            self.state.memory.load(state_address + 11, 1),
        )
        self.state.memory.store(
            state_address,
            claripy.Concat(
                *(output[name] for name in REGISTERS),
                random_add,
                random_sub,
                self.state.memory.load(state_address + 10, 2),
            ),
        )


def inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for field in (
        "random_add",
        "random_sub",
        "div_first",
        "div_second",
        "loaded_bank",
        "rom_bank",
    ):
        values[field] = claripy.BVS(f"{prefix}_{field}", 8)
    return values


def _setup(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    state.memory.store(H_RANDOM_ADD, values["random_add"])
    state.memory.store(H_RANDOM_SUB, values["random_sub"])
    for field in ("div_first", "div_second", "loaded_bank", "rom_bank"):
        state.globals[field] = values[field]
    state.globals["call"] = claripy.BVV(0, 112)


@cache
def _assembly_project() -> tuple[angr.Project, int]:
    location = symbol_location(SYMS, "Random")
    random_underscore = symbol_location(SYMS, "Random_")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    assert random_underscore.bank == RANDOM_UNDERSCORE_BANK
    assert random_underscore.address == RANDOM_UNDERSCORE_ADDRESS
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
    project.hook(base + 8, AssemblyFarRandom(base + 11), length=3)
    project.hook(base + 11, Sm83LoadAHighImmediate(0xD3, base + 13), length=2)
    return project, base


@cache
def _native_project() -> tuple[angr.Project, int]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_random_generate")
    random_underscore = project.loader.find_symbol("port_random")
    assert function is not None and random_underscore is not None
    project.hook(random_underscore.rebased_addr, NativeRandomUnderscore())
    return project, function.rebased_addr


def assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, function = _assembly_project()
    state = project.factory.blank_state(addr=function)
    set_assembly_registers(state, values)
    _setup(state, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    manager = project.factory.simulation_manager(state)
    manager.explore(find=lambda end: end.addr == RETURN)
    assert not manager.errored and len(manager.found) == 1
    return [
        Endpoint(
            **assembly_registers(end),
            random_add=end.memory.load(H_RANDOM_ADD, 1),
            random_sub=end.memory.load(H_RANDOM_SUB, 1),
            div_first=end.globals["div_first"],
            div_second=end.globals["div_second"],
            loaded_bank=end.globals["loaded_bank"],
            rom_bank=end.globals["rom_bank"],
            call=end.globals["call"],
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, function = _native_project()
    state = project.factory.call_state(function, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    for offset, field in enumerate(
        (
            "random_add",
            "random_sub",
            "div_first",
            "div_second",
            "loaded_bank",
            "rom_bank",
        ),
        8,
    ):
        state.memory.store(NATIVE_STATE + offset, values[field])
    for field in ("loaded_bank", "rom_bank"):
        state.globals[field] = values[field]
    state.globals["call"] = claripy.BVV(0, 112)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            random_add=end.memory.load(NATIVE_STATE + 8, 1),
            random_sub=end.memory.load(NATIVE_STATE + 9, 1),
            div_first=end.memory.load(NATIVE_STATE + 10, 1),
            div_second=end.memory.load(NATIVE_STATE + 11, 1),
            loaded_bank=end.memory.load(NATIVE_STATE + 12, 1),
            rom_bank=end.memory.load(NATIVE_STATE + 13, 1),
            call=end.globals["call"],
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


OBSERVABLES = (
    *REGISTERS,
    "random_add",
    "random_sub",
    "div_first",
    "div_second",
    "loaded_bank",
    "rom_bank",
    "call",
)


@pytest.mark.skipif(
    not ELF.exists() or not ROM.exists() or not SYMS.exists(), reason="build"
)
def test_random_pathwise_equivalence() -> None:
    values = inputs("random")
    assert_pathwise_equivalent(assembly(values), native(values), OBSERVABLES)
