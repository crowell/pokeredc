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
from verification.harness.sm83_shims import (
    Sm83AddHlRegisterPair,
    Sm83AddRegister,
    Sm83CpImmediate,
    Sm83DecRegister,
    Sm83IncRegister,
    Sm83LoadAImmediate,
    Sm83StoreAAtHlIncrement,
    Sm83StoreAImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
STACK = 0xC000
RETURN = 0xFFFF
LINK_STATE = 0xD12B
LIST_INDEX = 0xCCDE
RANDOM_NUMBERS = 0xD148
H_RANDOM_ADD = 0xFFD3
H_RANDOM_SUB = 0xFFD4
RANDOM_UNDERSCORE_BANK = 0x04
RANDOM_UNDERSCORE_ADDRESS = 0x7A8F
EXPECTED = bytes.fromhex(
    "fa2bd1fe04c25c3ee5c5fadecc4f06002148d1093ceadeccfe097ec1e1d8"
    "e5c5f5afeadecc2148d106097e4f8787813c220520f6f1c1e1c9"
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
    random_add: claripy.ast.BV
    random_sub: claripy.ast.BV
    div_first: claripy.ast.BV
    div_second: claripy.ast.BV
    loaded_bank: claripy.ast.BV
    rom_bank: claripy.ast.BV
    link_state: claripy.ast.BV
    list_index: claripy.ast.BV
    random_numbers: claripy.ast.BV
    random_call: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _random_transition(
    registers: dict[str, claripy.ast.BV],
    random_add: claripy.ast.BV,
    random_sub: claripy.ast.BV,
    div_first: claripy.ast.BV,
    div_second: claripy.ast.BV,
) -> tuple[claripy.ast.BV, claripy.ast.BV, claripy.ast.BV]:
    carry_in = registers["f"][4:4]
    first_wide = (
        claripy.ZeroExt(1, random_add)
        + claripy.ZeroExt(1, div_first)
        + claripy.ZeroExt(8, carry_in)
    )
    random_add_out = first_wide[7:0]
    first_carry = first_wide[8:8]
    borrow_amount = claripy.ZeroExt(1, div_second) + claripy.ZeroExt(
        8, first_carry
    )
    random_sub_out = (claripy.ZeroExt(1, random_sub) - borrow_amount)[7:0]
    half_borrow = claripy.ZeroExt(1, random_sub[3:0]) < (
        claripy.ZeroExt(1, div_second[3:0]) + claripy.ZeroExt(4, first_carry)
    )
    borrow = claripy.ZeroExt(1, random_sub) < borrow_amount
    flags = (
        claripy.BVV(0x40, 8)
        | claripy.If(
            random_sub_out == 0, claripy.BVV(0x80, 8), claripy.BVV(0, 8)
        )
        | claripy.If(half_borrow, claripy.BVV(0x20, 8), claripy.BVV(0, 8))
        | claripy.If(borrow, claripy.BVV(0x10, 8), claripy.BVV(0, 8))
    )
    return random_add_out, random_sub_out, flags


def _random_call_snapshot(
    registers: dict[str, claripy.ast.BV],
    random_add: claripy.ast.BV,
    random_sub: claripy.ast.BV,
    div_first: claripy.ast.BV,
    div_second: claripy.ast.BV,
    loaded_bank: claripy.ast.BV,
    rom_bank: claripy.ast.BV,
) -> claripy.ast.BV:
    return claripy.Concat(
        *(registers[name] for name in REGISTERS),
        random_add,
        random_sub,
        div_first,
        div_second,
        loaded_bank,
        rom_bank,
    )


class AssemblyRandom(angr.SimProcedure):
    """Complete proven Random transition at BattleRandom's tail-call boundary."""

    def run(self) -> None:  # type: ignore[override]
        registers = assembly_registers(self.state)
        random_add = self.state.memory.load(H_RANDOM_ADD, 1)
        random_sub = self.state.memory.load(H_RANDOM_SUB, 1)
        div_first = self.state.globals["div_first"]
        div_second = self.state.globals["div_second"]
        self.state.globals["random_call"] = _random_call_snapshot(
            registers,
            random_add,
            random_sub,
            div_first,
            div_second,
            self.state.globals["loaded_bank"],
            self.state.globals["rom_bank"],
        )
        internal = dict(registers)
        internal["b"] = claripy.BVV(RANDOM_UNDERSCORE_BANK, 8)
        internal["h"] = claripy.BVV(RANDOM_UNDERSCORE_ADDRESS >> 8, 8)
        internal["l"] = claripy.BVV(RANDOM_UNDERSCORE_ADDRESS & 0xFF, 8)
        add_out, sub_out, flags = _random_transition(
            internal, random_add, random_sub, div_first, div_second
        )
        self.state.regs.a = add_out
        self.state.regs.f = sm83_flags_to_z80(flags)
        self.state.memory.store(H_RANDOM_ADD, add_out)
        self.state.memory.store(H_RANDOM_SUB, sub_out)
        self.state.regs.sp = self.state.regs.sp + 2
        self.jump(RETURN)


class NativeRandomGenerate(angr.SimProcedure):
    """Complete proven port_random_generate transition at its call boundary."""

    def run(self, address: claripy.ast.BV) -> None:  # type: ignore[override]
        registers = {
            name: self.state.memory.load(address + offset, 1)
            for offset, name in enumerate(REGISTERS)
        }
        random_add = self.state.memory.load(address + 8, 1)
        random_sub = self.state.memory.load(address + 9, 1)
        div_first = self.state.memory.load(address + 10, 1)
        div_second = self.state.memory.load(address + 11, 1)
        loaded_bank = self.state.memory.load(address + 12, 1)
        rom_bank = self.state.memory.load(address + 13, 1)
        self.state.globals["random_call"] = _random_call_snapshot(
            registers,
            random_add,
            random_sub,
            div_first,
            div_second,
            loaded_bank,
            rom_bank,
        )
        internal = dict(registers)
        internal["b"] = claripy.BVV(RANDOM_UNDERSCORE_BANK, 8)
        internal["h"] = claripy.BVV(RANDOM_UNDERSCORE_ADDRESS >> 8, 8)
        internal["l"] = claripy.BVV(RANDOM_UNDERSCORE_ADDRESS & 0xFF, 8)
        add_out, sub_out, flags = _random_transition(
            internal, random_add, random_sub, div_first, div_second
        )
        output = dict(registers)
        output["a"] = add_out
        output["f"] = flags
        self.state.memory.store(
            address,
            claripy.Concat(
                *(output[name] for name in REGISTERS),
                add_out,
                sub_out,
                div_first,
                div_second,
                loaded_bank,
                rom_bank,
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
        "link_state",
        "list_index",
    ):
        values[field] = claripy.BVS(f"{prefix}_{field}", 8)
    values["random_numbers"] = claripy.BVS(f"{prefix}_random_numbers", 256 * 8)
    return values


@cache
def _assembly_project() -> tuple[angr.Project, int]:
    location = symbol_location(SYMS, "BattleRandom")
    random = symbol_location(SYMS, "Random")
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
    project.hook(base, Sm83LoadAImmediate(LINK_STATE, base + 3), length=3)
    project.hook(base + 3, Sm83CpImmediate(4, base + 5), length=2)
    project.hook(random.address, AssemblyRandom(), length=17)
    project.hook(base + 10, Sm83LoadAImmediate(LIST_INDEX, base + 13), length=3)
    project.hook(base + 19, Sm83AddHlRegisterPair("bc", base + 20), length=1)
    project.hook(base + 20, Sm83IncRegister("a", base + 21), length=1)
    project.hook(base + 21, Sm83StoreAImmediate(LIST_INDEX, base + 24), length=3)
    project.hook(base + 24, Sm83CpImmediate(9, base + 26), length=2)
    project.hook(base + 34, Sm83StoreAImmediate(LIST_INDEX, base + 37), length=3)
    project.hook(base + 44, Sm83AddRegister("a", base + 45), length=1)
    project.hook(base + 45, Sm83AddRegister("a", base + 46), length=1)
    project.hook(base + 46, Sm83AddRegister("c", base + 47), length=1)
    project.hook(base + 47, Sm83IncRegister("a", base + 48), length=1)
    project.hook(base + 48, Sm83StoreAAtHlIncrement(base + 49), length=1)
    project.hook(base + 49, Sm83DecRegister("b", base + 50), length=1)
    return project, base


@cache
def _native_project() -> tuple[angr.Project, int]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_battle_random")
    random = project.loader.find_symbol("port_random_generate")
    assert function is not None and random is not None
    project.hook(random.rebased_addr, NativeRandomGenerate())
    return project, function.rebased_addr


def _setup_assembly(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    set_assembly_registers(state, values)
    state.memory.store(LINK_STATE, values["link_state"])
    state.memory.store(LIST_INDEX, values["list_index"])
    state.memory.store(RANDOM_NUMBERS, values["random_numbers"])
    state.memory.store(H_RANDOM_ADD, values["random_add"])
    state.memory.store(H_RANDOM_SUB, values["random_sub"])
    for field in ("div_first", "div_second", "loaded_bank", "rom_bank"):
        state.globals[field] = values[field]
    state.globals["random_call"] = claripy.BVV(0, 112)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")


def assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, function = _assembly_project()
    state = project.factory.blank_state(addr=function)
    _setup_assembly(state, values)
    ends = collect_returns(project, state, RETURN)
    for end in ends:
        assert end.solver.is_true(end.regs.sp == STACK + 2)
    return [
        Endpoint(
            **assembly_registers(end),
            random_add=end.memory.load(H_RANDOM_ADD, 1),
            random_sub=end.memory.load(H_RANDOM_SUB, 1),
            div_first=end.globals["div_first"],
            div_second=end.globals["div_second"],
            loaded_bank=end.globals["loaded_bank"],
            rom_bank=end.globals["rom_bank"],
            link_state=end.memory.load(LINK_STATE, 1),
            list_index=end.memory.load(LIST_INDEX, 1),
            random_numbers=end.memory.load(RANDOM_NUMBERS, 256),
            random_call=end.globals["random_call"],
            constraints=tuple(end.solver.constraints),
        )
        for end in ends
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
            "link_state",
            "list_index",
        ),
        8,
    ):
        state.memory.store(NATIVE_STATE + offset, values[field])
    state.memory.store(NATIVE_STATE + 16, values["random_numbers"])
    state.globals["random_call"] = claripy.BVV(0, 112)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            random_add=end.memory.load(NATIVE_STATE + 8, 1),
            random_sub=end.memory.load(NATIVE_STATE + 9, 1),
            div_first=end.memory.load(NATIVE_STATE + 10, 1),
            div_second=end.memory.load(NATIVE_STATE + 11, 1),
            loaded_bank=end.memory.load(NATIVE_STATE + 12, 1),
            rom_bank=end.memory.load(NATIVE_STATE + 13, 1),
            link_state=end.memory.load(NATIVE_STATE + 14, 1),
            list_index=end.memory.load(NATIVE_STATE + 15, 1),
            random_numbers=end.memory.load(NATIVE_STATE + 16, 256),
            random_call=end.globals["random_call"],
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
    "link_state",
    "list_index",
    "random_numbers",
    "random_call",
)


def _assert_complete_domain(endpoints: list[Endpoint]) -> None:
    solver = claripy.Solver()
    domains = [claripy.And(*endpoint.constraints) for endpoint in endpoints]
    solver.add(claripy.Not(claripy.Or(*domains)))
    assert not solver.satisfiable()


@pytest.mark.skipif(not ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMS.exists(), reason="run make red")
def test_battle_random_pathwise_equivalence() -> None:
    values = inputs("battle_random")
    assembly_ends = assembly(values)
    native_ends = native(values)
    assert len(assembly_ends) == 3
    assert len(native_ends) == 3
    _assert_complete_domain(assembly_ends)
    _assert_complete_domain(native_ends)
    assert_pathwise_equivalent(assembly_ends, native_ends, OBSERVABLES)
