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
    Sm83AndRegister,
    Sm83CpImmediate,
    Sm83LoadAAtHlIncrement,
    Sm83LoadAHighImmediate,
    Sm83Rrca,
    Sm83StoreAAtHlIncrement,
    Sm83StoreAHighImmediate,
    Sm83StoreAImmediate,
)
from verification.tests.test_divide_wrapper import _divide_outputs
from verification.tests.test_multiply_wrapper import _multiply_transition

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
STACK = 0xC000
RETURN = 0xFFFF
DAMAGE = 0xD0D7
H_PRODUCT = 0xFF95
H_MULTIPLIER = 0xFF99
H_DIVIDE_BUFFER = 0xFF9A
H_RANDOM_ADD = 0xFFD3
H_RANDOM_SUB = 0xFFD4
H_LOADED_BANK = 0xFFB8
MAPPER_BANK = 0x2000
LINK_STATE = 0xD12B
LIST_INDEX = 0xCCDE
RANDOM_NUMBERS = 0xD148
EXPECTED = bytes.fromhex(
    "21d7d02aa720047efe02d8afe0962b2ae0977ee098cd9b6e0ffed938f8e099cd"
    "ac383effe0990604cdb938f09721d7d022f09877c9"
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
    damage: claripy.ast.BV
    product: claripy.ast.BV
    multiplier: claripy.ast.BV
    divide_buffer: claripy.ast.BV
    random_add: claripy.ast.BV
    random_sub: claripy.ast.BV
    div_first: claripy.ast.BV
    div_second: claripy.ast.BV
    loaded_bank: claripy.ast.BV
    mapper_bank: claripy.ast.BV
    link_state: claripy.ast.BV
    list_index: claripy.ast.BV
    random_numbers: claripy.ast.BV
    battle_call: claripy.ast.BV
    random_call: claripy.ast.BV
    multiply_call: claripy.ast.BV
    divide_call: claripy.ast.BV
    done: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _flag(condition: claripy.ast.Bool, value: int) -> claripy.ast.BV:
    return claripy.If(condition, claripy.BVV(value, 8), claripy.BVV(0, 8))


def _cp_flags(left: claripy.ast.BV, right: int) -> claripy.ast.BV:
    return (
        claripy.BVV(0x40, 8)
        | _flag(left == right, 0x80)
        | _flag((left & 0x0F).ULT(right & 0x0F), 0x20)
        | _flag(left.ULT(right), 0x10)
    )


def _random_transition(
    flags_in: claripy.ast.BV,
    random_add: claripy.ast.BV,
    random_sub: claripy.ast.BV,
    div_first: claripy.ast.BV,
    div_second: claripy.ast.BV,
) -> tuple[claripy.ast.BV, claripy.ast.BV, claripy.ast.BV]:
    carry_in = flags_in[4:4]
    first_wide = (
        claripy.ZeroExt(1, random_add)
        + claripy.ZeroExt(1, div_first)
        + claripy.ZeroExt(8, carry_in)
    )
    add_out = first_wide[7:0]
    first_carry = first_wide[8:8]
    subtrahend = claripy.ZeroExt(1, div_second) + claripy.ZeroExt(
        8, first_carry
    )
    sub_out = (claripy.ZeroExt(1, random_sub) - subtrahend)[7:0]
    flags = (
        claripy.BVV(0x40, 8)
        | _flag(sub_out == 0, 0x80)
        | _flag(
            claripy.ZeroExt(1, random_sub[3:0])
            < claripy.ZeroExt(1, div_second[3:0])
            + claripy.ZeroExt(4, first_carry),
            0x20,
        )
        | _flag(claripy.ZeroExt(1, random_sub) < subtrahend, 0x10)
    )
    return add_out, sub_out, flags


def _bytes(vector: claripy.ast.BV, count: int) -> list[claripy.ast.BV]:
    return [
        vector[count * 8 - 1 - index * 8 : count * 8 - 8 - index * 8]
        for index in range(count)
    ]


def _select_byte(vector: claripy.ast.BV, index: claripy.ast.BV) -> claripy.ast.BV:
    values = _bytes(vector, 256)
    selected = values[-1]
    for candidate in range(254, -1, -1):
        selected = claripy.If(index == candidate, values[candidate], selected)
    return selected


def _battle_transition(
    registers: dict[str, claripy.ast.BV],
    random_add: claripy.ast.BV,
    random_sub: claripy.ast.BV,
    div_first: claripy.ast.BV,
    div_second: claripy.ast.BV,
    loaded_bank: claripy.ast.BV,
    mapper_bank: claripy.ast.BV,
    link_state: claripy.ast.BV,
    list_index: claripy.ast.BV,
    random_numbers: claripy.ast.BV,
) -> tuple[
    dict[str, claripy.ast.BV],
    claripy.ast.BV,
    claripy.ast.BV,
    claripy.ast.BV,
    claripy.ast.BV,
    claripy.ast.BV,
]:
    post_cp = dict(registers)
    post_cp["a"] = link_state
    post_cp["f"] = _cp_flags(link_state, 4)
    add_out, sub_out, random_flags = _random_transition(
        post_cp["f"], random_add, random_sub, div_first, div_second
    )
    random_output = dict(post_cp)
    random_output["a"] = add_out
    random_output["f"] = random_flags

    next_index = list_index + 1
    selected = _select_byte(random_numbers, list_index)
    link_output = dict(post_cp)
    link_output["a"] = selected
    link_output["f"] = _cp_flags(next_index, 9)
    regenerate = next_index.UGE(9)
    number_bytes = _bytes(random_numbers, 256)
    regenerated = [
        number_bytes[index] * 5 + 1 if index < 9 else number_bytes[index]
        for index in range(256)
    ]
    regenerated_numbers = claripy.Concat(*regenerated)
    link_numbers = claripy.If(regenerate, regenerated_numbers, random_numbers)
    link_index = claripy.If(regenerate, claripy.BVV(0, 8), next_index)
    is_link = link_state == 4
    output = {
        name: claripy.If(is_link, link_output[name], random_output[name])
        for name in REGISTERS
    }
    random_call = claripy.If(
        is_link,
        claripy.BVV(0, 112),
        claripy.Concat(
            *(post_cp[name] for name in REGISTERS),
            random_add,
            random_sub,
            div_first,
            div_second,
            loaded_bank,
            mapper_bank,
        ),
    )
    return (
        output,
        claripy.If(is_link, random_add, add_out),
        claripy.If(is_link, random_sub, sub_out),
        claripy.If(is_link, link_index, list_index),
        claripy.If(is_link, link_numbers, random_numbers),
        random_call,
    )


def _battle_call(
    registers: dict[str, claripy.ast.BV],
    fields: tuple[claripy.ast.BV, ...],
) -> claripy.ast.BV:
    return claripy.Concat(*(registers[name] for name in REGISTERS), *fields)


class AssemblyBattleRandom(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        registers = assembly_registers(self.state)
        fields = (
            self.state.memory.load(H_RANDOM_ADD, 1),
            self.state.memory.load(H_RANDOM_SUB, 1),
            self.state.globals["div_first"],
            self.state.globals["div_second"],
            self.state.memory.load(H_LOADED_BANK, 1),
            self.state.memory.load(MAPPER_BANK, 1),
            self.state.memory.load(LINK_STATE, 1),
            self.state.memory.load(LIST_INDEX, 1),
            self.state.memory.load(RANDOM_NUMBERS, 256),
        )
        self.state.globals["battle_call"] = _battle_call(registers, fields)
        output, add, sub, index, numbers, random_call = _battle_transition(
            registers, *fields
        )
        for name in REGISTERS:
            value = output[name]
            setattr(
                self.state.regs,
                name,
                sm83_flags_to_z80(value) if name == "f" else value,
            )
        self.state.memory.store(H_RANDOM_ADD, add)
        self.state.memory.store(H_RANDOM_SUB, sub)
        self.state.memory.store(LIST_INDEX, index)
        self.state.memory.store(RANDOM_NUMBERS, numbers)
        self.state.globals["random_call"] = random_call
        self.jump(self._continuation)


class NativeBattleRandom(angr.SimProcedure):
    def run(self, address: claripy.ast.BV) -> None:  # type: ignore[override]
        registers = {
            name: self.state.memory.load(address + offset, 1)
            for offset, name in enumerate(REGISTERS)
        }
        fields = tuple(
            self.state.memory.load(address + offset, size)
            for offset, size in (
                (8, 1),
                (9, 1),
                (10, 1),
                (11, 1),
                (12, 1),
                (13, 1),
                (14, 1),
                (15, 1),
                (16, 256),
            )
        )
        self.state.globals["battle_call"] = _battle_call(registers, fields)
        output, add, sub, index, numbers, random_call = _battle_transition(
            registers, *fields
        )
        self.state.memory.store(
            address,
            claripy.Concat(
                *(output[name] for name in REGISTERS),
                add,
                sub,
                fields[2],
                fields[3],
                fields[4],
                fields[5],
                fields[6],
                index,
                numbers,
            ),
        )
        self.state.globals["random_call"] = random_call


def _multiply_call_snapshot(
    registers: dict[str, claripy.ast.BV],
    product: claripy.ast.BV,
    multiplier: claripy.ast.BV,
    buffer: claripy.ast.BV,
) -> claripy.ast.BV:
    return claripy.Concat(
        *(registers[name] for name in REGISTERS),
        product,
        multiplier,
        buffer,
        claripy.BVV(0x0D, 8),
        claripy.BVV(0x0D, 8),
    )


class AssemblyMultiply(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        caller = assembly_registers(self.state)
        callback = dict(caller)
        callback["a"] = claripy.BVV(0x0D, 8)
        callback["b"] = claripy.BVV(0x35, 8)
        callback["c"] = claripy.BVV(0xE4, 8)
        product = self.state.memory.load(H_PRODUCT, 4)
        multiplier = self.state.memory.load(H_MULTIPLIER, 1)
        buffer = self.state.memory.load(H_DIVIDE_BUFFER + 1, 4)
        self.state.globals["multiply_call"] = _multiply_call_snapshot(
            callback, product, multiplier, buffer
        )
        output, product, multiplier, buffer = _multiply_transition(
            callback, product, multiplier
        )
        self.state.regs.a = self.state.memory.load(H_LOADED_BANK, 1)
        self.state.regs.f = sm83_flags_to_z80(output["f"])
        self.state.memory.store(H_PRODUCT, product)
        self.state.memory.store(H_MULTIPLIER, multiplier)
        self.state.memory.store(H_DIVIDE_BUFFER + 1, buffer)
        self.state.memory.store(
            MAPPER_BANK, self.state.memory.load(H_LOADED_BANK, 1)
        )
        self.jump(self._continuation)


class NativeMultiply(angr.SimProcedure):
    def run(self, address: claripy.ast.BV) -> None:  # type: ignore[override]
        registers = {
            name: self.state.memory.load(address + offset, 1)
            for offset, name in enumerate(REGISTERS)
        }
        product = self.state.memory.load(address + 8, 4)
        multiplier = self.state.memory.load(address + 12, 1)
        buffer = self.state.memory.load(address + 13, 4)
        self.state.globals["multiply_call"] = claripy.Concat(
            self.state.memory.load(address, 17),
            self.state.memory.load(address + 17, 2),
        )
        output, product, multiplier, buffer = _multiply_transition(
            registers, product, multiplier
        )
        self.state.memory.store(
            address,
            claripy.Concat(
                *(output[name] for name in REGISTERS),
                product,
                multiplier,
                buffer,
            ),
        )


def _divide_call_snapshot(
    registers: dict[str, claripy.ast.BV],
    dividend: claripy.ast.BV,
    divisor: claripy.ast.BV,
    buffer: claripy.ast.BV,
    loaded: claripy.ast.BV,
    mapper: claripy.ast.BV,
) -> claripy.ast.BV:
    return claripy.Concat(
        *(registers[name] for name in REGISTERS),
        dividend,
        divisor,
        buffer,
        loaded,
        mapper,
    )


class AssemblyDivide(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        registers = assembly_registers(self.state)
        dividend = self.state.memory.load(H_PRODUCT, 4)
        divisor = self.state.memory.load(H_MULTIPLIER, 1)
        buffer = self.state.memory.load(H_DIVIDE_BUFFER, 5)
        self.state.globals["divide_call"] = _divide_call_snapshot(
            registers,
            dividend,
            divisor,
            buffer,
            self.state.memory.load(H_LOADED_BANK, 1),
            self.state.memory.load(MAPPER_BANK, 1),
        )
        quotient, remainder, buffer = _divide_outputs(
            registers["b"], dividend, divisor
        )
        self.state.memory.store(H_PRODUCT, quotient)
        self.state.memory.store(H_MULTIPLIER, remainder)
        self.state.memory.store(H_DIVIDE_BUFFER, buffer)
        self.jump(self._continuation)


class NativeDivide(angr.SimProcedure):
    def run(self, address: claripy.ast.BV) -> None:  # type: ignore[override]
        registers = {
            name: self.state.memory.load(address + offset, 1)
            for offset, name in enumerate(REGISTERS)
        }
        dividend = self.state.memory.load(address + 8, 4)
        divisor = self.state.memory.load(address + 12, 1)
        buffer = self.state.memory.load(address + 13, 5)
        self.state.globals["divide_call"] = _divide_call_snapshot(
            registers,
            dividend,
            divisor,
            buffer,
            self.state.memory.load(address + 18, 1),
            self.state.memory.load(address + 19, 1),
        )
        quotient, remainder, buffer = _divide_outputs(
            registers["b"], dividend, divisor
        )
        self.state.memory.store(address + 8, quotient)
        self.state.memory.store(address + 12, remainder)
        self.state.memory.store(address + 13, buffer)


def inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for field in (
        "random_add",
        "random_sub",
        "div_first",
        "div_second",
        "loaded_bank",
        "mapper_bank",
        "link_state",
        "list_index",
        "multiplier",
    ):
        values[field] = claripy.BVS(f"{prefix}_{field}", 8)
    values["random_numbers"] = claripy.BVS(f"{prefix}_random_numbers", 2048)
    values["damage"] = claripy.BVS(f"{prefix}_damage", 16)
    values["product"] = claripy.BVS(f"{prefix}_product", 32)
    values["divide_buffer"] = claripy.BVS(f"{prefix}_divide_buffer", 40)
    return values


def _initialize_globals(state: angr.SimState) -> None:
    state.globals["battle_call"] = claripy.BVV(0, 2176)
    state.globals["random_call"] = claripy.BVV(0, 112)
    state.globals["multiply_call"] = claripy.BVV(0, 152)
    state.globals["divide_call"] = claripy.BVV(0, 160)


def _setup_assembly(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    set_assembly_registers(state, values)
    state.memory.store(DAMAGE, values["damage"])
    state.memory.store(H_PRODUCT, values["product"])
    state.memory.store(H_MULTIPLIER, values["multiplier"])
    state.memory.store(H_DIVIDE_BUFFER, values["divide_buffer"])
    state.memory.store(H_RANDOM_ADD, values["random_add"])
    state.memory.store(H_RANDOM_SUB, values["random_sub"])
    state.globals["div_first"] = values["div_first"]
    state.globals["div_second"] = values["div_second"]
    state.memory.store(H_LOADED_BANK, values["loaded_bank"])
    state.memory.store(MAPPER_BANK, values["mapper_bank"])
    state.memory.store(LINK_STATE, values["link_state"])
    state.memory.store(LIST_INDEX, values["list_index"])
    state.memory.store(RANDOM_NUMBERS, values["random_numbers"])
    _initialize_globals(state)


def _setup_native(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    store_native_registers(state, NATIVE_STATE, values)
    for offset, field in enumerate(
        (
            "random_add",
            "random_sub",
            "div_first",
            "div_second",
            "loaded_bank",
            "mapper_bank",
            "link_state",
            "list_index",
        ),
        8,
    ):
        state.memory.store(NATIVE_STATE + offset, values[field])
    state.memory.store(NATIVE_STATE + 16, values["random_numbers"])
    state.memory.store(NATIVE_STATE + 272, values["damage"])
    state.memory.store(NATIVE_STATE + 274, values["product"])
    state.memory.store(NATIVE_STATE + 278, values["multiplier"])
    state.memory.store(NATIVE_STATE + 279, values["divide_buffer"])
    _initialize_globals(state)


def _assembly_endpoint(state: angr.SimState, done: int) -> Endpoint:
    return Endpoint(
        **assembly_registers(state),
        damage=state.memory.load(DAMAGE, 2),
        product=state.memory.load(H_PRODUCT, 4),
        multiplier=state.memory.load(H_MULTIPLIER, 1),
        divide_buffer=state.memory.load(H_DIVIDE_BUFFER, 5),
        random_add=state.memory.load(H_RANDOM_ADD, 1),
        random_sub=state.memory.load(H_RANDOM_SUB, 1),
        div_first=state.globals["div_first"],
        div_second=state.globals["div_second"],
        loaded_bank=state.memory.load(H_LOADED_BANK, 1),
        mapper_bank=state.memory.load(MAPPER_BANK, 1),
        link_state=state.memory.load(LINK_STATE, 1),
        list_index=state.memory.load(LIST_INDEX, 1),
        random_numbers=state.memory.load(RANDOM_NUMBERS, 256),
        battle_call=state.globals["battle_call"],
        random_call=state.globals["random_call"],
        multiply_call=state.globals["multiply_call"],
        divide_call=state.globals["divide_call"],
        done=claripy.BVV(done, 8),
        constraints=tuple(state.solver.constraints),
    )


def _native_endpoint(state: angr.SimState, done: claripy.ast.BV) -> Endpoint:
    return Endpoint(
        **native_registers(state, NATIVE_STATE),
        damage=state.memory.load(NATIVE_STATE + 272, 2),
        product=state.memory.load(NATIVE_STATE + 274, 4),
        multiplier=state.memory.load(NATIVE_STATE + 278, 1),
        divide_buffer=state.memory.load(NATIVE_STATE + 279, 5),
        random_add=state.memory.load(NATIVE_STATE + 8, 1),
        random_sub=state.memory.load(NATIVE_STATE + 9, 1),
        div_first=state.memory.load(NATIVE_STATE + 10, 1),
        div_second=state.memory.load(NATIVE_STATE + 11, 1),
        loaded_bank=state.memory.load(NATIVE_STATE + 12, 1),
        mapper_bank=state.memory.load(NATIVE_STATE + 13, 1),
        link_state=state.memory.load(NATIVE_STATE + 14, 1),
        list_index=state.memory.load(NATIVE_STATE + 15, 1),
        random_numbers=state.memory.load(NATIVE_STATE + 16, 256),
        battle_call=state.globals["battle_call"],
        random_call=state.globals["random_call"],
        multiply_call=state.globals["multiply_call"],
        divide_call=state.globals["divide_call"],
        done=done,
        constraints=tuple(state.solver.constraints),
    )


@cache
def _assembly_project() -> tuple[angr.Project, int]:
    location = symbol_location(SYMS, "RandomizeDamage")
    battle = symbol_location(SYMS, "BattleRandom")
    multiply = symbol_location(SYMS, "Multiply")
    divide = symbol_location(SYMS, "Divide")
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
    project.hook(base + 3, Sm83LoadAAtHlIncrement(base + 4), length=1)
    project.hook(base + 4, Sm83AndRegister("a", base + 5), length=1)
    project.hook(base + 8, Sm83CpImmediate(2, base + 10), length=2)
    project.hook(base + 12, Sm83StoreAHighImmediate(0x96, base + 14), length=2)
    project.hook(base + 15, Sm83LoadAAtHlIncrement(base + 16), length=1)
    project.hook(base + 16, Sm83StoreAHighImmediate(0x97, base + 18), length=2)
    project.hook(base + 19, Sm83StoreAHighImmediate(0x98, base + 21), length=2)
    project.hook(base + 21, AssemblyBattleRandom(base + 24), length=3)
    project.hook(base + 24, Sm83Rrca(base + 25), length=1)
    project.hook(base + 25, Sm83CpImmediate(217, base + 27), length=2)
    project.hook(base + 29, Sm83StoreAHighImmediate(0x99, base + 31), length=2)
    project.hook(base + 36, Sm83StoreAHighImmediate(0x99, base + 38), length=2)
    project.hook(base + 43, Sm83LoadAHighImmediate(0x97, base + 45), length=2)
    project.hook(base + 48, Sm83StoreAAtHlIncrement(base + 49), length=1)
    project.hook(base + 49, Sm83LoadAHighImmediate(0x98, base + 51), length=2)

    project.hook(multiply.address + 7, AssemblyMultiply(multiply.address + 10), length=3)
    project.hook(divide.address + 3, Sm83LoadAHighImmediate(0xB8, divide.address + 5), length=2)
    project.hook(divide.address + 8, Sm83StoreAHighImmediate(0xB8, divide.address + 10), length=2)
    project.hook(divide.address + 10, Sm83StoreAImmediate(MAPPER_BANK, divide.address + 13), length=3)
    project.hook(divide.address + 13, AssemblyDivide(divide.address + 16), length=3)
    project.hook(divide.address + 17, Sm83StoreAHighImmediate(0xB8, divide.address + 19), length=2)
    project.hook(divide.address + 19, Sm83StoreAImmediate(MAPPER_BANK, divide.address + 22), length=3)
    return project, base


@cache
def _native_project() -> angr.Project:
    project = angr.Project(ELF, auto_load_libs=False)
    battle = project.loader.find_symbol("port_battle_random")
    multiply = project.loader.find_symbol("port_multiply")
    divide = project.loader.find_symbol("port_divide")
    assert battle is not None and multiply is not None and divide is not None
    project.hook(battle.rebased_addr, NativeBattleRandom())
    project.hook(multiply.rebased_addr, NativeMultiply())
    project.hook(divide.rebased_addr, NativeDivide())
    return project


def _collect_boundaries(
    manager: angr.SimulationManager, boundaries: tuple[int, ...]
) -> list[angr.SimState]:
    manager.step()
    manager.stashes["completed"] = []
    while manager.active:
        manager.move(
            from_stash="active",
            to_stash="completed",
            filter_func=lambda candidate: candidate.addr in boundaries,
        )
        if manager.active:
            manager.step()
    assert not manager.errored
    return manager.completed


def assembly_begin(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, base = _assembly_project()
    state = project.factory.blank_state(addr=base)
    _setup_assembly(state, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    ends = _collect_boundaries(
        project.factory.simulation_manager(state), (base + 21, RETURN)
    )
    return [_assembly_endpoint(end, 1 if end.addr == RETURN else 0) for end in ends]


def native_begin(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = _native_project()
    function = project.loader.find_symbol("port_randomize_damage_begin")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    _setup_native(state, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [_native_endpoint(end, end.regs.rax[7:0]) for end in manager.deadended]


def assembly_step(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, base = _assembly_project()
    state = project.factory.blank_state(addr=base + 21)
    _setup_assembly(state, values)
    ends = _collect_boundaries(
        project.factory.simulation_manager(state), (base + 21, base + 29)
    )
    return [_assembly_endpoint(end, 1 if end.addr == base + 29 else 0) for end in ends]


def native_step(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = _native_project()
    function = project.loader.find_symbol("port_randomize_damage_random_step")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    _setup_native(state, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [_native_endpoint(end, end.regs.rax[7:0]) for end in manager.deadended]


def assembly_finish(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, base = _assembly_project()
    state = project.factory.blank_state(addr=base + 29)
    _setup_assembly(state, values)
    state.solver.add(values["a"].UGE(217))
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    ends = collect_returns(project, state, RETURN)
    return [_assembly_endpoint(end, 1) for end in ends]


def native_finish(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = _native_project()
    function = project.loader.find_symbol("port_randomize_damage_finish")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    _setup_native(state, values)
    state.solver.add(values["a"].UGE(217))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [_native_endpoint(end, claripy.BVV(1, 8)) for end in manager.deadended]


OBSERVABLES = (
    *REGISTERS,
    "damage",
    "product",
    "multiplier",
    "divide_buffer",
    "random_add",
    "random_sub",
    "div_first",
    "div_second",
    "loaded_bank",
    "mapper_bank",
    "link_state",
    "list_index",
    "random_numbers",
    "battle_call",
    "random_call",
    "multiply_call",
    "divide_call",
    "done",
)


def _assert_complete_domain(endpoints: list[Endpoint]) -> None:
    solver = claripy.Solver()
    solver.add(
        claripy.Not(
            claripy.Or(
                *(claripy.And(*endpoint.constraints) for endpoint in endpoints)
            )
        )
    )
    assert not solver.satisfiable()


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(), reason="build")
def test_randomize_damage_pathwise_equivalence() -> None:
    begin_values = inputs("randomize_damage_begin")
    assembly_begins = assembly_begin(begin_values)
    native_begins = native_begin(begin_values)
    _assert_complete_domain(assembly_begins)
    _assert_complete_domain(native_begins)
    assert_pathwise_equivalent(assembly_begins, native_begins, OBSERVABLES)

    step_values = inputs("randomize_damage_step")
    assembly_steps = assembly_step(step_values)
    native_steps = native_step(step_values)
    _assert_complete_domain(assembly_steps)
    _assert_complete_domain(native_steps)
    assert_pathwise_equivalent(assembly_steps, native_steps, OBSERVABLES)

    finish_values = inputs("randomize_damage_finish")
    assert_pathwise_equivalent(
        assembly_finish(finish_values), native_finish(finish_values), OBSERVABLES
    )
