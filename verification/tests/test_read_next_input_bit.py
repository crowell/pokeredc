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
from verification.harness.rom import (
    linked_bytes,
    rom_window,
    sm83_flags_to_z80,
    symbol_location,
)
from verification.harness.sm83_shims import (
    Sm83DecRegister,
    Sm83LoadAImmediate,
    Sm83StoreAImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF

INPUT_CUR_BYTE = 0xD0A5
INPUT_BIT_COUNTER = 0xD0A6
INPUT_POINTER = 0xD0AB
EXPECTED = bytes.fromhex(
    "faa6d03d2008cd8b26eaa5d03e08eaa6d0faa5d007eaa5d0e601c9"
)
CALL_SIZE = 8 + 3


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
    call_valid: claripy.ast.BV
    call: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["pointer_low"] = claripy.BVS(f"{prefix}_pointer_low", 8)
    values["pointer_high"] = claripy.BVS(f"{prefix}_pointer_high", 8)
    values["current"] = claripy.BVS(f"{prefix}_current", 8)
    values["counter"] = claripy.BVS(f"{prefix}_counter", 8)
    values["source"] = claripy.BVS(f"{prefix}_source", 8)
    for register in REGISTERS:
        values[f"post_{register}"] = (
            claripy.Concat(
                claripy.BVS(f"{prefix}_post_flags", 4),
                claripy.BVV(0, 4),
            )
            if register == "f"
            else claripy.BVS(f"{prefix}_post_{register}", 8)
        )
    values["post_pointer_low"] = claripy.BVS(
        f"{prefix}_post_pointer_low", 8
    )
    values["post_pointer_high"] = claripy.BVS(
        f"{prefix}_post_pointer_high", 8
    )
    return values


def _pointer(values: dict[str, claripy.ast.BV]) -> claripy.ast.BV:
    return claripy.Concat(values["pointer_high"], values["pointer_low"])


def _setup(
    state: angr.SimState,
    values: dict[str, claripy.ast.BV],
    native: bool,
) -> None:
    base = NATIVE_MEMORY if native else 0
    pointer = _pointer(values)
    state.solver.add(pointer.UGE(0x4000), pointer.ULE(0x7FFF))
    state.memory.store(base + INPUT_POINTER, values["pointer_low"])
    state.memory.store(base + INPUT_POINTER + 1, values["pointer_high"])
    state.memory.store(base + INPUT_CUR_BYTE, values["current"])
    state.memory.store(base + INPUT_BIT_COUNTER, values["counter"])
    address = (
        claripy.ZeroExt(48, pointer) + NATIVE_MEMORY if native else pointer
    )
    state.memory.store(address, values["source"])
    state.globals["call_valid"] = claripy.BVV(0, 8)
    state.globals["call"] = claripy.BVV(0, CALL_SIZE * 8)


def _source(
    state: angr.SimState,
    values: dict[str, claripy.ast.BV],
    native: bool,
) -> claripy.ast.BV:
    pointer = _pointer(values)
    address = (
        claripy.ZeroExt(48, pointer) + NATIVE_MEMORY if native else pointer
    )
    return state.memory.load(address, 1)


def _memory(
    state: angr.SimState,
    values: dict[str, claripy.ast.BV],
    native: bool,
) -> claripy.ast.BV:
    base = NATIVE_MEMORY if native else 0
    return claripy.Concat(
        state.memory.load(base + INPUT_POINTER, 2),
        state.memory.load(base + INPUT_CUR_BYTE, 1),
        state.memory.load(base + INPUT_BIT_COUNTER, 1),
        _source(state, values, native),
    )


def _assembly_call(state: angr.SimState) -> claripy.ast.BV:
    low = state.memory.load(INPUT_POINTER, 1)
    high = state.memory.load(INPUT_POINTER + 1, 1)
    pointer = claripy.Concat(high, low)
    return claripy.Concat(
        *(assembly_registers(state)[name] for name in REGISTERS),
        low,
        high,
        state.memory.load(pointer, 1),
    )


def _native_call(
    state: angr.SimState, address: claripy.ast.BV
) -> claripy.ast.BV:
    return claripy.Concat(
        *(native_registers(state, address)[name] for name in REGISTERS),
        state.memory.load(address + 8, 1),
        state.memory.load(address + 9, 1),
        state.memory.load(address + 10, 1),
    )


def _apply_assembly_post(
    state: angr.SimState, values: dict[str, claripy.ast.BV]
) -> None:
    for register in REGISTERS:
        value = values[f"post_{register}"]
        if register == "f":
            value = sm83_flags_to_z80(value)
        setattr(state.regs, register, value)
    state.memory.store(INPUT_POINTER, values["post_pointer_low"])
    state.memory.store(INPUT_POINTER + 1, values["post_pointer_high"])


def _apply_native_post(
    state: angr.SimState,
    values: dict[str, claripy.ast.BV],
    address: claripy.ast.BV,
) -> None:
    for offset, register in enumerate(REGISTERS):
        state.memory.store(address + offset, values[f"post_{register}"])
    state.memory.store(address + 8, values["post_pointer_low"])
    state.memory.store(address + 9, values["post_pointer_high"])


class ForkOnNZ(angr.SimProcedure):
    def __init__(self, taken: int, fallthrough: int) -> None:
        super().__init__()
        self.taken = taken
        self.fallthrough = fallthrough

    def run(self) -> None:  # type: ignore[override]
        condition = ((self.state.regs.f >> 6) & 1) == 0
        taken = self.state.copy()
        fallthrough = self.state.copy()
        taken.solver.add(condition)
        fallthrough.solver.add(claripy.Not(condition))
        taken.regs.ip = claripy.BVV(self.taken, 16)
        fallthrough.regs.ip = claripy.BVV(self.fallthrough, 16)
        self.inhibit_autoret = True
        self.successors.add_successor(
            taken, self.taken, condition, "Ijk_Boring"
        )
        self.successors.add_successor(
            fallthrough,
            self.fallthrough,
            claripy.Not(condition),
            "Ijk_Boring",
        )


class LoadAImmediate(angr.SimProcedure):
    def __init__(self, value: int, next_address: int) -> None:
        super().__init__()
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(self.value, 8)
        self.jump(self.next_address)


class Rlca(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        value = self.state.regs.a
        self.state.regs.a = claripy.RotateLeft(value, 1)
        self.state.regs.f = claripy.ZeroExt(7, value[7])
        self.jump(self.next_address)


class Sm83AndImmediateCorrect(angr.SimProcedure):
    def __init__(self, value: int, next_address: int) -> None:
        super().__init__()
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a &= self.value
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x50, 8),
            claripy.BVV(0x10, 8),
        )
        self.jump(self.next_address)


class AssemblyReadByteBoundary(angr.SimProcedure):
    def __init__(
        self, values: dict[str, claripy.ast.BV], next_address: int
    ) -> None:
        super().__init__()
        self.values = values
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["call_valid"] = claripy.BVV(1, 8)
        self.state.globals["call"] = _assembly_call(self.state)
        _apply_assembly_post(self.state, self.values)
        self.jump(self.next_address)


class NativeReadByteBoundary(angr.SimProcedure):
    def __init__(self, values: dict[str, claripy.ast.BV]) -> None:
        super().__init__()
        self.values = values

    def run(self, address: claripy.ast.BV) -> None:  # type: ignore[override]
        self.state.globals["call_valid"] = claripy.BVV(1, 8)
        self.state.globals["call"] = _native_call(self.state, address)
        _apply_native_post(self.state, self.values, address)


class Done(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(DONE)


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "ReadNextInputBit")
    end = symbol_location(SYMBOLS, "ReadNextInputByte")
    assert location.bank == end.bank == 0
    assert end.address - location.address == len(EXPECTED)
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
    project.hook(base, Sm83LoadAImmediate(INPUT_BIT_COUNTER, base + 3), length=3)
    project.hook(base + 3, Sm83DecRegister("a", base + 4), length=1)
    project.hook(base + 4, ForkOnNZ(base + 14, base + 6), length=2)
    project.hook(
        base + 6, AssemblyReadByteBoundary(values, base + 9), length=3
    )
    project.hook(base + 9, Sm83StoreAImmediate(INPUT_CUR_BYTE, base + 12), length=3)
    project.hook(base + 12, LoadAImmediate(8, base + 14), length=2)
    project.hook(
        base + 14, Sm83StoreAImmediate(INPUT_BIT_COUNTER, base + 17), length=3
    )
    project.hook(base + 17, Sm83LoadAImmediate(INPUT_CUR_BYTE, base + 20), length=3)
    project.hook(base + 20, Rlca(base + 21), length=1)
    project.hook(base + 21, Sm83StoreAImmediate(INPUT_CUR_BYTE, base + 24), length=3)
    project.hook(
        base + 24, Sm83AndImmediateCorrect(1, base + 26), length=2
    )
    project.hook(base + 26, Done(), length=1)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _setup(state, values, native=False)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=2)
    assert not manager.errored and len(manager.found) == 2
    return [
        Endpoint(
            **assembly_registers(final),
            memory=_memory(final, values, native=False),
            call_valid=final.globals["call_valid"],
            call=final.globals["call"],
            constraints=tuple(final.solver.constraints),
        )
        for final in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_read_next_input_bit")
    read_byte = project.loader.find_symbol("port_read_next_input_byte")
    assert function is not None and read_byte is not None
    project.hook(read_byte.rebased_addr, NativeReadByteBoundary(values))
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, values, native=True)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 2
    return [
        Endpoint(
            **native_registers(final, NATIVE_STATE),
            memory=_memory(final, values, native=True),
            call_valid=final.globals["call_valid"],
            call=final.globals["call"],
            constraints=tuple(final.solver.constraints),
        )
        for final in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(
    not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`"
)
def test_read_next_input_bit_pathwise_equivalence() -> None:
    values = _inputs("read_next_input_bit")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "memory", "call_valid", "call"),
    )
