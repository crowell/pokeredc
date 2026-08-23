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
from verification.harness.sm83_shims import Sm83AddImmediate

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF
SOURCE = 0xC3B2
DESTINATION = 0xCBFC
EXPECTED = bytes.fromhex(
    "21b2c3cdf20efa26d54fe6e04779c612e61fb0e0d1fa27d5e0d23e01e0d0c9"
)
FIELDS = (
    "map_view_vram_low",
    "map_view_vram_high",
    "redraw_dest_low",
    "redraw_dest_high",
    "redraw_mode",
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
    fields: claripy.ast.BV
    call: claripy.ast.BV
    writes: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _source_address(index: int) -> int:
    return SOURCE + (index // 2) * 20 + (index & 1)


class ColumnSummary(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        registers = assembly_registers(self.state)
        reads = tuple(
            self.state.memory.load(_source_address(index), 1)
            for index in range(36)
        )
        self.state.globals["call"] = claripy.Concat(
            *(registers[r] for r in REGISTERS), *reads
        )
        for register in REGISTERS:
            value = self.state.globals["callee_" + register]
            if register == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, register, value)
        for index in range(36):
            self.state.memory.store(
                DESTINATION + index, self.state.globals[f"callee_write{index}"]
            )
        self.jump(self.next_address)


class NativeColumnSummary(angr.SimProcedure):
    def run(self, copy: claripy.ast.BV) -> None:  # type: ignore[override]
        self.state.globals["call"] = self.state.memory.load(copy, 44)
        for offset, register in enumerate(REGISTERS):
            self.state.memory.store(
                copy + offset, self.state.globals["callee_" + register]
            )
        for index in range(36):
            self.state.memory.store(
                copy + 44 + index,
                self.state.globals[f"callee_write{index}"],
            )


class LoadField(angr.SimProcedure):
    def __init__(self, field: str, next_address: int):
        super().__init__()
        self.field = field
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals[self.field]
        self.jump(self.next_address)


class StoreField(LoadField):
    def run(self) -> None:  # type: ignore[override]
        self.state.globals[self.field] = self.state.regs.a
        self.jump(self.next_address)


class AndImmediate(angr.SimProcedure):
    def __init__(self, value: int, next_address: int):
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


class OrRegister(angr.SimProcedure):
    def __init__(self, register: str, next_address: int):
        super().__init__()
        self.register = register
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a |= getattr(self.state.regs, self.register)
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x40, 8),
            claripy.BVV(0, 8),
        )
        self.jump(self.next_address)


class Finish(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(DONE)


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for field in FIELDS:
        values[field] = claripy.BVS(f"{prefix}_{field}", 8)
    values["reads"] = claripy.BVS(f"{prefix}_reads", 36 * 8)
    values["callee_writes"] = claripy.BVS(
        f"{prefix}_callee_writes", 36 * 8
    )
    for register in REGISTERS:
        values["callee_" + register] = (
            claripy.Concat(
                claripy.BVS(f"{prefix}_callee_flags", 4), claripy.BVV(0, 4)
            )
            if register == "f"
            else claripy.BVS(f"{prefix}_callee_{register}", 8)
        )
    return values


def _byte(vector: claripy.ast.BV, index: int) -> claripy.ast.BV:
    high = vector.size() - index * 8 - 1
    return vector[high : high - 7]


def _setup(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    for field in FIELDS:
        state.globals[field] = values[field]
    for register in REGISTERS:
        state.globals["callee_" + register] = values["callee_" + register]
    for index in range(36):
        state.globals[f"callee_write{index}"] = _byte(
            values["callee_writes"], index
        )
    state.globals["call"] = claripy.BVV(0, 44 * 8)


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "ScheduleEastColumnRedraw")
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
    project.hook(base + 3, ColumnSummary(base + 6), length=3)
    project.hook(base + 6, LoadField("map_view_vram_low", base + 9), length=3)
    project.hook(base + 10, AndImmediate(0xE0, base + 12), length=2)
    project.hook(base + 14, Sm83AddImmediate(18, base + 16), length=2)
    project.hook(base + 16, AndImmediate(0x1F, base + 18), length=2)
    project.hook(base + 18, OrRegister("b", base + 19), length=1)
    project.hook(base + 19, StoreField("redraw_dest_low", base + 21), length=2)
    project.hook(
        base + 21, LoadField("map_view_vram_high", base + 24), length=3
    )
    project.hook(base + 24, StoreField("redraw_dest_high", base + 26), length=2)
    project.hook(base + 28, StoreField("redraw_mode", base + 30), length=2)
    project.hook(base + 30, Finish(), length=1)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _setup(state, values)
    for index in range(36):
        state.memory.store(_source_address(index), _byte(values["reads"], index))
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE)
    assert not manager.errored
    return [
        Endpoint(
            **assembly_registers(end),
            fields=claripy.Concat(*(end.globals[field] for field in FIELDS)),
            call=end.globals["call"],
            writes=end.memory.load(DESTINATION, 36),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_schedule_east_column_redraw")
    callee = project.loader.find_symbol("port_schedule_column_redraw_helper")
    assert function is not None and callee is not None
    project.hook(callee.rebased_addr, NativeColumnSummary())
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    for offset, field in enumerate(FIELDS, 8):
        state.memory.store(NATIVE_STATE + offset, values[field])
    _setup(state, values)
    for index in range(36):
        state.memory.store(
            NATIVE_MEMORY + _source_address(index), _byte(values["reads"], index)
        )
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            fields=end.memory.load(NATIVE_STATE + 8, len(FIELDS)),
            call=end.globals["call"],
            writes=end.memory.load(NATIVE_MEMORY + DESTINATION, 36),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_schedule_east_column_redraw_pathwise_equivalence() -> None:
    values = _inputs("schedule_east_column_redraw")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "fields", "call", "writes"),
    )
