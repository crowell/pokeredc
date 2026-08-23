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

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
MARKER = 0x1234
DONE = 0xEFFF
EXPECTED = bytes.fromhex("21a0c3cda60efa26d5e0d1fa27d5e0d23e02e0d0c9")
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
    marker: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class CopySummary(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        registers = assembly_registers(self.state)
        self.state.globals["call"] = claripy.Concat(
            *(registers[r] for r in REGISTERS), self.state.memory.load(MARKER, 1)
        )
        for register in REGISTERS:
            value = self.state.globals["callee_" + register]
            if register == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, register, value)
        self.state.memory.store(MARKER, self.state.globals["callee_marker"])
        self.jump(self.next_address)


class NativeCopySummary(angr.SimProcedure):
    def run(
        self, registers: claripy.ast.BV, memory: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        self.state.globals["call"] = claripy.Concat(
            self.state.memory.load(registers, 8),
            self.state.memory.load(memory + MARKER, 1),
        )
        for offset, register in enumerate(REGISTERS):
            self.state.memory.store(
                registers + offset, self.state.globals["callee_" + register]
            )
        self.state.memory.store(
            memory + MARKER, self.state.globals["callee_marker"]
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


class Finish(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(DONE)


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for field in FIELDS:
        values[field] = claripy.BVS(f"{prefix}_{field}", 8)
    for register in REGISTERS:
        values["callee_" + register] = (
            claripy.Concat(
                claripy.BVS(f"{prefix}_callee_flags", 4), claripy.BVV(0, 4)
            )
            if register == "f"
            else claripy.BVS(f"{prefix}_callee_{register}", 8)
        )
    values["marker"] = claripy.BVS(f"{prefix}_marker", 8)
    values["callee_marker"] = claripy.BVS(f"{prefix}_callee_marker", 8)
    return values


def _setup(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    for field in FIELDS:
        state.globals[field] = values[field]
    for register in REGISTERS:
        state.globals["callee_" + register] = values["callee_" + register]
    state.globals["callee_marker"] = values["callee_marker"]
    state.globals["call"] = claripy.BVV(0, 72)


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "ScheduleNorthRowRedraw")
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
    project.hook(base + 3, CopySummary(base + 6), length=3)
    project.hook(base + 6, LoadField("map_view_vram_low", base + 9), length=3)
    project.hook(base + 9, StoreField("redraw_dest_low", base + 11), length=2)
    project.hook(
        base + 11, LoadField("map_view_vram_high", base + 14), length=3
    )
    project.hook(base + 14, StoreField("redraw_dest_high", base + 16), length=2)
    project.hook(base + 18, StoreField("redraw_mode", base + 20), length=2)
    project.hook(base + 20, Finish(), length=1)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _setup(state, values)
    state.memory.store(MARKER, values["marker"])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE)
    assert not manager.errored
    return [
        Endpoint(
            **assembly_registers(end),
            fields=claripy.Concat(*(end.globals[field] for field in FIELDS)),
            call=end.globals["call"],
            marker=end.memory.load(MARKER, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_schedule_north_row_redraw")
    callee = project.loader.find_symbol("port_copy_to_redraw_src_tiles")
    assert function is not None and callee is not None
    project.hook(callee.rebased_addr, NativeCopySummary())
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    for offset, field in enumerate(FIELDS, 8):
        state.memory.store(NATIVE_STATE + offset, values[field])
    _setup(state, values)
    state.memory.store(NATIVE_MEMORY + MARKER, values["marker"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            fields=end.memory.load(NATIVE_STATE + 8, len(FIELDS)),
            call=end.globals["call"],
            marker=end.memory.load(NATIVE_MEMORY + MARKER, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_schedule_north_row_redraw_pathwise_equivalence() -> None:
    values = _inputs("schedule_north_row_redraw")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "fields", "call", "marker"),
    )
