from __future__ import annotations

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
)
from verification.harness.rom import (
    linked_bytes,
    rom_window,
    sm83_flags_to_z80,
    symbol_location,
)
from verification.tests.test_schedule_east_column_redraw import (
    DESTINATION,
    Endpoint,
    FIELDS,
    Finish,
    LoadField,
    NativeColumnSummary,
    StoreField,
    _byte,
    _inputs,
    _setup,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF
SOURCE = 0xC3A0
EXPECTED = bytes.fromhex("21a0c3cdf20efa26d5e0d1fa27d5e0d23e01e0d0c9")


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


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "ScheduleWestColumnRedraw")
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
    function = project.loader.find_symbol("port_schedule_west_column_redraw")
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
def test_schedule_west_column_redraw_pathwise_equivalence() -> None:
    values = _inputs("schedule_west_column_redraw")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "fields", "call", "writes"),
    )
