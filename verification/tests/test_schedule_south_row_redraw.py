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
from verification.harness.rom import linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair
from verification.tests.test_schedule_north_row_redraw import (
    Endpoint,
    FIELDS,
    Finish,
    LoadField,
    MARKER,
    NativeCopySummary,
    StoreField,
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
EXPECTED = bytes.fromhex(
    "21e0c4cda60efa26d56ffa27d567010002097ce603f698e0d27de0d13e02e0d0c9"
)


class CopySummary(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        registers = assembly_registers(self.state)
        self.state.globals["call"] = claripy.Concat(
            *(registers[r] for r in REGISTERS), self.state.memory.load(MARKER, 1)
        )
        from verification.harness.rom import sm83_flags_to_z80

        for register in REGISTERS:
            value = self.state.globals["callee_" + register]
            if register == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, register, value)
        self.state.memory.store(MARKER, self.state.globals["callee_marker"])
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


class OrImmediate(AndImmediate):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a |= self.value
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x40, 8),
            claripy.BVV(0, 8),
        )
        self.jump(self.next_address)


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "ScheduleSouthRowRedraw")
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
    project.hook(
        base + 10, LoadField("map_view_vram_high", base + 13), length=3
    )
    project.hook(
        base + 17, Sm83AddHlRegisterPair("bc", base + 18), length=1
    )
    project.hook(base + 19, AndImmediate(3, base + 21), length=2)
    project.hook(base + 21, OrImmediate(0x98, base + 23), length=2)
    project.hook(base + 23, StoreField("redraw_dest_high", base + 25), length=2)
    project.hook(base + 26, StoreField("redraw_dest_low", base + 28), length=2)
    project.hook(base + 30, StoreField("redraw_mode", base + 32), length=2)
    project.hook(base + 32, Finish(), length=1)
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
    function = project.loader.find_symbol("port_schedule_south_row_redraw")
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
def test_schedule_south_row_redraw_pathwise_equivalence() -> None:
    values = _inputs("schedule_south_row_redraw")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "fields", "call", "marker"),
    )
