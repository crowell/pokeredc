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
SERIAL = 0xCC3D
MARKER = 0x1234
DONE = 0xEFFF
EXPECTED = bytes.fromhex("fa3dcc2155c4011400cd873a36ecc9")
FIELDS = ("received", "written", "write_h", "write_l")


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
    state: claripy.ast.BV
    call: claripy.ast.BV
    serial: claripy.ast.BV
    marker: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class LoadSerial(angr.SimProcedure):
    def __init__(self, target: int):
        super().__init__()
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        value = self.state.memory.load(SERIAL, 1)
        self.state.regs.a = value
        self.state.globals["received"] = value
        self.jump(self.target)


class AddNTimesSummary(angr.SimProcedure):
    def __init__(self, target: int):
        super().__init__()
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        registers = assembly_registers(self.state)
        self.state.globals["call"] = claripy.Concat(
            *(registers[register] for register in REGISTERS)
        )
        for register in REGISTERS:
            value = self.state.globals["out_" + register]
            if register == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, register, value)
        self.jump(self.target)


class NativeAddNTimesSummary(angr.SimProcedure):
    def run(self, registers: claripy.ast.BV) -> None:  # type: ignore[override]
        self.state.globals["call"] = self.state.memory.load(registers, 8)
        self.state.memory.store(
            registers,
            claripy.Concat(
                *(self.state.globals["out_" + register]
                  for register in REGISTERS)
            ),
        )


class WriteCursor(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        address = self.state.regs.hl
        self.state.memory.store(address, claripy.BVV(0xEC, 8))
        self.state.globals["written"] = claripy.BVV(0xEC, 8)
        self.state.globals["write_h"] = self.state.regs.h
        self.state.globals["write_l"] = self.state.regs.l
        self.jump(DONE)


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for field in FIELDS:
        values[field] = claripy.BVS(f"{prefix}_{field}", 8)
    for register in REGISTERS:
        values["out_" + register] = (
            claripy.Concat(
                claripy.BVS(f"{prefix}_out_flags", 4), claripy.BVV(0, 4)
            )
            if register == "f"
            else claripy.BVS(f"{prefix}_out_{register}", 8)
        )
    values["serial"] = claripy.BVS(f"{prefix}_serial", 8)
    values["marker"] = claripy.BVS(f"{prefix}_marker", 8)
    return values


def _setup(
    state: angr.SimState, values: dict[str, claripy.ast.BV]
) -> None:
    for field in FIELDS:
        state.globals[field] = values[field]
    for register in REGISTERS:
        state.globals["out_" + register] = values["out_" + register]
    state.globals["call"] = claripy.BVV(0, 64)


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(
        SYMBOLS, "TradeCenter_PlaceSelectedEnemyMonMenuCursor"
    )
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0, "entry_point": location.address,
        },
    )
    base = location.address
    project.hook(base, LoadSerial(base + 3), length=3)
    project.hook(base + 9, AddNTimesSummary(base + 12), length=3)
    project.hook(base + 12, WriteCursor(), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _setup(state, values)
    state.memory.store(SERIAL, values["serial"])
    state.memory.store(MARKER, values["marker"])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE)
    assert not manager.errored
    return [
        Endpoint(
            **assembly_registers(end),
            state=claripy.Concat(
                *(end.globals[field] for field in FIELDS)
            ),
            call=end.globals["call"],
            serial=end.memory.load(SERIAL, 1),
            marker=end.memory.load(MARKER, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(
        "port_trade_center_place_selected_enemy_mon_menu_cursor"
    )
    add = project.loader.find_symbol("port_add_n_times")
    assert function is not None and add is not None
    project.hook(add.rebased_addr, NativeAddNTimesSummary())
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    for offset, field in enumerate(FIELDS, 8):
        state.memory.store(NATIVE_STATE + offset, values[field])
    _setup(state, values)
    state.memory.store(NATIVE_MEMORY + SERIAL, values["serial"])
    state.memory.store(NATIVE_MEMORY + MARKER, values["marker"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            state=end.memory.load(NATIVE_STATE + 8, len(FIELDS)),
            call=end.globals["call"],
            serial=end.memory.load(NATIVE_MEMORY + SERIAL, 1),
            marker=end.memory.load(NATIVE_MEMORY + MARKER, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_trade_center_cursor_pathwise_equivalence() -> None:
    values = _inputs("trade_center_cursor")
    assert_pathwise_equivalent(
        _assembly(values), _native(values),
        (*REGISTERS, "state", "call", "serial", "marker"),
    )
