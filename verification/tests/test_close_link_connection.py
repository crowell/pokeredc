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
EXPECTED = bytes.fromhex("cdd73d3effe0aa3e02e001afe0ad3e80e002c9")
FIELDS = (
    "connection_status",
    "serial_send_data",
    "serial_receive_data",
    "serial_control",
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
    state: claripy.ast.BV
    call: claripy.ast.BV
    marker: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class DelaySummary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        registers = assembly_registers(self.state)
        self.state.globals["call"] = claripy.Concat(
            *(registers[register] for register in REGISTERS),
            self.state.globals["marker"],
        )
        for register in REGISTERS:
            value = self.state.globals["out_" + register]
            if register == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, register, value)
        self.state.globals["marker"] = self.state.globals["out_marker"]
        self.jump(self.state.addr + 3)


class NativeDelaySummary(angr.SimProcedure):
    def run(
        self, registers: claripy.ast.BV, memory: claripy.ast.BV | None = None
    ) -> None:  # type: ignore[override]
        if memory is None:
            memory = self.state.regs.rsi
        self.state.globals["call"] = claripy.Concat(
            self.state.memory.load(registers, 8),
            self.state.memory.load(memory + MARKER, 1),
        )
        self.state.memory.store(
            registers,
            claripy.Concat(
                *(self.state.globals["out_" + register]
                  for register in REGISTERS)
            ),
        )
        self.state.memory.store(
            memory + MARKER, self.state.globals["out_marker"]
        )


class LoadImmediate(angr.SimProcedure):
    def __init__(self, value: int, target: int):
        super().__init__()
        self.value = value
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.value
        self.jump(self.target)


class StoreField(angr.SimProcedure):
    def __init__(self, field: str, target: int):
        super().__init__()
        self.field = field
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.state.globals[self.field] = self.state.regs.a
        self.jump(self.target)


class XorA(angr.SimProcedure):
    def __init__(self, target: int):
        super().__init__()
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = 0
        self.state.regs.f = 0x40
        self.jump(self.target)


class Finish(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
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
    values["marker"] = claripy.BVS(f"{prefix}_marker", 8)
    values["out_marker"] = claripy.BVS(f"{prefix}_out_marker", 8)
    return values


def _setup(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    for field in FIELDS:
        state.globals[field] = values[field]
    for register in REGISTERS:
        state.globals["out_" + register] = values["out_" + register]
    state.globals["marker"] = values["marker"]
    state.globals["out_marker"] = values["out_marker"]
    state.globals["call"] = claripy.BVV(0, 72)


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "CloseLinkConnection")
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
    project.hook(base, DelaySummary(), length=3)
    project.hook(base + 3, LoadImmediate(0xFF, base + 5), length=2)
    project.hook(base + 5, StoreField("connection_status", base + 7), length=2)
    project.hook(base + 7, LoadImmediate(2, base + 9), length=2)
    project.hook(base + 9, StoreField("serial_send_data", base + 11), length=2)
    project.hook(base + 11, XorA(base + 12), length=1)
    project.hook(base + 12, StoreField("serial_receive_data", base + 14), length=2)
    project.hook(base + 14, LoadImmediate(0x80, base + 16), length=2)
    project.hook(base + 16, StoreField("serial_control", base + 18), length=2)
    project.hook(base + 18, Finish(), length=1)
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
            state=claripy.Concat(*(end.globals[field] for field in FIELDS)),
            call=end.globals["call"],
            marker=end.globals["marker"],
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_close_link_connection")
    delay = project.loader.find_symbol("port_delay3")
    assert function is not None and delay is not None
    project.hook(delay.rebased_addr, NativeDelaySummary())
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
            state=end.memory.load(NATIVE_STATE + 8, len(FIELDS)),
            call=end.globals["call"],
            marker=end.memory.load(NATIVE_MEMORY + MARKER, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_close_link_connection_pathwise_equivalence() -> None:
    values = _inputs("close_link_connection")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "state", "call", "marker"),
    )
