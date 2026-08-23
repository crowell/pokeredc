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
from verification.harness.rom import collect_returns, linked_bytes, rom_window, sm83_flags_to_z80, symbol_location

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xFFFF
MARKER = 0x1234
FIELDS = ("requested_bank", "loaded_bank", "rom_bank")
EXPECTED_BODY = bytes.fromhex(
    "e08bf0b8f5f08be0b8ea0020e5d5d5545de1cdb500d1e1f1e0b8ea0020c9"
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
    memory: claripy.ast.BV
    call_registers: claripy.ast.BV
    marker: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class LoadField(angr.SimProcedure):
    def __init__(self, field: str, continuation: int) -> None:
        super().__init__()
        self.field = field
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals[self.field]
        self.jump(self.continuation)


class StoreField(angr.SimProcedure):
    def __init__(self, field: str, continuation: int) -> None:
        super().__init__()
        self.field = field
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.globals[self.field] = self.state.regs.a
        self.jump(self.continuation)


class CopyDataSummary(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        call = assembly_registers(self.state)
        self.state.globals["call_registers"] = claripy.Concat(
            *(call[register] for register in REGISTERS)
        )
        for register in REGISTERS:
            value = self.state.globals[f"copy_{register}"]
            if register == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, register, value)
        self.state.memory.store(MARKER, self.state.globals["copy_marker"])
        self.jump(self.continuation)


class NativeCopyDataSummary(angr.SimProcedure):
    def run(
        self, registers: claripy.ast.BV, memory: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        self.state.globals["call_registers"] = self.state.memory.load(registers, 8)
        for offset, register in enumerate(REGISTERS):
            self.state.memory.store(
                registers + offset, self.state.globals[f"copy_{register}"]
            )
        self.state.memory.store(memory + MARKER, self.state.globals["copy_marker"])


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for field in FIELDS:
        values[field] = claripy.BVS(f"{prefix}_{field}", 8)
    for register in REGISTERS:
        values[f"copy_{register}"] = (
            claripy.Concat(
                claripy.BVS(f"{prefix}_copy_flags", 4), claripy.BVV(0, 4)
            )
            if register == "f"
            else claripy.BVS(f"{prefix}_copy_{register}", 8)
        )
    values["marker"] = claripy.BVS(f"{prefix}_marker", 8)
    values["copy_marker"] = claripy.BVS(f"{prefix}_copy_marker", 8)
    return values


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "FarCopyData3")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY
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
    project.hook(base, StoreField("requested_bank", base + 2), length=2)
    project.hook(base + 2, LoadField("loaded_bank", base + 4), length=2)
    project.hook(base + 5, LoadField("requested_bank", base + 7), length=2)
    project.hook(base + 7, StoreField("loaded_bank", base + 9), length=2)
    project.hook(base + 9, StoreField("rom_bank", base + 12), length=3)
    project.hook(base + 18, CopyDataSummary(base + 21), length=3)
    project.hook(base + 24, StoreField("loaded_bank", base + 26), length=2)
    project.hook(base + 26, StoreField("rom_bank", base + 29), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    for field in FIELDS:
        state.globals[field] = values[field]
    for register in REGISTERS:
        state.globals[f"copy_{register}"] = values[f"copy_{register}"]
    state.globals["copy_marker"] = values["copy_marker"]
    state.globals["call_registers"] = claripy.BVV(0, 64)
    state.memory.store(MARKER, values["marker"])
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    return [
        Endpoint(
            **assembly_registers(end),
            memory=claripy.Concat(*(end.globals[field] for field in FIELDS)),
            call_registers=end.globals["call_registers"],
            marker=end.memory.load(MARKER, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, RETURN)
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_far_copy_data3")
    copy_data = project.loader.find_symbol("port_copy_data")
    assert function is not None and copy_data is not None
    project.hook(copy_data.rebased_addr, NativeCopyDataSummary())
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    for offset, field in enumerate(FIELDS, 8):
        state.memory.store(NATIVE_STATE + offset, values[field])
    for register in REGISTERS:
        state.globals[f"copy_{register}"] = values[f"copy_{register}"]
    state.globals["copy_marker"] = values["copy_marker"]
    state.globals["call_registers"] = claripy.BVV(0, 64)
    state.memory.store(NATIVE_MEMORY + MARKER, values["marker"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=end.memory.load(NATIVE_STATE + 8, len(FIELDS)),
            call_registers=end.globals["call_registers"],
            marker=end.memory.load(NATIVE_MEMORY + MARKER, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_far_copy_data3_pathwise_equivalence() -> None:
    values = _inputs("far_copy_data3")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "memory", "call_registers", "marker"),
    )
