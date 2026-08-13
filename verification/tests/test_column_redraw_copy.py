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
from verification.harness.rom import collect_returns, linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import Sm83AddRegister, Sm83DecRegister, Sm83IncRegister


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
STACK = 0xD000
RETURN = 0xFFFF


class ReadTile(angr.SimProcedure):
    def __init__(self, next_address: int, increment_hl: bool):
        super().__init__()
        self.next_address = next_address
        self.increment_hl = increment_hl

    def run(self):
        index = self.state.globals["read_index"]
        self.state.regs.a = self.state.globals[f"read{index}"]
        self.state.globals["read_index"] = index + 1
        if self.increment_hl:
            self.state.regs.hl = self.state.regs.hl + 1
        self.jump(self.next_address)


class WriteTile(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__()
        self.next_address = next_address

    def run(self):
        index = self.state.globals["write_index"]
        self.state.globals[f"write{index}"] = self.state.regs.a
        self.state.globals["write_index"] = index + 1
        self.jump(self.next_address)


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
    writes: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _inputs() -> dict[str, claripy.ast.BV]:
    inputs = symbolic_registers("column_redraw")
    inputs["reads"] = claripy.BVS("column_redraw_reads", 36 * 8)
    inputs["writes"] = claripy.BVS("column_redraw_writes", 36 * 8)
    return inputs


def _assembly(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "ScheduleColumnRedrawHelper")
    address = location.address
    project = angr.Project(
        rom_window(ROM, location.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": address,
        },
    )
    project.hook(address + 5, ReadTile(address + 6, True), length=1)
    project.hook(address + 6, WriteTile(address + 7), length=1)
    project.hook(address + 8, ReadTile(address + 9, False), length=1)
    project.hook(address + 9, WriteTile(address + 10), length=1)
    project.hook(address + 13, Sm83AddRegister("l", address + 14), length=1)
    project.hook(address + 17, Sm83IncRegister("h", address + 18), length=1)
    project.hook(address + 18, Sm83DecRegister("c", address + 19), length=1)
    state = project.factory.blank_state(addr=address)
    set_assembly_registers(state, inputs)
    for index in range(36):
        high = 36 * 8 - index * 8 - 1
        state.globals[f"read{index}"] = inputs["reads"][high : high - 7]
        state.globals[f"write{index}"] = inputs["writes"][high : high - 7]
    state.globals["read_index"] = 0
    state.globals["write_index"] = 0
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    return [
        Endpoint(
            **assembly_registers(end),
            writes=claripy.Concat(*(end.globals[f"write{i}"] for i in range(36))),
            constraints=tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, RETURN)
    ]


def _native(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_schedule_column_redraw_helper")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["reads"])
    state.memory.store(NATIVE_STATE + 44, inputs["writes"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            writes=end.memory.load(NATIVE_STATE + 44, 36),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
def test_equivalence() -> None:
    inputs = _inputs()
    assert_pathwise_equivalent(
        _assembly(inputs), _native(inputs), (*REGISTERS, "writes")
    )


def test_exact_body() -> None:
    location = symbol_location(SYMBOLS, "ScheduleColumnRedrawHelper")
    assert linked_bytes(ROM, location, 22) == bytes.fromhex(
        "11fccb0e122a12137e12133e13856f3001240d20f0c9"
    )
