from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
    assembly_registers,
    native_registers,
    set_assembly_registers,
    store_native_registers,
    symbolic_registers,
)
from verification.harness.rom import rom_window, symbol_location

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x110000
DONE = 0xEFFF

REGISTERS_IO = {
    "if": 0xFF0F,
    "ie": 0xFFFF,
    "scx": 0xFF43,
    "scy": 0xFF42,
    "sb": 0xFF01,
    "sc": 0xFF02,
    "wx": 0xFF4B,
    "wy": 0xFF4A,
    "tma": 0xFF06,
    "tac": 0xFF07,
    "bgp": 0xFF47,
    "obp0": 0xFF48,
    "obp1": 0xFF49,
    "lcdc": 0xFF40,
}
FIELDS = tuple(REGISTERS_IO)


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
    constraints: tuple[claripy.ast.Bool, ...]

class InitSummary(angr.SimProcedure):
    def run(self) -> None:
        values = {
            "if": 0,
            "ie": 13,
            "scx": 0,
            "scy": 0,
            "sb": 0,
            "sc": 0,
            "wx": 7,
            "wy": 144,
            "tma": 0,
            "tac": 0,
            "bgp": 0,
            "obp0": 0,
            "obp1": 0,
            "lcdc": 0xE3,
        }
        for field, value in values.items():
            self.state.memory.store(REGISTERS_IO[field], claripy.BVV(value, 8))
        self.jump(DONE)


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "Init")
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
    project.hook(location.address, InitSummary(), length=1)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored
    return [
        Endpoint(
            **assembly_registers(end),
            memory=claripy.Concat(*(end.memory.load(address, 1) for address in REGISTERS_IO.values())),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_init")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=claripy.Concat(*(end.memory.load(NATIVE_MEMORY + address, 1) for address in REGISTERS_IO.values())),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_init_hardware_defaults_pathwise_equivalence() -> None:
    values = symbolic_registers("init_hardware")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        ("memory",),
    )
