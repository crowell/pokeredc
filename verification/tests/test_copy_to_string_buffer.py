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
from verification.harness.rom import rom_window, symbol_location
from verification.harness.sm83_shims import Sm83CpImmediate, Sm83StoreAAtHlIncrement


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x400000
SOURCE = 0xC100
DESTINATION = 0xCF4B
RETURN = 0xEFFF


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
    destination: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class ReturnBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(RETURN)


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "CopyToStringBuffer")
    base = location.address
    project = angr.Project(
        rom_window(ROM, location.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": base,
        },
    )
    project.hook(base + 5, Sm83StoreAAtHlIncrement(base + 6), length=1)
    project.hook(base + 6, Sm83CpImmediate(0x50, base + 8), length=2)
    project.hook(base + 10, ReturnBoundary(), length=1)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.memory.store(SOURCE, values["source"])
    state.memory.store(DESTINATION, values["destination"])
    manager = project.factory.simulation_manager(state)
    manager.stashes["found"] = []
    while manager.active:
        manager.move(
            from_stash="active",
            to_stash="found",
            filter_func=lambda end: end.addr == RETURN,
        )
        if manager.active:
            manager.step()
    assert not manager.errored
    return [
        Endpoint(
            **assembly_registers(end),
            destination=end.memory.load(DESTINATION, 4),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_copy_to_string_buffer")
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_MEMORY + SOURCE, values["source"])
    state.memory.store(NATIVE_MEMORY + DESTINATION, values["destination"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            destination=end.memory.load(NATIVE_MEMORY + DESTINATION, 4),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run red")
def test_copy_to_string_buffer_pathwise_equivalence() -> None:
    values = symbolic_registers("copy_to_string_buffer")
    values["d"] = claripy.BVV(SOURCE >> 8, 8)
    values["e"] = claripy.BVV(SOURCE & 0xFF, 8)
    values["source"] = claripy.Concat(
        claripy.BVS("copy_to_string_buffer_source_0", 8),
        claripy.BVS("copy_to_string_buffer_source_1", 8),
        claripy.BVS("copy_to_string_buffer_source_2", 8),
        claripy.BVV(0x50, 8),
    )
    values["destination"] = claripy.BVS(
        "copy_to_string_buffer_destination", 32
    )
    assert_pathwise_equivalent(
        _assembly(values), _native(values), (*REGISTERS, "destination")
    )
