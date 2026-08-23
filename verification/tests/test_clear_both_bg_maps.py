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


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x110000
DONE = 0xEFFF


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
    fill_state: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class AssemblyFillBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(DONE)


class NativeFillBoundary(angr.SimProcedure):
    def run(self, state_pointer: claripy.ast.BV, memory_pointer: claripy.ast.BV) -> None:  # type: ignore[override]
        del state_pointer, memory_pointer


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    entry = symbol_location(SYMBOLS, "ClearBothBGMaps")
    fill_memory = symbol_location(SYMBOLS, "FillMemory").address
    project = angr.Project(
        rom_window(ROM, entry.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": entry.address,
        },
    )
    project.hook(fill_memory, AssemblyFillBoundary(), length=1)
    state = project.factory.blank_state(addr=entry.address)
    set_assembly_registers(state, values)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE)
    assert not manager.errored
    return [
        Endpoint(
            **assembly_registers(end),
            fill_state=claripy.Concat(
                values["saved_d"], values["saved_e"], values["written"]
            ),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_clear_both_bg_maps")
    fill_memory = project.loader.find_symbol("port_fill_memory")
    assert function is not None and fill_memory is not None
    project.hook(fill_memory.rebased_addr, NativeFillBoundary())
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, values["saved_d"])
    state.memory.store(NATIVE_STATE + 9, values["saved_e"])
    state.memory.store(NATIVE_STATE + 10, values["written"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            fill_state=end.memory.load(NATIVE_STATE + 8, 3),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run red")
def test_clear_both_bg_maps_pathwise_equivalence() -> None:
    values = symbolic_registers("clear_both_bg_maps")
    values["saved_d"] = claripy.BVS("clear_both_saved_d", 8)
    values["saved_e"] = claripy.BVS("clear_both_saved_e", 8)
    values["written"] = claripy.BVS("clear_both_written", 8)
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "fill_state"),
    )
