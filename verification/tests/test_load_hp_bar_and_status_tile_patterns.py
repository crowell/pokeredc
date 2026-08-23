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
from verification.harness.sm83_shims import Sm83BitRegister
from verification.tests.test_load_text_box_tile_patterns import (
    DONE,
    FIELDS,
    MARKER,
    Endpoint,
    LoadLcdc,
    NativeTransferSummary,
    TransferSummary,
    inputs,
    setup_globals,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
EXPECTED = bytes.fromhex(
    "f040cb7f200e21a05e11209601e0013e04c3f71711a05e212096011e04c34818"
)


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "LoadHpBarAndStatusTilePatterns")
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
    project.hook(base, LoadLcdc(base + 2), length=2)
    project.hook(base + 2, Sm83BitRegister(7, "a", base + 4), length=2)
    project.hook(base + 17, TransferSummary(1, True), length=3)
    project.hook(base + 20, TransferSummary(2, False), length=12)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    setup_globals(state, values)
    state.memory.store(MARKER, values["marker"])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=10)
    return [
        Endpoint(
            **assembly_registers(end),
            memory=claripy.Concat(*(end.globals[field] for field in FIELDS)),
            call_registers=end.globals["call_registers"],
            kind=end.globals["kind"],
            marker=end.memory.load(MARKER, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(
        "port_load_hp_bar_and_status_tile_patterns"
    )
    far_copy = project.loader.find_symbol("port_far_copy_data2")
    on_path = project.loader.find_symbol(
        "port_load_hp_bar_and_status_tile_patterns_on"
    )
    assert function is not None and far_copy is not None and on_path is not None
    project.hook(far_copy.rebased_addr, NativeTransferSummary(1, True))
    project.hook(on_path.rebased_addr, NativeTransferSummary(2, False))
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    for offset, field in enumerate(FIELDS, 8):
        state.memory.store(NATIVE_STATE + offset, values[field])
    setup_globals(state, values)
    state.memory.store(NATIVE_MEMORY + MARKER, values["marker"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=end.memory.load(NATIVE_STATE + 8, len(FIELDS)),
            call_registers=end.globals["call_registers"],
            kind=end.globals["kind"],
            marker=end.memory.load(NATIVE_MEMORY + MARKER, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_load_hp_bar_and_status_tile_patterns_pathwise_equivalence() -> None:
    values = inputs("load_hp_bar_and_status_tile_patterns")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "memory", "call_registers", "kind", "marker"),
    )
