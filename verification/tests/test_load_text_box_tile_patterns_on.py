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
from verification.tests.test_load_font_tile_patterns_on import (
    CopyVideoDataDoubleSummary as TransferSummary,
    Endpoint,
    NativeCopyVideoDataDoubleSummary as NativeTransferSummary,
    _inputs,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF
MARKER = 0x1234
EXPECTED_BODY = bytes.fromhex("118862210096012004c34818")


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "LoadTextBoxTilePatterns.on")
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
    project.hook(location.address + 9, TransferSummary(), length=3)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.globals["call_registers"] = claripy.BVV(0, 64)
    for register in REGISTERS:
        state.globals[f"transfer_{register}"] = values[f"transfer_{register}"]
    state.globals["transfer_marker"] = values["transfer_marker"]
    state.memory.store(MARKER, values["marker"])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE)
    return [
        Endpoint(
            **assembly_registers(end),
            call_registers=end.globals["call_registers"],
            marker=end.memory.load(MARKER, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_load_text_box_tile_patterns_on")
    transfer = project.loader.find_symbol("port_copy_video_data")
    assert function is not None and transfer is not None
    project.hook(transfer.rebased_addr, NativeTransferSummary())
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    state.globals["call_registers"] = claripy.BVV(0, 64)
    for register in REGISTERS:
        state.globals[f"transfer_{register}"] = values[f"transfer_{register}"]
    state.globals["transfer_marker"] = values["transfer_marker"]
    state.memory.store(NATIVE_MEMORY + MARKER, values["marker"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            call_registers=end.globals["call_registers"],
            marker=end.memory.load(NATIVE_MEMORY + MARKER, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_load_text_box_tile_patterns_on_pathwise_equivalence() -> None:
    values = _inputs("load_text_box_tile_patterns_on")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "call_registers", "marker"),
    )
