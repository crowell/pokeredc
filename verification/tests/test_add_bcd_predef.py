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
from verification.tests import test_sub_bcd_predef as shared

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
EXPECTED = bytes.fromhex(
    "cd943ea7411a8e27121b2b0d20f730083e991312130520fbc9"
)


def _assembly(
    values: dict[str, claripy.ast.BV],
) -> list[shared.Endpoint]:
    location = symbol_location(SYMBOLS, "AddBCDPredef")
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
    project.hook(
        base, shared.CallSummary("predef", base + 3), length=3
    )
    project.hook(
        base + 3, shared.CallSummary("sub", shared.DONE), length=22
    )
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    shared._setup(state, values)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=shared.DONE)
    assert not manager.errored
    return [
        shared.Endpoint(
            **assembly_registers(end),
            state=claripy.Concat(
                *(end.globals[field] for field in shared.FIELDS)
            ),
            calls=shared._calls(end),
            marker=end.globals["marker"],
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(
    values: dict[str, claripy.ast.BV],
) -> list[shared.Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_add_bcd_predef")
    predef = project.loader.find_symbol("port_get_predef_registers")
    add = project.loader.find_symbol("port_add_bcd")
    assert function is not None and predef is not None and add is not None
    project.hook(predef.rebased_addr, shared.NativeCallSummary("predef"))
    project.hook(add.rebased_addr, shared.NativeCallSummary("sub"))
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    for offset, field in enumerate(shared.FIELDS, 8):
        state.memory.store(NATIVE_STATE + offset, values[field])
    shared._setup(state, values)
    state.memory.store(NATIVE_MEMORY + shared.MARKER, values["marker"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        shared.Endpoint(
            **native_registers(end, NATIVE_STATE),
            state=end.memory.load(NATIVE_STATE + 8, len(shared.FIELDS)),
            calls=shared._calls(end),
            marker=end.memory.load(NATIVE_MEMORY + shared.MARKER, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_add_bcd_predef_pathwise_equivalence() -> None:
    values = shared._inputs("add_bcd_predef")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "state", "calls", "marker"),
    )
