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
    symbolic_registers,
)
from verification.harness.rom import linked_bytes, rom_window, symbol_location
from verification.tests.test_animation_unused_palette1 import (
    DONE,
    EXPECTED_TAIL,
    NATIVE_MEMORY,
    NATIVE_STATE,
    R_BGP,
    W_ON_SGB,
    Endpoint,
    LoadOnSgb,
    WritePalette,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    entry = symbol_location(SYMBOLS, "SetAnimationBGPalette")
    assert linked_bytes(ROM, entry, len(EXPECTED_TAIL)) == EXPECTED_TAIL
    project = angr.Project(
        rom_window(ROM, entry.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0, "entry_point": entry.address,
        },
    )
    project.hook(entry.address, LoadOnSgb(entry.address + 3), length=3)
    project.hook(entry.address + 8, WritePalette(), length=3)
    state = project.factory.blank_state(addr=entry.address)
    set_assembly_registers(state, values)
    state.memory.store(W_ON_SGB, values["on_sgb"])
    state.memory.store(R_BGP, values["palette"])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=2)
    assert not manager.errored
    return [
        Endpoint(
            **assembly_registers(end),
            on_sgb=end.memory.load(W_ON_SGB, 1),
            palette=end.memory.load(R_BGP, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_set_animation_bg_palette")
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_MEMORY + W_ON_SGB, values["on_sgb"])
    state.memory.store(NATIVE_MEMORY + R_BGP, values["palette"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            on_sgb=end.memory.load(NATIVE_MEMORY + W_ON_SGB, 1),
            palette=end.memory.load(NATIVE_MEMORY + R_BGP, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_set_animation_bg_palette_pathwise_equivalence() -> None:
    values = symbolic_registers("set_animation_bg_palette")
    values["on_sgb"] = claripy.BVS("set_animation_bg_palette_on_sgb", 8)
    values["palette"] = claripy.BVS("set_animation_bg_palette_value", 8)
    assert_pathwise_equivalent(
        _assembly(values), _native(values),
        (*REGISTERS, "on_sgb", "palette"),
    )
