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
from verification.harness.sm83_shims import (
    Sm83AddRegister,
    Sm83LoadAHighImmediate,
    Sm83SwapRegister,
)


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x400000
SPRITE_DATA_OFFSET = 0xFF8B
SPRITE_INDEX = 0xFF8C
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
    constraints: tuple[claripy.ast.Bool, ...]


class ReturnBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(RETURN)


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "GetPointerWithinSpriteStateData1")
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
    project.hook(
        base + 6,
        Sm83LoadAHighImmediate(0x8B, base + 8),
        length=2,
    )
    project.hook(
        base + 9,
        Sm83LoadAHighImmediate(0x8C, base + 11),
        length=2,
    )
    project.hook(base + 11, Sm83SwapRegister("a", base + 13), length=2)
    project.hook(base + 13, Sm83AddRegister("b", base + 14), length=1)
    project.hook(base + 15, ReturnBoundary(), length=1)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.memory.store(SPRITE_DATA_OFFSET, values["sprite_data_offset"])
    state.memory.store(SPRITE_INDEX, values["sprite_index"])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN)
    assert not manager.errored
    return [
        Endpoint(
            **assembly_registers(end),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(
        "port_get_pointer_within_sprite_state_data1"
    )
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(
        NATIVE_MEMORY + SPRITE_DATA_OFFSET, values["sprite_data_offset"]
    )
    state.memory.store(NATIVE_MEMORY + SPRITE_INDEX, values["sprite_index"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run red")
def test_get_pointer_within_sprite_state_data1_pathwise_equivalence() -> None:
    values = symbolic_registers("get_pointer_within_sprite_state_data1")
    values["sprite_data_offset"] = claripy.BVS("sprite_data_offset", 8)
    values["sprite_index"] = claripy.BVS("sprite_index", 8)
    assert_pathwise_equivalent(_assembly(values), _native(values), REGISTERS)
