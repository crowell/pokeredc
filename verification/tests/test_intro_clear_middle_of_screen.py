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
from verification.harness.sm83_shims import Sm83LoadAFromRegister, Sm83OrRegister


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
RETURN = 0xEFFF
TILEMAP_START = 0xC3F0
TILEMAP_LENGTH = 0x00C8


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
    tilemap: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class ReturnBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(RETURN)


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "IntroClearMiddleOfScreen")
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
        base + 10,
        Sm83LoadAFromRegister("b", base + 11),
        length=1,
    )
    project.hook(base + 11, Sm83OrRegister("c", base + 12), length=1)
    project.hook(base + 14, ReturnBoundary(), length=1)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.memory.store(TILEMAP_START, values["tilemap"])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN)
    assert not manager.errored
    assert len(manager.found) == 1
    return [
        Endpoint(
            **assembly_registers(end),
            tilemap=end.memory.load(TILEMAP_START, TILEMAP_LENGTH),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_intro_clear_middle_of_screen")
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_MEMORY + TILEMAP_START, values["tilemap"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            tilemap=end.memory.load(
                NATIVE_MEMORY + TILEMAP_START, TILEMAP_LENGTH
            ),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run red")
def test_intro_clear_middle_of_screen_pathwise_equivalence() -> None:
    values = symbolic_registers("intro_clear_middle_of_screen")
    values["tilemap"] = claripy.BVS(
        "intro_clear_middle_of_screen_tilemap", TILEMAP_LENGTH * 8
    )
    assert_pathwise_equivalent(
        _assembly(values), _native(values), (*REGISTERS, "tilemap")
    )
