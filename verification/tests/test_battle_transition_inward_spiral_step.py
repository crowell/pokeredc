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
    Sm83AddHlRegisterPair,
    Sm83DecRegister,
    Sm83LoadAImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
DONE = 0xEFFF
COUNTER = 0xCD3D


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
    written: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class StoreFF(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(self.state.regs.hl, claripy.BVV(0xFF, 8))
        self.state.globals["written"] = claripy.BVV(0xFF, 8)
        self.jump(self.state.addr + 2)


class Boundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.successors.add_successor(
            self.state.copy(), DONE, claripy.BoolV(True), "Ijk_Boring"
        )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "BattleTransition_InwardSpiral_")
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
    project.hook(base + 1, StoreFF(), length=2)
    project.hook(base + 3, Sm83AddHlRegisterPair("de", base + 4), length=1)
    project.hook(base + 5, Sm83LoadAImmediate(COUNTER, base + 8), length=3)
    project.hook(base + 8, Sm83DecRegister("a", base + 9), length=1)
    project.hook(base + 0x0B, Boundary(), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.memory.store(COUNTER, claripy.BVV(1, 8))
    state.globals["written"] = claripy.BVV(0, 8)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored
    return [
        Endpoint(
            **assembly_registers(end),
            written=end.globals["written"],
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_battle_transition_inward_spiral_step")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, claripy.BVV(1, 8))
    state.memory.store(NATIVE_STATE + 9, claripy.BVV(0, 8))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            written=end.memory.load(NATIVE_STATE + 9, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_battle_transition_inward_spiral_step_pathwise_equivalence() -> None:
    values = symbolic_registers("battle_transition_inward_spiral_step")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "written"),
    )
