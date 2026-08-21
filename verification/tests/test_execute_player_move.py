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
    Sm83IncRegister,
    Sm83LoadAHighImmediate,
    Sm83LoadAImmediate,
    Sm83StoreAHighImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
DONE = 0xEFFF
H_WHOSE_TURN = 0xFFF3
SELECTED = 0xCCDC


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
    whose_turn: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class XorA(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x40, 8)
        self.jump(self.state.addr + 1)


class Boundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.successors.add_successor(
            self.state.copy(), DONE, claripy.BoolV(True), "Ijk_Boring"
        )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "ExecutePlayerMove")
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
    project.hook(base, XorA(), length=1)
    project.hook(base + 1, Sm83StoreAHighImmediate(0xF3, base + 3), length=2)
    project.hook(base + 3, Sm83LoadAImmediate(SELECTED, base + 6), length=3)
    project.hook(base + 6, Sm83IncRegister("a", base + 7), length=1)
    project.hook(base + 7, Boundary(), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.memory.store(SELECTED, values["selected_move"])
    state.memory.store(H_WHOSE_TURN, values["whose_turn"])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored
    return [
        Endpoint(
            **assembly_registers(end),
            whose_turn=end.memory.load(H_WHOSE_TURN, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_execute_player_move")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, values["selected_move"])
    state.memory.store(NATIVE_STATE + 9, values["whose_turn"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            whose_turn=end.memory.load(NATIVE_STATE + 9, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_execute_player_move_entry_pathwise_equivalence() -> None:
    values = symbolic_registers("execute_player_move")
    values["selected_move"] = claripy.BVS("execute_player_move_selected", 8)
    values["whose_turn"] = claripy.BVS("execute_player_move_whose_turn", 8)
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "whose_turn"),
    )
