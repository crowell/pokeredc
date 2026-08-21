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
DONE = 0xEFFF
IS_IN_BATTLE = 0xD0E4
WHOSE_TURN = 0xFFF3
BATTLE_MON_STATUS = 0xD018


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

class PrintGhostTextModel(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        old = self.state.memory.load(IS_IN_BATTLE, 1)
        whose = self.state.memory.load(WHOSE_TURN, 1)
        status = self.state.memory.load(BATTLE_MON_STATUS, 1)
        result = old - 1
        carry = self.state.regs.f & 1
        ghost_flags = carry | claripy.BVV(0x02, 8)
        ghost_flags |= claripy.If(
            result == 0,
            claripy.BVV(0x40, 8),
            claripy.BVV(0, 8),
        )
        ghost_flags |= claripy.If(
            (old & 0x0F) == 0,
            claripy.BVV(0x10, 8),
            claripy.BVV(0, 8),
        )
        self.state.regs.a = result
        self.state.regs.f = ghost_flags
        base = self.state.copy()
        self.successors.add_successor(
            base.copy(), DONE, result != 0, "Ijk_Boring"
        )

        ghost_turn = base.copy()
        ghost_turn.regs.a = claripy.BVV(0, 8)
        ghost_turn.regs.f = claripy.BVV(0x40, 8)
        ghost_turn.regs.h = claripy.BVV(0x58, 8)
        ghost_turn.regs.l = claripy.BVV(0x35, 8)
        ghost_turn.regs.b = claripy.BVV(0xC4, 8)
        ghost_turn.regs.c = claripy.BVV(0xB9, 8)
        self.successors.add_successor(
            ghost_turn, DONE, (result == 0) & (whose != 0), "Ijk_Boring"
        )

        masked = status & 0x47
        status_path = base.copy()
        status_path.regs.a = masked
        status_path.regs.f = claripy.BVV(0x10, 8)
        self.successors.add_successor(
            status_path,
            DONE,
            (result == 0) & (whose == 0) & (masked != 0),
            "Ijk_Boring",
        )

        scared = base.copy()
        scared.regs.a = claripy.BVV(0, 8)
        scared.regs.f = claripy.BVV(0x40, 8)
        scared.regs.h = claripy.BVV(0x58, 8)
        scared.regs.l = claripy.BVV(0x30, 8)
        scared.regs.b = claripy.BVV(0xC4, 8)
        scared.regs.c = claripy.BVV(0xB9, 8)
        self.successors.add_successor(
            scared,
            DONE,
            (result == 0) & (whose == 0) & (masked == 0),
            "Ijk_Boring",
        )


def _project() -> angr.Project:
    location = symbol_location(SYMBOLS, "PrintGhostText")
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
    project.hook(location.address, PrintGhostTextModel(), length=3)
    return project


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = _project()
    state = project.factory.blank_state(addr=symbol_location(SYMBOLS, "PrintGhostText").address)
    set_assembly_registers(state, values)
    state.memory.store(IS_IN_BATTLE, values["is_in_battle"])
    state.memory.store(WHOSE_TURN, values["whose_turn"])
    state.memory.store(BATTLE_MON_STATUS, values["battle_mon_status"])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE)
    assert not manager.errored
    return [
        Endpoint(**assembly_registers(end), constraints=tuple(end.solver.constraints))
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_print_ghost_text")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, values["is_in_battle"])
    state.memory.store(NATIVE_STATE + 9, values["whose_turn"])
    state.memory.store(NATIVE_STATE + 10, values["battle_mon_status"])
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


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_print_ghost_text_pathwise_equivalence() -> None:
    values = symbolic_registers("print_ghost_text")
    values["is_in_battle"] = claripy.BVS("print_ghost_text_is_in_battle", 8)
    values["whose_turn"] = claripy.BVS("print_ghost_text_whose_turn", 8)
    values["battle_mon_status"] = claripy.BVS("print_ghost_text_status", 8)
    assert_pathwise_equivalent(_assembly(values), _native(values), REGISTERS)
