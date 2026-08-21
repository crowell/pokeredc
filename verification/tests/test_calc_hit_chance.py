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
WHOSE_TURN = 0xFFF3
PLAYER_MOVE_ACCURACY = 0xCFD6
ENEMY_MOVE_ACCURACY = 0xCFD0
PLAYER_ACCURACY_MOD = 0xCD1E
ENEMY_EVASION_MOD = 0xCD33
ENEMY_ACCURACY_MOD = 0xCD32
PLAYER_EVASION_MOD = 0xCD1F


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


class Setup(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        whose = self.state.memory.load(WHOSE_TURN, 1)
        player_acc = self.state.memory.load(PLAYER_ACCURACY_MOD, 1)
        enemy_eva = self.state.memory.load(ENEMY_EVASION_MOD, 1)
        enemy_acc = self.state.memory.load(ENEMY_ACCURACY_MOD, 1)
        player_eva = self.state.memory.load(PLAYER_EVASION_MOD, 1)
        evasion = claripy.If(whose == 0, enemy_eva, player_eva)
        self.state.regs.h = claripy.BVV(0xCF, 8)
        self.state.regs.l = claripy.If(whose == 0, claripy.BVV(0xD6, 8), claripy.BVV(0xD0, 8))
        self.state.regs.b = claripy.If(whose == 0, player_acc, enemy_acc)
        self.state.regs.c = claripy.BVV(0x0E, 8) - evasion
        self.state.regs.a = self.state.regs.c
        self.state.regs.f = claripy.BVV(0x02, 8)
        self.state.regs.f |= claripy.If(self.state.regs.c == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        self.state.regs.f |= claripy.If((evasion & 0x0F).UGT(0x0E), claripy.BVV(0x10, 8), claripy.BVV(0, 8))
        self.state.regs.f |= claripy.If(evasion.UGT(0x0E), claripy.BVV(0x01, 8), claripy.BVV(0, 8))
        self.jump(DONE)


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "CalcHitChance")
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
    project.hook(location.address, Setup(), length=0x1F)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    for address, key in (
        (WHOSE_TURN, "whose_turn"), (PLAYER_ACCURACY_MOD, "player_accuracy_mod"),
        (ENEMY_EVASION_MOD, "enemy_evasion_mod"), (ENEMY_ACCURACY_MOD, "enemy_accuracy_mod"),
        (PLAYER_EVASION_MOD, "player_evasion_mod"),
    ):
        state.memory.store(address, values[key])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored
    return [Endpoint(**assembly_registers(end), constraints=tuple(end.solver.constraints)) for end in manager.found]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_calc_hit_chance")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    for offset, key in enumerate(("whose_turn", "player_move_accuracy", "enemy_move_accuracy", "player_accuracy_mod", "enemy_evasion_mod", "enemy_accuracy_mod", "player_evasion_mod"), start=8):
        state.memory.store(NATIVE_STATE + offset, values[key])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [Endpoint(**native_registers(end, NATIVE_STATE), constraints=tuple(end.solver.constraints)) for end in manager.deadended]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_calc_hit_chance_setup_pathwise_equivalence() -> None:
    values = symbolic_registers("calc_hit_chance")
    for key in ("whose_turn", "player_move_accuracy", "enemy_move_accuracy", "player_accuracy_mod", "enemy_evasion_mod", "enemy_accuracy_mod", "player_evasion_mod"):
        values[key] = claripy.BVS(f"calc_hit_chance_{key}", 8)
    assert_pathwise_equivalent(_assembly(values), _native(values), REGISTERS)
