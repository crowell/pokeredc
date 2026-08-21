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
BATTLE_TYPE_1 = 0xD019
ENEMY_TYPE_1 = 0xCFEA
PLAYER_MOVE_TYPE = 0xCFD5
ENEMY_MOVE_TYPE = 0xCFCF


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
        battle_1 = self.state.memory.load(BATTLE_TYPE_1, 1)
        battle_2 = self.state.memory.load(BATTLE_TYPE_1 + 1, 1)
        enemy_1 = self.state.memory.load(ENEMY_TYPE_1, 1)
        enemy_2 = self.state.memory.load(ENEMY_TYPE_1 + 1, 1)
        player_move = self.state.memory.load(PLAYER_MOVE_TYPE, 1)
        enemy_move = self.state.memory.load(ENEMY_MOVE_TYPE, 1)
        self.state.regs.a = claripy.If(whose == 0, player_move, enemy_move)
        self.state.regs.b = claripy.If(whose == 0, battle_1, enemy_1)
        self.state.regs.c = claripy.If(whose == 0, battle_2, enemy_2)
        self.state.regs.d = claripy.If(whose == 0, enemy_1, battle_1)
        self.state.regs.e = claripy.If(whose == 0, enemy_2, battle_2)
        self.state.regs.f = claripy.BVV(0x10, 8) | claripy.If(
            whose == 0,
            claripy.BVV(0x40, 8),
            claripy.BVV(0, 8),
        )
        self.jump(DONE)


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "AdjustDamageForMoveType")
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
    project.hook(location.address, Setup(), length=0x2C)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    for address, key in (
        (WHOSE_TURN, "whose_turn"),
        (BATTLE_TYPE_1, "battle_type_1"),
        (BATTLE_TYPE_1 + 1, "battle_type_2"),
        (ENEMY_TYPE_1, "enemy_type_1"),
        (ENEMY_TYPE_1 + 1, "enemy_type_2"),
        (PLAYER_MOVE_TYPE, "player_move_type"),
        (ENEMY_MOVE_TYPE, "enemy_move_type"),
    ):
        state.memory.store(address, values[key])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored
    return [
        Endpoint(**assembly_registers(end), constraints=tuple(end.solver.constraints))
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_adjust_damage_for_move_type")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    for offset, key in enumerate((
        "whose_turn", "battle_type_1", "battle_type_2", "enemy_type_1",
        "enemy_type_2", "player_move_type", "enemy_move_type",
    ), start=8):
        state.memory.store(NATIVE_STATE + offset, values[key])
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
def test_adjust_damage_for_move_type_setup_pathwise_equivalence() -> None:
    values = symbolic_registers("adjust_damage_for_move_type")
    for key in (
        "whose_turn", "battle_type_1", "battle_type_2", "enemy_type_1",
        "enemy_type_2", "player_move_type", "enemy_move_type",
    ):
        values[key] = claripy.BVS(f"adjust_damage_{key}", 8)
    assert_pathwise_equivalent(_assembly(values), _native(values), REGISTERS)
