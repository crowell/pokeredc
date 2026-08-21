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
PLAYER_EFFECT = 0xCFD3
ENEMY_EFFECT = 0xCFCD
MOVE_MISSED = 0xD05F


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


def _apply_move_hit(state: angr.SimState, memory: dict[int, claripy.ast.BV]) -> None:
    whose = memory[WHOSE_TURN]
    player = memory[PLAYER_EFFECT]
    enemy = memory[ENEMY_EFFECT]
    state.regs.a = claripy.If(whose == 0, player, enemy)
    state.regs.f = claripy.BVV(0x10, 8) | claripy.If(whose == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
    state.regs.h = claripy.BVV(0xD0, 8)
    state.regs.l = claripy.If(whose == 0, claripy.BVV(0x67, 8), claripy.BVV(0x62, 8))
    state.regs.d = claripy.BVV(0xCF, 8)
    state.regs.e = claripy.If(whose == 0, claripy.BVV(0xD3, 8), claripy.BVV(0xCD, 8))
    state.regs.b = claripy.If(whose == 0, claripy.BVV(0xCF, 8), claripy.BVV(0xD0, 8))
    state.regs.c = claripy.If(whose == 0, claripy.BVV(0xE9, 8), claripy.BVV(0x18, 8))


class MoveHitCall(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        memory = {
            WHOSE_TURN: self.state.memory.load(WHOSE_TURN, 1),
            PLAYER_EFFECT: self.state.memory.load(PLAYER_EFFECT, 1),
            ENEMY_EFFECT: self.state.memory.load(ENEMY_EFFECT, 1),
        }
        _apply_move_hit(self.state, memory)
        self.jump(self.state.addr + 3)

class AfterMoveHit(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        missed = self.state.memory.load(MOVE_MISSED, 1)
        self.state.regs.a = missed
        self.state.regs.f = claripy.BVV(0x10, 8) | claripy.If(missed == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        self.jump(DONE)


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "EnemyMoveHitTest")
    project = angr.Project(rom_window(ROM, location.bank), auto_load_libs=False, rebase_granularity=0x100, main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0, "entry_point": location.address})
    project.hook(location.address, MoveHitCall(), length=3)
    project.hook(location.address + 3, AfterMoveHit(), length=4)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    for address, key in ((WHOSE_TURN, "whose_turn"), (PLAYER_EFFECT, "player_move_effect"), (ENEMY_EFFECT, "enemy_move_effect"), (MOVE_MISSED, "move_missed")):
        state.memory.store(address, values[key])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored
    return [Endpoint(**assembly_registers(end), constraints=tuple(end.solver.constraints)) for end in manager.found]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_enemy_move_hit_test")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    for offset, key in enumerate(("whose_turn", "player_move_effect", "enemy_move_effect", "move_missed"), start=8):
        state.memory.store(NATIVE_STATE + offset, values[key])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [Endpoint(**native_registers(end, NATIVE_STATE), constraints=tuple(end.solver.constraints)) for end in manager.deadended]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_enemy_move_hit_test_pathwise_equivalence() -> None:
    values = symbolic_registers("enemy_move_hit_test")
    for key in ("whose_turn", "player_move_effect", "enemy_move_effect", "move_missed"):
        values[key] = claripy.BVS(f"enemy_move_hit_test_{key}", 8)
    assert_pathwise_equivalent(_assembly(values), _native(values), REGISTERS)
