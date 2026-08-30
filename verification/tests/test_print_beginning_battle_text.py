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
from verification.harness.sm83_shims import Sm83DecRegister, Sm83LoadAImmediate

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
DONE = 0xEFFF
W_IS_IN_BATTLE = 0xD057
W_CUR_MAP = 0xD35E
W_ENEMY_MON_SPECIES2 = 0xD0D8
W_MOVE_MISSED = 0xD05F
POKEMON_TOWER_3F = 0x90
POKEMON_TOWER_7F_PLUS_ONE = 0x95
WILD_MON_APPEARED_TEXT = 0x4E3B
HOOKED_MON_ATTACKED_TEXT = 0x4E40
TRAINER_WANTS_TO_FIGHT_TEXT = 0x4E4A


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


class BranchBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        wild = self.state.regs.a == 0
        for is_wild in (True, False):
            successor = self.state.copy()
            successor.add_constraints(wild if is_wild else ~wild)
            if is_wild:
                cur_map = int(self.state.solver.eval(
                    self.state.memory.load(W_CUR_MAP, 1)
                ))
                if not (POKEMON_TOWER_3F <= cur_map < POKEMON_TOWER_7F_PLUS_ONE):
                    species = self.state.memory.load(W_ENEMY_MON_SPECIES2, 1)
                    successor.regs.a = species
                    missed = int(self.state.solver.eval(
                        self.state.memory.load(W_MOVE_MISSED, 1)
                    ))
                    text = HOOKED_MON_ATTACKED_TEXT if missed else WILD_MON_APPEARED_TEXT
                    successor.regs.h = claripy.BVV(text >> 8, 8)
                    successor.regs.l = claripy.BVV(text & 0xFF, 8)
            else:
                successor.regs.h = claripy.BVV(TRAINER_WANTS_TO_FIGHT_TEXT >> 8, 8)
                successor.regs.l = claripy.BVV(TRAINER_WANTS_TO_FIGHT_TEXT & 0xFF, 8)
            self.successors.add_successor(
                successor, DONE, claripy.BoolV(True), "Ijk_Boring"
            )
        self.inhibit_autoret = True


def _assembly(values: dict[str, claripy.ast.BV], *, cur_map: int = 0,
              enemy_species: int = 0, move_missed: int = 0) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "PrintBeginningBattleText")
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
    project.hook(base, Sm83LoadAImmediate(W_IS_IN_BATTLE, base + 3), length=3)
    project.hook(base + 3, Sm83DecRegister("a", base + 4), length=1)
    project.hook(base + 4, BranchBoundary(), length=2)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.memory.store(W_IS_IN_BATTLE, values["is_in_battle"])
    state.memory.store(W_CUR_MAP, claripy.BVV(cur_map, 8))
    state.memory.store(W_ENEMY_MON_SPECIES2, claripy.BVV(enemy_species, 8))
    state.memory.store(W_MOVE_MISSED, claripy.BVV(move_missed, 8))
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored
    return [
        Endpoint(**assembly_registers(end), constraints=tuple(end.solver.constraints))
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV], *, cur_map: int = 0,
            enemy_species: int = 0, move_missed: int = 0) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_print_beginning_battle_text")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, values["is_in_battle"])
    state.memory.store(NATIVE_STATE + 9, claripy.BVV(cur_map, 8))
    state.memory.store(NATIVE_STATE + 10, claripy.BVV(enemy_species, 8))
    state.memory.store(NATIVE_STATE + 11, claripy.BVV(move_missed, 8))
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
def test_print_beginning_battle_text_entry_pathwise_equivalence() -> None:
    values = symbolic_registers("print_beginning_battle_text")
    values["is_in_battle"] = claripy.BVS("print_beginning_battle_text_is_in_battle", 8)
    assert_pathwise_equivalent(_assembly(values), _native(values), REGISTERS)


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
@pytest.mark.parametrize(
    ("is_in_battle", "cur_map", "enemy_species", "move_missed"),
    [(0, 0, 0x4A, 0), (0, 0, 0x4A, 1), (1, 0, 0x00, 0),
     (0, POKEMON_TOWER_3F, 0x4A, 0)],
)
def test_print_beginning_battle_text_selection_pathwise_equivalence(
    is_in_battle: int, cur_map: int, enemy_species: int, move_missed: int,
) -> None:
    values = symbolic_registers("print_beginning_battle_text_selection")
    values["is_in_battle"] = claripy.BVV(is_in_battle, 8)
    assert_pathwise_equivalent(
        _assembly(values, cur_map=cur_map, enemy_species=enemy_species,
                  move_missed=move_missed),
        _native(values, cur_map=cur_map, enemy_species=enemy_species,
                move_missed=move_missed),
        REGISTERS,
    )
