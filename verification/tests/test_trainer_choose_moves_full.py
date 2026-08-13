from __future__ import annotations

from dataclasses import dataclass
from functools import cache
from pathlib import Path

import angr
import pytest

from verification.harness.rom import linked_bytes, symbol_location


ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000

MOVE_CHOICE_TABLE = linked_bytes(
    ROM, symbol_location(SYMBOLS, "TrainerClassMoveChoiceModifications"), 121
)


@dataclass(frozen=True)
class Case:
    trainer_class: int
    disabled: int
    status: int
    layer2: int
    moves: tuple[int, int, int, int]
    powers: tuple[int, int, int, int]
    effects: tuple[int, int, int, int]
    types: tuple[int, int, int, int]
    effectiveness: tuple[int, int, int, int]


CASES = (
    Case(1, 0, 0, 0, (1, 2, 3, 0), (30, 20, 10, 0), (0, 0, 0, 0), (1, 2, 3, 0), (16, 16, 16, 16)),
    Case(2, 0, 0, 0, (1, 2, 3, 4), (0, 0, 0, 0), (1, 2, 3, 4), (1, 1, 1, 1), (16, 16, 16, 16)),
    Case(2, 0, 1, 0, (1, 2, 3, 4), (0, 0, 0, 0), (1, 0x20, 0x42, 0x7F), (1, 1, 1, 1), (16, 16, 16, 16)),
    Case(7, 0x20, 1, 1, (1, 2, 3, 4), (0, 30, 40, 50), (1, 0x0A, 0x35, 0x7F), (1, 2, 3, 4), (16, 32, 8, 16)),
    Case(4, 0, 0, 0, (1, 2, 3, 0), (20, 0, 40, 0), (0, 0x28, 0, 0), (1, 1, 2, 0), (8, 16, 32, 16)),
    Case(4, 0x40, 0, 0, (1, 2, 3, 4), (20, 0, 0, 0), (0, 0, 0, 0), (1, 1, 1, 1), (8, 16, 16, 16)),
    Case(13, 0, 1, 1, (1, 2, 3, 0), (0, 25, 40, 0), (0x20, 0x0A, 0, 0), (1, 2, 3, 0), (16, 16, 16, 16)),
    Case(44, 0x10, 1, 1, (1, 2, 0, 0), (0, 25, 0, 0), (0x43, 0x12, 0, 0), (3, 4, 0, 0), (32, 8, 16, 16)),
)


def modifications(trainer_class: int) -> tuple[int, ...]:
    offset = 0
    for _ in range(trainer_class - 1):
        offset = MOVE_CHOICE_TABLE.index(0, offset) + 1
    end = MOVE_CHOICE_TABLE.index(0, offset)
    return tuple(MOVE_CHOICE_TABLE[offset:end])


def reference(case: Case):
    scores = [10, 10, 10, 10]
    disabled_slot = case.disabled >> 4
    if disabled_slot:
        scores[disabled_slot - 1] = 0x50
    mods = modifications(case.trainer_class)
    if not mods:
        registers = (0, 0xA0, 0, max(disabled_slot - 1, 0), 0, 0, 0xCF, 0xED)
        return registers, bytes(scores), bytes(case.moves), 0, 0

    active = next((i for i, move in enumerate(case.moves) if move == 0), 4)
    read_move_called = 0
    effectiveness_called = 0
    callback_b = 0
    for modification in mods:
        callback_b = 0  # dispatcher loads B with zero before every callback
        if modification == 1 and case.status:
            callback_b = 0 if active == 4 else 4 - active
            read_move_called |= active != 0
            for slot in range(active):
                if case.powers[slot] == 0 and case.effects[slot] in (1, 0x20, 0x42, 0x43):
                    scores[slot] = (scores[slot] + 5) & 0xFF
        elif modification == 2 and case.layer2 == 1:
            callback_b = 0 if active == 4 else 4 - active
            read_move_called |= active != 0
            for slot in range(active):
                effect = case.effects[slot]
                if 0x0A <= effect < 0x1A or 0x32 <= effect < 0x42:
                    scores[slot] = (scores[slot] - 1) & 0xFF
        elif modification == 3:
            callback_b = 0 if active == 4 else 4 - active
            read_move_called |= active != 0
            effectiveness_called |= active != 0
            for slot in range(active):
                effectiveness = case.effectiveness[slot]
                if effectiveness > 0x10:
                    scores[slot] = (scores[slot] - 1) & 0xFF
                elif effectiveness < 0x10:
                    better = any(
                        case.effects[candidate] in (0x28, 0x29, 0x2B)
                        or (
                            case.types[candidate] != case.types[slot]
                            and case.powers[candidate] != 0
                        )
                        for candidate in range(active)
                    )
                    if better:
                        scores[slot] = (scores[slot] + 1) & 0xFF

    distance = [score if score else 256 for score in scores[:active]]
    minimum = min(distance)
    result = bytes(
        case.moves[slot] if slot < active and distance[slot] == minimum else 0
        for slot in range(4)
    )
    registers = (result[3], 0xC0, callback_b, 0, 0xCF, 0xF1, 0xCE, 0xE9)
    return registers, result, bytes(case.moves), int(read_move_called), int(effectiveness_called)


@cache
def native_project() -> tuple[angr.Project, int]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_ai_enemy_trainer_choose_moves")
    assert function is not None
    return project, function.rebased_addr


def native(case: Case):
    project, function_address = native_project()
    values = bytearray(47)
    values[8] = case.disabled
    values[9] = case.trainer_class
    values[20:24] = bytes(case.moves)
    values[27] = case.status
    values[28] = case.layer2
    values[29:33] = bytes(case.powers)
    values[33:37] = bytes(case.effects)
    values[37:41] = bytes(case.types)
    values[41:45] = bytes(case.effectiveness)
    state = project.factory.call_state(function_address, NATIVE_STATE)
    state.memory.store(NATIVE_STATE, bytes(values))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    end = manager.deadended[0]
    memory = end.memory.load(NATIVE_STATE, 47)
    concrete = end.solver.eval(memory, cast_to=bytes)
    return (
        tuple(concrete[:8]),
        concrete[16:20],
        concrete[20:24],
        concrete[45],
        concrete[46],
    )


@pytest.mark.skipif(not ELF.exists(), reason="native verification binary is absent")
@pytest.mark.parametrize("case", CASES)
def test_full_parent_composition(case: Case):
    assert native(case) == reference(case)
