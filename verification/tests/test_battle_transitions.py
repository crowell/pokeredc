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
from verification.harness.rom import collect_returns, linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import (
    Sm83CpImmediate,
    Sm83CpRegister,
    Sm83LoadAAtHlIncrement,
    Sm83LoadAImmediate,
    Sm83StoreAImmediate,
    Sm83SubRegister,
)


ROOT = Path(__file__).resolve().parents[2]
VERIFY = ROOT / "verification"
NATIVE_ELF = VERIFY / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
GB_STACK = 0xD000
GB_RETURN = 0xFFFF
NATIVE_STATE = 0x100000
PARTY_LENGTH = 0x2C
HP_NAMES = tuple(f"hp{index}" for index in range(12))
LEVEL_NAMES = tuple(f"level{index}" for index in range(6))


@dataclass(frozen=True)
class OpponentEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    current_opponent: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class DungeonEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    current_map: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class LevelEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    hp0: claripy.ast.BV
    hp1: claripy.ast.BV
    hp2: claripy.ast.BV
    hp3: claripy.ast.BV
    hp4: claripy.ast.BV
    hp5: claripy.ast.BV
    hp6: claripy.ast.BV
    hp7: claripy.ast.BV
    hp8: claripy.ast.BV
    hp9: claripy.ast.BV
    hp10: claripy.ast.BV
    hp11: claripy.ast.BV
    level0: claripy.ast.BV
    level1: claripy.ast.BV
    level2: claripy.ast.BV
    level3: claripy.ast.BV
    level4: claripy.ast.BV
    level5: claripy.ast.BV
    enemy_level: claripy.ast.BV
    spiral: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _z80_project(symbol: str) -> tuple[angr.Project, int]:
    location = symbol_location(SYMBOLS, symbol)
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
    return project, location.address


def _opponent_assembly(inputs: dict[str, claripy.ast.BV]) -> list[OpponentEndpoint]:
    project, address = _z80_project("GetBattleTransitionID_WildOrTrainer")
    opponent = symbol_location(SYMBOLS, "wCurOpponent").address
    project.hook(address, Sm83LoadAImmediate(opponent, address + 3), length=3)
    project.hook(address + 3, Sm83CpImmediate(200, address + 5), length=2)
    state = project.factory.blank_state(addr=address)
    set_assembly_registers(state, inputs)
    state.memory.store(opponent, inputs["current_opponent"])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    return [
        OpponentEndpoint(
            **assembly_registers(end),
            current_opponent=end.memory.load(opponent, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, GB_RETURN)
    ]


def _opponent_native(inputs: dict[str, claripy.ast.BV]) -> list[OpponentEndpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(
        "port_get_battle_transition_id_wild_or_trainer"
    )
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["current_opponent"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        OpponentEndpoint(
            **native_registers(end, NATIVE_STATE),
            current_opponent=end.memory.load(NATIVE_STATE + 8, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


def _level_addresses() -> tuple[tuple[int, ...], tuple[int, ...], int, int]:
    first_hp = symbol_location(SYMBOLS, "wPartyMon1HP").address
    hp_addresses = tuple(
        first_hp + mon * PARTY_LENGTH + byte for mon in range(6) for byte in range(2)
    )
    level_addresses = tuple(first_hp + mon * PARTY_LENGTH + 0x20 for mon in range(6))
    enemy = symbol_location(SYMBOLS, "wCurEnemyLevel").address
    spiral = symbol_location(SYMBOLS, "wBattleTransitionSpiralDirection").address
    return hp_addresses, level_addresses, enemy, spiral


def _constrain_level_domain(
    state: angr.SimState, inputs: dict[str, claripy.ast.BV], first_alive: int
) -> None:
    for slot in range(first_alive):
        state.solver.add(inputs[f"hp{slot * 2}"] == 0)
        state.solver.add(inputs[f"hp{slot * 2 + 1}"] == 0)
    state.solver.add(
        (inputs[f"hp{first_alive * 2}"] | inputs[f"hp{first_alive * 2 + 1}"])
        != 0
    )
    for name in LEVEL_NAMES:
        state.solver.add(inputs[name].UGE(1), inputs[name].ULE(100))
    state.solver.add(inputs["enemy_level"].UGE(1), inputs["enemy_level"].ULE(100))


def _level_assembly(
    inputs: dict[str, claripy.ast.BV], first_alive: int
) -> list[LevelEndpoint]:
    project, address = _z80_project("GetBattleTransitionID_CompareLevels")
    hp_addresses, level_addresses, enemy, spiral = _level_addresses()
    project.hook(address + 3, Sm83LoadAAtHlIncrement(address + 4), length=1)
    project.hook(address + 21, Sm83LoadAImmediate(enemy, address + 24), length=3)
    project.hook(address + 24, Sm83SubRegister("e", address + 25), length=1)
    project.hook(address + 31, Sm83StoreAImmediate(spiral, address + 34), length=3)
    project.hook(address + 38, Sm83StoreAImmediate(spiral, address + 41), length=3)
    state = project.factory.blank_state(addr=address)
    set_assembly_registers(state, inputs)
    for name, memory_address in zip(HP_NAMES, hp_addresses, strict=True):
        state.memory.store(memory_address, inputs[name])
    for name, memory_address in zip(LEVEL_NAMES, level_addresses, strict=True):
        state.memory.store(memory_address, inputs[name])
    state.memory.store(enemy, inputs["enemy_level"])
    state.memory.store(spiral, inputs["spiral"])
    _constrain_level_domain(state, inputs, first_alive)
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    return [
        LevelEndpoint(
            **assembly_registers(end),
            **{
                name: end.memory.load(memory_address, 1)
                for name, memory_address in zip(HP_NAMES, hp_addresses, strict=True)
            },
            **{
                name: end.memory.load(memory_address, 1)
                for name, memory_address in zip(LEVEL_NAMES, level_addresses, strict=True)
            },
            enemy_level=end.memory.load(enemy, 1),
            spiral=end.memory.load(spiral, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, GB_RETURN)
    ]


def _level_native(
    inputs: dict[str, claripy.ast.BV], first_alive: int
) -> list[LevelEndpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_get_battle_transition_id_compare_levels")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    for offset, name in enumerate(HP_NAMES, 8):
        state.memory.store(NATIVE_STATE + offset, inputs[name])
    for offset, name in enumerate(LEVEL_NAMES, 20):
        state.memory.store(NATIVE_STATE + offset, inputs[name])
    state.memory.store(NATIVE_STATE + 26, inputs["enemy_level"])
    state.memory.store(NATIVE_STATE + 27, inputs["spiral"])
    _constrain_level_domain(state, inputs, first_alive)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        LevelEndpoint(
            **native_registers(end, NATIVE_STATE),
            **{
                name: end.memory.load(NATIVE_STATE + offset, 1)
                for offset, name in enumerate(HP_NAMES, 8)
            },
            **{
                name: end.memory.load(NATIVE_STATE + offset, 1)
                for offset, name in enumerate(LEVEL_NAMES, 20)
            },
            enemy_level=end.memory.load(NATIVE_STATE + 26, 1),
            spiral=end.memory.load(NATIVE_STATE + 27, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


def _dungeon_assembly(inputs: dict[str, claripy.ast.BV]) -> list[DungeonEndpoint]:
    project, address = _z80_project("GetBattleTransitionID_IsDungeonMap")
    current_map = symbol_location(SYMBOLS, "wCurMap").address
    project.hook(address, Sm83LoadAImmediate(current_map, address + 3), length=3)
    for offset in (7, 21, 27):
        project.hook(
            address + offset,
            Sm83LoadAAtHlIncrement(address + offset + 1),
            length=1,
        )
    for offset in (8, 22):
        project.hook(
            address + offset,
            Sm83CpImmediate(0xff, address + offset + 2),
            length=2,
        )
    for offset, register in ((12, "e"), (28, "e"), (32, "d")):
        project.hook(
            address + offset,
            Sm83CpRegister(register, address + offset + 1),
            length=1,
        )
    state = project.factory.blank_state(addr=address)
    set_assembly_registers(state, inputs)
    state.memory.store(current_map, inputs["current_map"])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    return [
        DungeonEndpoint(
            **assembly_registers(end),
            current_map=end.memory.load(current_map, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, GB_RETURN)
    ]


def _dungeon_native(inputs: dict[str, claripy.ast.BV]) -> list[DungeonEndpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(
        "port_get_battle_transition_id_is_dungeon_map"
    )
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["current_map"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        DungeonEndpoint(
            **native_registers(end, NATIVE_STATE),
            current_map=end.memory.load(NATIVE_STATE + 8, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_wild_or_trainer_symbolic_equivalence() -> None:
    inputs = symbolic_registers("wild_or_trainer")
    inputs["current_opponent"] = claripy.BVS("wild_or_trainer_opponent", 8)
    assert_pathwise_equivalent(
        _opponent_assembly(inputs),
        _opponent_native(inputs),
        (*REGISTERS, "current_opponent"),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("first_alive", range(6))
def test_compare_levels_symbolic_equivalence(first_alive: int) -> None:
    prefix = f"compare_levels_{first_alive}"
    inputs = symbolic_registers(prefix)
    for name in (*HP_NAMES, *LEVEL_NAMES, "enemy_level", "spiral"):
        inputs[name] = claripy.BVS(f"{prefix}_{name}", 8)
    assert_pathwise_equivalent(
        _level_assembly(inputs, first_alive),
        _level_native(inputs, first_alive),
        (*REGISTERS, *HP_NAMES, *LEVEL_NAMES, "enemy_level", "spiral"),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_is_dungeon_map_symbolic_equivalence() -> None:
    inputs = symbolic_registers("is_dungeon_map")
    inputs["current_map"] = claripy.BVS("is_dungeon_map_current_map", 8)
    assert_pathwise_equivalent(
        _dungeon_assembly(inputs),
        _dungeon_native(inputs),
        (*REGISTERS, "current_map"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "size", "expected"),
    [
        ("GetBattleTransitionID_WildOrTrainer", 13, "fa59d0fec83003cb81c9cbc1c9"),
        (
            "GetBattleTransitionID_CompareLevels",
            42,
            "216cd12ab62006112b001918f6111f00197ec6035ffa27d1933008cb893e01ea47cdc9cbc9afea47cdc9",
        ),
        (
            "GetBattleTransitionID_IsDungeonMap",
            38,
            "fa5ed35f213f4a2afeff2806bb20f8cbd1c921444a2afeff2809572abb38f67bba30eccb91c9",
        ),
    ],
)
def test_battle_transition_machine_code_is_accounted_for(
    symbol: str, size: int, expected: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, size) == bytes.fromhex(expected)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_dungeon_map_tables_are_accounted_for() -> None:
    exact = symbol_location(SYMBOLS, "DungeonMaps1")
    ranges = symbol_location(SYMBOLS, "DungeonMaps2")
    assert linked_bytes(ROM, exact, 5) == bytes.fromhex("3352c0e8ff")
    assert linked_bytes(ROM, ranges, 9) == bytes.fromhex("3b3d5f768d97cfe4ff")
