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
    Sm83LoadAAtHlDecrement,
    Sm83LoadAHighImmediate,
    Sm83LoadAImmediate,
    Sm83RrRegister,
    Sm83SrlRegister,
    Sm83StoreAAtHlIncrement,
    Sm83StoreAHighImmediate,
)


ROOT = Path(__file__).resolve().parents[2]
VERIFY = ROOT / "verification"
NATIVE_ELF = VERIFY / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
GB_STACK = 0xD000
GB_RETURN = 0xFFFF
NATIVE_STATE = 0x100000
MEMORY_NAMES = (
    "whose_turn",
    "player_status",
    "enemy_status",
    "player_speed_high",
    "player_speed_low",
    "enemy_speed_high",
    "enemy_speed_low",
    "player_attack_high",
    "player_attack_low",
    "enemy_attack_high",
    "enemy_attack_low",
)


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
    player_status: claripy.ast.BV
    enemy_status: claripy.ast.BV
    player_speed_high: claripy.ast.BV
    player_speed_low: claripy.ast.BV
    enemy_speed_high: claripy.ast.BV
    enemy_speed_low: claripy.ast.BV
    player_attack_high: claripy.ast.BV
    player_attack_low: claripy.ast.BV
    enemy_attack_high: claripy.ast.BV
    enemy_attack_low: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _addresses() -> dict[str, int]:
    player_speed = symbol_location(SYMBOLS, "wBattleMonSpeed").address
    enemy_speed = symbol_location(SYMBOLS, "wEnemyMonSpeed").address
    player_attack = symbol_location(SYMBOLS, "wBattleMonAttack").address
    enemy_attack = symbol_location(SYMBOLS, "wEnemyMonAttack").address
    return {
        "whose_turn": symbol_location(SYMBOLS, "hWhoseTurn").address,
        "player_status": symbol_location(SYMBOLS, "wBattleMonStatus").address,
        "enemy_status": symbol_location(SYMBOLS, "wEnemyMonStatus").address,
        "player_speed_high": player_speed,
        "player_speed_low": player_speed + 1,
        "enemy_speed_high": enemy_speed,
        "enemy_speed_low": enemy_speed + 1,
        "player_attack_high": player_attack,
        "player_attack_low": player_attack + 1,
        "enemy_attack_high": enemy_attack,
        "enemy_attack_low": enemy_attack + 1,
    }


def _hook_penalty_body(project: angr.Project, symbol: str) -> None:
    base = symbol_location(SYMBOLS, symbol).address
    project.hook(base, Sm83LoadAHighImmediate(0xF3, base + 2), length=2)
    if symbol == "QuarterSpeedDueToParalysis":
        status_loads = ((5, "player_status"), (33, "enemy_status"))
        decrements = (14, 42)
        shifts = (17, 21, 45, 49)
        rotates = (19, 23, 47, 51)
        stores = (25, 53)
    else:
        status_loads = ((5, "player_status"), (29, "enemy_status"))
        decrements = (14, 38)
        shifts = (17, 41)
        rotates = (19, 43)
        stores = (21, 45)
    addresses = _addresses()
    for offset, name in status_loads:
        project.hook(
            base + offset,
            Sm83LoadAImmediate(addresses[name], base + offset + 3),
            length=3,
        )
    for offset in decrements:
        project.hook(
            base + offset,
            Sm83LoadAAtHlDecrement(base + offset + 1),
            length=1,
        )
    for offset in shifts:
        project.hook(
            base + offset,
            Sm83SrlRegister("a", base + offset + 2),
            length=2,
        )
    for offset in rotates:
        project.hook(
            base + offset,
            Sm83RrRegister("b", base + offset + 2),
            length=2,
        )
    for offset in stores:
        project.hook(
            base + offset,
            Sm83StoreAAtHlIncrement(base + offset + 1),
            length=1,
        )


def _assembly_endpoints(
    symbol: str, inputs: dict[str, claripy.ast.BV]
) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, symbol)
    addresses = _addresses()
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
    common = symbol_location(SYMBOLS, "ApplyBurnAndParalysisPenalties").address
    project.hook(
        common,
        Sm83StoreAHighImmediate(0xF3, common + 2),
        length=2,
    )
    _hook_penalty_body(project, "QuarterSpeedDueToParalysis")
    _hook_penalty_body(project, "HalveAttackDueToBurn")
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    for name, address in addresses.items():
        state.memory.store(address, inputs[name])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    return [
        Endpoint(
            **assembly_registers(end),
            **{name: end.memory.load(address, 1) for name, address in addresses.items()},
            constraints=tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, GB_RETURN)
    ]


def _native_endpoints(
    c_symbol: str, inputs: dict[str, claripy.ast.BV]
) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(c_symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    for offset, name in enumerate(MEMORY_NAMES, 8):
        state.memory.store(NATIVE_STATE + offset, inputs[name])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            **{
                name: end.memory.load(NATIVE_STATE + offset, 1)
                for offset, name in enumerate(MEMORY_NAMES, 8)
            },
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("assembly_symbol", "c_symbol"),
    [
        (
            "ApplyBurnAndParalysisPenaltiesToPlayer",
            "port_apply_burn_and_paralysis_penalties_to_player",
        ),
        (
            "ApplyBurnAndParalysisPenaltiesToEnemy",
            "port_apply_burn_and_paralysis_penalties_to_enemy",
        ),
        (
            "ApplyBurnAndParalysisPenalties",
            "port_apply_burn_and_paralysis_penalties",
        ),
    ],
)
def test_combined_penalties_symbolic_equivalence(
    assembly_symbol: str, c_symbol: str
) -> None:
    inputs = symbolic_registers(assembly_symbol)
    for name in MEMORY_NAMES:
        inputs[name] = claripy.BVS(f"{assembly_symbol}_{name}", 8)
    assert_pathwise_equivalent(
        _assembly_endpoints(assembly_symbol, inputs),
        _native_endpoints(c_symbol, inputs),
        (*REGISTERS, *MEMORY_NAMES),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "size", "expected"),
    [
        (
            "ApplyBurnAndParalysisPenaltiesToPlayer",
            13,
            "3e011801afe0f3cd276dc3646d",
        ),
        (
            "ApplyBurnAndParalysisPenaltiesToEnemy",
            9,
            "afe0f3cd276dc3646d",
        ),
        (
            "ApplyBurnAndParalysisPenalties",
            8,
            "e0f3cd276dc3646d",
        ),
    ],
)
def test_combined_penalty_entry_code_is_accounted_for(
    symbol: str, size: int, expected: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, size) == bytes.fromhex(expected)
