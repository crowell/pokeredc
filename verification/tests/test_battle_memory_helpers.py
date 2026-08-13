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
    Sm83DecAtHl,
    Sm83DecRegister,
    Sm83LoadAImmediate,
    Sm83StoreAImmediate,
)


ROOT = Path(__file__).resolve().parents[2]
VERIFY = ROOT / "verification"
NATIVE_ELF = VERIFY / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
GB_STACK = 0xD000
GB_RETURN = 0xFFFF
NATIVE_STATE = 0x100000
X_NAMES = tuple(f"x{index}" for index in range(21))


@dataclass(frozen=True)
class SlideEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    x0: claripy.ast.BV
    x1: claripy.ast.BV
    x2: claripy.ast.BV
    x3: claripy.ast.BV
    x4: claripy.ast.BV
    x5: claripy.ast.BV
    x6: claripy.ast.BV
    x7: claripy.ast.BV
    x8: claripy.ast.BV
    x9: claripy.ast.BV
    x10: claripy.ast.BV
    x11: claripy.ast.BV
    x12: claripy.ast.BV
    x13: claripy.ast.BV
    x14: claripy.ast.BV
    x15: claripy.ast.BV
    x16: claripy.ast.BV
    x17: claripy.ast.BV
    x18: claripy.ast.BV
    x19: claripy.ast.BV
    x20: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class SwapEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    player_level: claripy.ast.BV
    enemy_level: claripy.ast.BV
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


def _slide_assembly(inputs: dict[str, claripy.ast.BV]) -> SlideEndpoint:
    project, address = _z80_project("SlidePlayerHeadLeft")
    first_x = symbol_location(SYMBOLS, "wShadowOAMSprite00XCoord").address
    x_addresses = tuple(first_x + index * 4 for index in range(21))
    project.hook(address + 9, Sm83DecAtHl(address + 10), length=1)
    project.hook(address + 10, Sm83DecAtHl(address + 11), length=1)
    project.hook(address + 12, Sm83DecRegister("c", address + 13), length=1)
    state = project.factory.blank_state(addr=address)
    set_assembly_registers(state, inputs)
    for name, memory_address in zip(X_NAMES, x_addresses, strict=True):
        state.memory.store(memory_address, inputs[name])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    end = collect_returns(project, state, GB_RETURN)[0]
    return SlideEndpoint(
        **assembly_registers(end),
        **{
            name: end.memory.load(memory_address, 1)
            for name, memory_address in zip(X_NAMES, x_addresses, strict=True)
        },
        constraints=tuple(end.solver.constraints),
    )


def _slide_native(inputs: dict[str, claripy.ast.BV]) -> SlideEndpoint:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_slide_player_head_left")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    for offset, name in enumerate(X_NAMES, 8):
        state.memory.store(NATIVE_STATE + offset, inputs[name])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    end = manager.deadended[0]
    return SlideEndpoint(
        **native_registers(end, NATIVE_STATE),
        **{
            name: end.memory.load(NATIVE_STATE + offset, 1)
            for offset, name in enumerate(X_NAMES, 8)
        },
        constraints=tuple(end.solver.constraints),
    )


def _swap_assembly(inputs: dict[str, claripy.ast.BV]) -> SwapEndpoint:
    project, address = _z80_project("SwapPlayerAndEnemyLevels")
    player = symbol_location(SYMBOLS, "wBattleMonLevel").address
    enemy = symbol_location(SYMBOLS, "wEnemyMonLevel").address
    project.hook(address + 1, Sm83LoadAImmediate(player, address + 4), length=3)
    project.hook(address + 5, Sm83LoadAImmediate(enemy, address + 8), length=3)
    project.hook(address + 8, Sm83StoreAImmediate(player, address + 11), length=3)
    project.hook(address + 12, Sm83StoreAImmediate(enemy, address + 15), length=3)
    state = project.factory.blank_state(addr=address)
    set_assembly_registers(state, inputs)
    state.memory.store(player, inputs["player_level"])
    state.memory.store(enemy, inputs["enemy_level"])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    end = collect_returns(project, state, GB_RETURN)[0]
    return SwapEndpoint(
        **assembly_registers(end),
        player_level=end.memory.load(player, 1),
        enemy_level=end.memory.load(enemy, 1),
        constraints=tuple(end.solver.constraints),
    )


def _swap_native(inputs: dict[str, claripy.ast.BV]) -> SwapEndpoint:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_swap_player_and_enemy_levels")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["player_level"])
    state.memory.store(NATIVE_STATE + 9, inputs["enemy_level"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    end = manager.deadended[0]
    return SwapEndpoint(
        **native_registers(end, NATIVE_STATE),
        player_level=end.memory.load(NATIVE_STATE + 8, 1),
        enemy_level=end.memory.load(NATIVE_STATE + 9, 1),
        constraints=tuple(end.solver.constraints),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_slide_player_head_left_symbolic_equivalence() -> None:
    inputs = symbolic_registers("slide_player_head")
    for name in X_NAMES:
        inputs[name] = claripy.BVS(f"slide_player_head_{name}", 8)
    assert_pathwise_equivalent(
        [_slide_assembly(inputs)],
        [_slide_native(inputs)],
        (*REGISTERS, *X_NAMES),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_swap_player_and_enemy_levels_symbolic_equivalence() -> None:
    inputs = symbolic_registers("swap_levels")
    inputs["player_level"] = claripy.BVS("swap_levels_player", 8)
    inputs["enemy_level"] = claripy.BVS("swap_levels_enemy", 8)
    assert_pathwise_equivalent(
        [_swap_assembly(inputs)],
        [_swap_native(inputs)],
        (*REGISTERS, "player_level", "enemy_level"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "size", "expected"),
    [
        ("SlidePlayerHeadLeft", 17, "c52101c30e151104003535190d20fac1c9"),
        (
            "SwapPlayerAndEnemyLevels",
            17,
            "c5fa22d047faf3cfea22d078eaf3cfc1c9",
        ),
    ],
)
def test_battle_memory_helper_code_is_accounted_for(
    symbol: str, size: int, expected: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, size) == bytes.fromhex(expected)
