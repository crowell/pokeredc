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
from verification.harness.sm83_shims import Sm83StoreAImmediate


ROOT = Path(__file__).resolve().parents[2]
VERIFY = ROOT / "verification"
NATIVE_ELF = VERIFY / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
GB_STACK = 0xD000
GB_RETURN = 0xFFFF
NATIVE_STATE = 0x100000


RESET_PORTS = (
    ("CeladonGymResetScripts", "wCeladonGymCurScript", "port_celadon_gym_reset_scripts"),
    ("CeruleanGymResetScripts", "wCeruleanGymCurScript", "port_cerulean_gym_reset_scripts"),
    ("FightingDojoResetScripts", "wFightingDojoCurScript", "port_fighting_dojo_reset_scripts"),
    ("FuchsiaGymResetScripts", "wFuchsiaGymCurScript", "port_fuchsia_gym_reset_scripts"),
    (
        "GameCornerReenterMapAfterPlayerLoss",
        "wGameCornerCurScript",
        "port_game_corner_reenter_map_after_player_loss",
    ),
    ("MtMoonB2FResetScripts", "wMtMoonB2FCurScript", "port_mt_moon_b2f_reset_scripts"),
    ("PewterGymResetScripts", "wPewterGymCurScript", "port_pewter_gym_reset_scripts"),
    (
        "PokemonTower2FResetRivalEncounter",
        "wPokemonTower2FCurScript",
        "port_pokemon_tower_2f_reset_rival_encounter",
    ),
    (
        "PokemonTower6FSetDefaultScript",
        "wPokemonTower6FCurScript",
        "port_pokemon_tower_6f_set_default_script",
    ),
    (
        "PokemonTower7FSetDefaultScript",
        "wPokemonTower7FCurScript",
        "port_pokemon_tower_7f_set_default_script",
    ),
    (
        "RocketHideoutB4FSetDefaultScript",
        "wRocketHideoutB4FCurScript",
        "port_rocket_hideout_b4f_set_default_script",
    ),
    ("Route12ResetScripts", "wRoute12CurScript", "port_route_12_reset_scripts"),
    ("Route16ResetScripts", "wRoute16CurScript", "port_route_16_reset_scripts"),
    ("Route24SetDefaultScript", "wRoute24CurScript", "port_route_24_set_default_script"),
    ("SaffronGymResetScripts", "wSaffronGymCurScript", "port_saffron_gym_reset_scripts"),
    ("VermilionGymResetScripts", "wVermilionGymCurScript", "port_vermilion_gym_reset_scripts"),
    ("ViridianGymResetScripts", "wViridianGymCurScript", "port_viridian_gym_reset_scripts"),
    (
        "SilphCo11FResetCurScript",
        "wSilphCo11FCurScript",
        "port_silph_co_11f_reset_cur_script",
    ),
    (
        "SilphCo7FSetDefaultScript",
        "wSilphCo7FCurScript",
        "port_silph_co_7f_set_default_script",
    ),
)

ZERO_STORE_PORTS = (
    ("ResetAgathaScript", ("wAgathasRoomCurScript",), "port_reset_agatha_script"),
    ("ResetBrunoScript", ("wBrunosRoomCurScript",), "port_reset_bruno_script"),
    (
        "ResetRivalScript",
        ("wJoyIgnore", "wChampionsRoomCurScript"),
        "port_reset_rival_script",
    ),
    (
        "CinnabarGymResetScripts",
        (
            "wJoyIgnore",
            "wCinnabarGymCurScript",
            "wCurMapScript",
            "wOpponentAfterWrongAnswer",
        ),
        "port_cinnabar_gym_reset_scripts",
    ),
    ("ResetLanceScript", ("wLancesRoomCurScript",), "port_reset_lance_script"),
    ("ResetLoreleiScript", ("wLoreleisRoomCurScript",), "port_reset_lorelei_script"),
    (
        "SSAnne2FResetScripts",
        ("wJoyIgnore", "wSSAnne2FCurScript"),
        "port_ss_anne_2f_reset_scripts",
    ),
    (
        "Route22SetDefaultScript",
        ("wJoyIgnore", "wRoute22CurScript"),
        "port_route_22_set_default_script",
    ),
)


@dataclass(frozen=True)
class ResetEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    joy_ignore: claripy.ast.BV
    current_script: claripy.ast.BV
    current_map_script: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class ZeroStoresEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    memory0: claripy.ast.BV
    memory1: claripy.ast.BV
    memory2: claripy.ast.BV
    memory3: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _assembly_endpoint(
    symbol: str,
    current_script_symbol: str,
    inputs: dict[str, claripy.ast.BV],
) -> ResetEndpoint:
    location = symbol_location(SYMBOLS, symbol)
    destinations = (
        symbol_location(SYMBOLS, "wJoyIgnore").address,
        symbol_location(SYMBOLS, current_script_symbol).address,
        symbol_location(SYMBOLS, "wCurMapScript").address,
    )
    assert len(set(destinations)) == 3
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
    for offset, destination in zip((1, 4, 7), destinations):
        project.hook(
            location.address + offset,
            Sm83StoreAImmediate(destination, location.address + offset + 3),
            length=3,
        )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    for index, destination in enumerate(destinations):
        state.memory.store(destination, inputs[f"memory{index}"])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    assert len(returned) == 1
    end = returned[0]
    return ResetEndpoint(
        **assembly_registers(end),
        joy_ignore=end.memory.load(destinations[0], 1),
        current_script=end.memory.load(destinations[1], 1),
        current_map_script=end.memory.load(destinations[2], 1),
        constraints=tuple(end.solver.constraints),
    )


def _native_endpoint(c_symbol: str, inputs: dict[str, claripy.ast.BV]) -> ResetEndpoint:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(c_symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    for index in range(3):
        state.memory.store(NATIVE_STATE + 8 + index, inputs[f"memory{index}"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    end = manager.deadended[0]
    return ResetEndpoint(
        **native_registers(end, NATIVE_STATE),
        joy_ignore=end.memory.load(NATIVE_STATE + 8, 1),
        current_script=end.memory.load(NATIVE_STATE + 9, 1),
        current_map_script=end.memory.load(NATIVE_STATE + 10, 1),
        constraints=tuple(end.solver.constraints),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("symbol,current_script_symbol,c_symbol", RESET_PORTS)
def test_script_reset_symbolic_equivalence(
    symbol: str, current_script_symbol: str, c_symbol: str
) -> None:
    inputs = symbolic_registers(symbol.lower())
    for index, name in enumerate(("joy_ignore", "current_script", "current_map_script")):
        inputs[f"memory{index}"] = claripy.BVS(f"{symbol.lower()}_{name}", 8)
    assembly = _assembly_endpoint(symbol, current_script_symbol, inputs)
    native = _native_endpoint(c_symbol, inputs)
    assert_pathwise_equivalent(
        [assembly],
        [native],
        (*REGISTERS, "joy_ignore", "current_script", "current_map_script"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("symbol,current_script_symbol,_c_symbol", RESET_PORTS)
def test_script_reset_exact_linked_body(
    symbol: str, current_script_symbol: str, _c_symbol: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    destinations = (
        symbol_location(SYMBOLS, "wJoyIgnore").address,
        symbol_location(SYMBOLS, current_script_symbol).address,
        symbol_location(SYMBOLS, "wCurMapScript").address,
    )
    expected = bytearray((0xAF,))
    for destination in destinations:
        expected.extend((0xEA, destination & 0xFF, destination >> 8))
    expected.append(0xC9)
    assert linked_bytes(ROM, location, len(expected)) == bytes(expected)


def _zero_stores_assembly(
    symbol: str,
    destination_symbols: tuple[str, ...],
    inputs: dict[str, claripy.ast.BV],
) -> ZeroStoresEndpoint:
    location = symbol_location(SYMBOLS, symbol)
    destinations = tuple(
        symbol_location(SYMBOLS, destination).address
        for destination in destination_symbols
    )
    assert len(set(destinations)) == len(destinations)
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
    for index, destination in enumerate(destinations):
        offset = 1 + 3 * index
        project.hook(
            location.address + offset,
            Sm83StoreAImmediate(destination, location.address + offset + 3),
            length=3,
        )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    for index, destination in enumerate(destinations):
        state.memory.store(destination, inputs[f"memory{index}"])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    assert len(returned) == 1
    end = returned[0]
    outputs = {
        f"memory{index}": (
            end.memory.load(destinations[index], 1)
            if index < len(destinations)
            else inputs[f"memory{index}"]
        )
        for index in range(4)
    }
    return ZeroStoresEndpoint(
        **assembly_registers(end),
        **outputs,
        constraints=tuple(end.solver.constraints),
    )


def _zero_stores_native(
    c_symbol: str, inputs: dict[str, claripy.ast.BV]
) -> ZeroStoresEndpoint:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(c_symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    for index in range(4):
        state.memory.store(NATIVE_STATE + 8 + index, inputs[f"memory{index}"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    end = manager.deadended[0]
    return ZeroStoresEndpoint(
        **native_registers(end, NATIVE_STATE),
        **{
            f"memory{index}": end.memory.load(NATIVE_STATE + 8 + index, 1)
            for index in range(4)
        },
        constraints=tuple(end.solver.constraints),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("symbol,destination_symbols,c_symbol", ZERO_STORE_PORTS)
def test_zero_store_leaf_symbolic_equivalence(
    symbol: str, destination_symbols: tuple[str, ...], c_symbol: str
) -> None:
    inputs = symbolic_registers(symbol.lower())
    for index in range(4):
        inputs[f"memory{index}"] = claripy.BVS(
            f"{symbol.lower()}_memory{index}", 8
        )
    assembly = _zero_stores_assembly(symbol, destination_symbols, inputs)
    native = _zero_stores_native(c_symbol, inputs)
    assert_pathwise_equivalent(
        [assembly],
        [native],
        (*REGISTERS, *(f"memory{index}" for index in range(len(destination_symbols)))),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("symbol,destination_symbols,_c_symbol", ZERO_STORE_PORTS)
def test_zero_store_leaf_exact_linked_body(
    symbol: str, destination_symbols: tuple[str, ...], _c_symbol: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    expected = bytearray((0xAF,))
    for destination_symbol in destination_symbols:
        destination = symbol_location(SYMBOLS, destination_symbol).address
        expected.extend((0xEA, destination & 0xFF, destination >> 8))
    expected.append(0xC9)
    assert linked_bytes(ROM, location, len(expected)) == bytes(expected)


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_execute_player_move_done_symbolic_equivalence() -> None:
    inputs = symbolic_registers("execute_player_move_done")
    for index in range(4):
        inputs[f"memory{index}"] = claripy.BVS(
            f"execute_player_move_done_memory{index}", 8
        )
    assembly = _zero_stores_assembly(
        "ExecutePlayerMoveDone", ("wActionResultOrTookBattleTurn",), inputs
    )
    native = _zero_stores_native("port_execute_player_move_done", inputs)
    assert_pathwise_equivalent(
        [assembly], [native], (*REGISTERS, "memory0")
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_execute_player_move_done_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "ExecutePlayerMoveDone")
    destination = symbol_location(SYMBOLS, "wActionResultOrTookBattleTurn").address
    assert linked_bytes(ROM, location, 7) == bytes(
        (0xAF, 0xEA, destination & 0xFF, destination >> 8, 0x06, 1, 0xC9)
    )
