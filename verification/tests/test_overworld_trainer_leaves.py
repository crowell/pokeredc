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
from verification.harness.rom import (
    collect_returns,
    linked_bytes,
    rom_window,
    sm83_flags_to_z80,
    symbol_location,
)
from verification.harness.sm83_shims import Sm83CpImmediate, Sm83LoadAImmediate, Sm83StoreAImmediate


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_CALLBACK = 0x100100
GB_STACK = 0xD000
GB_RETURN = 0xFFFF
DONE = 0xEFFF


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
    memory: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class TileBoundary(angr.SimProcedure):
    def __init__(self, full: bool, destination: int):
        super().__init__()
        self.full = full
        self.destination = destination

    def run(self):
        self.state.globals["dispatched"] = claripy.BVV(1, 8)
        if self.full:
            callback = self.state.globals["callback"]
            for register in REGISTERS:
                value = callback[register]
                if register == "f":
                    value = sm83_flags_to_z80(value)
                setattr(self.state.regs, register, value)
            self.state.memory.store(self.destination, callback["standing"])
        self.jump(DONE)


def _project(symbol: str) -> tuple[angr.Project, int]:
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


def _tile_inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    inputs = symbolic_registers(prefix)
    inputs["fetched"] = claripy.BVS(prefix + "_fetched", 8)
    inputs["standing"] = claripy.BVS(prefix + "_standing", 8)
    inputs["dispatched"] = claripy.BVS(prefix + "_dispatched", 8)
    for register, value in symbolic_registers(prefix + "_callback").items():
        inputs["callback_" + register] = value
    inputs["callback_standing"] = claripy.BVS(prefix + "_callback_standing", 8)
    return inputs


def _tile_assembly(inputs: dict[str, claripy.ast.BV], full: bool) -> list[Endpoint]:
    project, address = _project("CheckForTilePairCollisions2")
    source = symbol_location(SYMBOLS, "wTileMap").address + 9 * 20 + 8
    destination = symbol_location(SYMBOLS, "wTilePlayerStandingOn").address
    project.hook(address, Sm83LoadAImmediate(source, address + 3), length=3)
    project.hook(address + 3, Sm83StoreAImmediate(destination, address + 6), length=3)
    project.hook(address + 6, TileBoundary(full, destination), length=1)
    state = project.factory.blank_state(addr=address)
    set_assembly_registers(state, inputs)
    state.memory.store(source, inputs["fetched"])
    state.memory.store(destination, inputs["standing"])
    state.globals["dispatched"] = inputs["dispatched"]
    state.globals["callback"] = {
        register: inputs["callback_" + register] for register in REGISTERS
    } | {"standing": inputs["callback_standing"]}
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE)
    return [
        Endpoint(
            **assembly_registers(end),
            memory=claripy.Concat(
                end.memory.load(destination, 1),
                end.globals["dispatched"],
            ),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _tile_native(inputs: dict[str, claripy.ast.BV], full: bool) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    suffix = "" if full else "_begin"
    function = project.loader.find_symbol("port_check_for_tile_pair_collisions2" + suffix)
    assert function is not None
    if full:
        state = project.factory.call_state(
            function.rebased_addr,
            NATIVE_STATE,
            NATIVE_CALLBACK,
            inputs["callback_standing"],
        )
        store_native_registers(
            state,
            NATIVE_CALLBACK,
            {register: inputs["callback_" + register] for register in REGISTERS},
        )
    else:
        state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(
        NATIVE_STATE + 8,
        claripy.Concat(inputs["fetched"], inputs["standing"], inputs["dispatched"]),
    )
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=end.memory.load(NATIVE_STATE + 9, 2),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.parametrize("full", (False, True))
def test_tile_pair_entry_equivalence(full: bool) -> None:
    inputs = _tile_inputs("tile_pair_" + str(full))
    assert_pathwise_equivalent(
        _tile_assembly(inputs, full), _tile_native(inputs, full), (*REGISTERS, "memory")
    )


def _enemy_inputs() -> dict[str, claripy.ast.BV]:
    inputs = symbolic_registers("enemy_parameters")
    for name in (
        "engaged_class", "engaged_set", "current_opponent", "enemy_class",
        "trainer_number", "enemy_level",
    ):
        inputs[name] = claripy.BVS("enemy_parameters_" + name, 8)
    return inputs


def _enemy_addresses() -> dict[str, int]:
    return {
        "engaged_class": symbol_location(SYMBOLS, "wEngagedTrainerClass").address,
        "engaged_set": symbol_location(SYMBOLS, "wEngagedTrainerSet").address,
        "current_opponent": symbol_location(SYMBOLS, "wCurOpponent").address,
        "enemy_class": symbol_location(SYMBOLS, "wEnemyMonOrTrainerClass").address,
        "trainer_number": symbol_location(SYMBOLS, "wTrainerNo").address,
        "enemy_level": symbol_location(SYMBOLS, "wCurEnemyLevel").address,
    }


def _enemy_assembly(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, address = _project("InitBattleEnemyParameters")
    memory = _enemy_addresses()
    for offset, name, next_offset in (
        (0, "engaged_class", 3),
        (11, "engaged_set", 14),
    ):
        project.hook(address + offset, Sm83LoadAImmediate(memory[name], address + next_offset), length=3)
    for offset, name, next_offset in (
        (3, "current_opponent", 6),
        (6, "enemy_class", 9),
        (16, "trainer_number", 19),
        (20, "enemy_level", 23),
    ):
        project.hook(address + offset, Sm83StoreAImmediate(memory[name], address + next_offset), length=3)
    project.hook(address + 9, Sm83CpImmediate(200, address + 11), length=2)
    state = project.factory.blank_state(addr=address)
    set_assembly_registers(state, inputs)
    for name, memory_address in memory.items():
        state.memory.store(memory_address, inputs[name])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    return [
        Endpoint(
            **assembly_registers(end),
            memory=claripy.Concat(*(end.memory.load(memory[name], 1) for name in memory)),
            constraints=tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, GB_RETURN)
    ]


def _enemy_native(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_init_battle_enemy_parameters")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    names = tuple(_enemy_addresses())
    state.memory.store(NATIVE_STATE + 8, claripy.Concat(*(inputs[name] for name in names)))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=end.memory.load(NATIVE_STATE + 8, len(names)),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
def test_init_battle_enemy_parameters_equivalence() -> None:
    inputs = _enemy_inputs()
    assert_pathwise_equivalent(
        _enemy_assembly(inputs), _enemy_native(inputs), (*REGISTERS, "memory")
    )


def test_exact_linked_bodies() -> None:
    tile = symbol_location(SYMBOLS, "CheckForTilePairCollisions2")
    assert linked_bytes(ROM, tile, 6) == bytes.fromhex("fa5cc4ea0ecf")
    enemy = symbol_location(SYMBOLS, "InitBattleEnemyParameters")
    assert linked_bytes(ROM, enemy, 24) == bytes.fromhex(
        "fa2dcdea59d0ea13d7fec8fa2ecd3804ea5dd0c9ea27d1c9"
    )
