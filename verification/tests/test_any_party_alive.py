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
    Sm83DecRegister,
    Sm83LoadAImmediate,
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
    party_count: claripy.ast.BV
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
    constraints: tuple[claripy.ast.Bool, ...]


def _assembly_endpoints(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "AnyPartyAlive")
    party_count = symbol_location(SYMBOLS, "wPartyCount").address
    first_hp = symbol_location(SYMBOLS, "wPartyMon1HP").address
    hp_addresses = tuple(
        first_hp + mon * PARTY_LENGTH + byte for mon in range(6) for byte in range(2)
    )
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
    project.hook(
        location.address,
        Sm83LoadAImmediate(party_count, location.address + 3),
        length=3,
    )
    project.hook(
        location.address + 15,
        Sm83DecRegister("e", location.address + 16),
        length=1,
    )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    state.memory.store(party_count, inputs["party_count"])
    for name, address in zip(HP_NAMES, hp_addresses, strict=True):
        state.memory.store(address, inputs[name])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    return [
        Endpoint(
            **assembly_registers(end),
            party_count=end.memory.load(party_count, 1),
            **{
                name: end.memory.load(address, 1)
                for name, address in zip(HP_NAMES, hp_addresses, strict=True)
            },
            constraints=tuple(end.solver.constraints),
        )
        for end in returned
    ]


def _native_endpoints(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_any_party_alive")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["party_count"])
    for offset, name in enumerate(HP_NAMES, 9):
        state.memory.store(NATIVE_STATE + offset, inputs[name])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            party_count=end.memory.load(NATIVE_STATE + 8, 1),
            **{
                name: end.memory.load(NATIVE_STATE + offset, 1)
                for offset, name in enumerate(HP_NAMES, 9)
            },
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


def _enemy_assembly_endpoints(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "AnyEnemyPokemonAliveCheck")
    party_count = symbol_location(SYMBOLS, "wEnemyPartyCount").address
    first_hp = symbol_location(SYMBOLS, "wEnemyMon1HP").address
    hp_addresses = tuple(
        first_hp + mon * PARTY_LENGTH + byte for mon in range(6) for byte in range(2)
    )
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
    project.hook(
        location.address,
        Sm83LoadAImmediate(party_count, location.address + 3),
        length=3,
    )
    project.hook(
        location.address + 16,
        Sm83DecRegister("b", location.address + 17),
        length=1,
    )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    state.memory.store(party_count, inputs["party_count"])
    for name, address in zip(HP_NAMES, hp_addresses, strict=True):
        state.memory.store(address, inputs[name])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    return [
        Endpoint(
            **assembly_registers(end),
            party_count=end.memory.load(party_count, 1),
            **{
                name: end.memory.load(address, 1)
                for name, address in zip(HP_NAMES, hp_addresses, strict=True)
            },
            constraints=tuple(end.solver.constraints),
        )
        for end in returned
    ]


def _enemy_native_endpoints(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_any_enemy_pokemon_alive_check")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["party_count"])
    for offset, name in enumerate(HP_NAMES, 9):
        state.memory.store(NATIVE_STATE + offset, inputs[name])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            party_count=end.memory.load(NATIVE_STATE + 8, 1),
            **{
                name: end.memory.load(NATIVE_STATE + offset, 1)
                for offset, name in enumerate(HP_NAMES, 9)
            },
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("party_count", range(1, 7))
def test_any_party_alive_symbolic_equivalence(party_count: int) -> None:
    prefix = f"any_party_alive_{party_count}"
    inputs = symbolic_registers(prefix)
    inputs["party_count"] = claripy.BVV(party_count, 8)
    for name in HP_NAMES:
        inputs[name] = claripy.BVS(f"{prefix}_{name}", 8)
    assert_pathwise_equivalent(
        _assembly_endpoints(inputs),
        _native_endpoints(inputs),
        (*REGISTERS, "party_count", *HP_NAMES),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("party_count", range(1, 7))
def test_any_enemy_pokemon_alive_symbolic_equivalence(party_count: int) -> None:
    prefix = f"any_enemy_pokemon_alive_{party_count}"
    inputs = symbolic_registers(prefix)
    inputs["party_count"] = claripy.BVV(party_count, 8)
    for name in HP_NAMES:
        inputs[name] = claripy.BVS(f"{prefix}_{name}", 8)
    assert_pathwise_equivalent(
        _enemy_assembly_endpoints(inputs),
        _enemy_native_endpoints(inputs),
        (*REGISTERS, "party_count", *HP_NAMES),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_any_party_alive_machine_code_is_accounted_for() -> None:
    location = symbol_location(SYMBOLS, "AnyPartyAlive")
    assert linked_bytes(ROM, location, 20) == bytes.fromhex(
        "fa63d15faf216cd1012b00b623b6091d20f957c9"
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_any_enemy_pokemon_alive_machine_code_is_accounted_for() -> None:
    location = symbol_location(SYMBOLS, "AnyEnemyPokemonAliveCheck")
    assert linked_bytes(ROM, location, 21) == bytes.fromhex(
        "fa9cd847af21a5d8112c00b623b62b190520f8a7c9"
    )
