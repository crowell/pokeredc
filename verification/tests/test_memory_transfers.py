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
    Sm83LoadAHighImmediate,
    Sm83LoadAImmediate,
    Sm83StoreAHighImmediate,
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
ROM_BANK_REGISTER = 0x2000

PORTS = (
    (
        "BankswitchBack",
        "port_bankswitch_back",
        ("wBankswitchHomeSavedROMBank", "hLoadedROMBank", ROM_BANK_REGISTER),
        ("load", "store_high", "store"),
    ),
    (
        "CinnabarGymSetTrainerHeader",
        "port_cinnabar_gym_set_trainer_header",
        ("hTextID", "wTrainerHeaderFlagBit"),
        ("load_high", "store"),
    ),
    (
        "SilphCo11FSetCurScript",
        "port_silph_co_11f_set_cur_script",
        ("wSilphCo11FCurScript", "wCurMapScript"),
        ("store", "store"),
    ),
    (
        "SilphCo7FSetCurScript",
        "port_silph_co_7f_set_cur_script",
        ("wSilphCo7FCurScript", "wCurMapScript"),
        ("store", "store"),
    ),
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
    memory0: claripy.ast.BV
    memory1: claripy.ast.BV
    memory2: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _addresses(symbols: tuple[str | int, ...]) -> tuple[int, ...]:
    return tuple(
        value if isinstance(value, int) else symbol_location(SYMBOLS, value).address
        for value in symbols
    )


def _assembly(
    symbol: str,
    destination_symbols: tuple[str | int, ...],
    operations: tuple[str, ...],
    inputs: dict[str, claripy.ast.BV],
) -> Endpoint:
    location = symbol_location(SYMBOLS, symbol)
    addresses = _addresses(destination_symbols)
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
    offset = 0
    classes = {
        "load": (Sm83LoadAImmediate, 3),
        "load_high": (Sm83LoadAHighImmediate, 2),
        "store": (Sm83StoreAImmediate, 3),
        "store_high": (Sm83StoreAHighImmediate, 2),
    }
    for operation, address in zip(operations, addresses):
        procedure, length = classes[operation]
        project.hook(
            location.address + offset,
            procedure(address, location.address + offset + length),
            length=length,
        )
        offset += length
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    for index, address in enumerate(addresses):
        state.memory.store(address, inputs[f"memory{index}"])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    assert len(returned) == 1
    end = returned[0]
    outputs = {
        f"memory{index}": (
            end.memory.load(addresses[index], 1)
            if index < len(addresses)
            else inputs[f"memory{index}"]
        )
        for index in range(3)
    }
    return Endpoint(
        **assembly_registers(end),
        **outputs,
        constraints=tuple(end.solver.constraints),
    )


def _native(c_symbol: str, inputs: dict[str, claripy.ast.BV]) -> Endpoint:
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
    return Endpoint(
        **native_registers(end, NATIVE_STATE),
        **{
            f"memory{index}": end.memory.load(NATIVE_STATE + 8 + index, 1)
            for index in range(3)
        },
        constraints=tuple(end.solver.constraints),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("symbol,c_symbol,destination_symbols,operations", PORTS)
def test_memory_transfer_symbolic_equivalence(
    symbol: str,
    c_symbol: str,
    destination_symbols: tuple[str | int, ...],
    operations: tuple[str, ...],
) -> None:
    inputs = symbolic_registers(symbol.lower())
    for index in range(3):
        inputs[f"memory{index}"] = claripy.BVS(f"{symbol.lower()}_memory{index}", 8)
    assert_pathwise_equivalent(
        [_assembly(symbol, destination_symbols, operations, inputs)],
        [_native(c_symbol, inputs)],
        (*REGISTERS, *(f"memory{index}" for index in range(len(destination_symbols)))),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_memory_transfer_exact_linked_bodies() -> None:
    saved = symbol_location(SYMBOLS, "wBankswitchHomeSavedROMBank").address
    loaded = symbol_location(SYMBOLS, "hLoadedROMBank").address
    location = symbol_location(SYMBOLS, "BankswitchBack")
    assert linked_bytes(ROM, location, 9) == bytes(
        (
            0xFA, saved & 0xFF, saved >> 8,
            0xE0, loaded & 0xFF,
            0xEA, ROM_BANK_REGISTER & 0xFF, ROM_BANK_REGISTER >> 8,
            0xC9,
        )
    )

    text_id = symbol_location(SYMBOLS, "hTextID").address
    trainer = symbol_location(SYMBOLS, "wTrainerHeaderFlagBit").address
    location = symbol_location(SYMBOLS, "CinnabarGymSetTrainerHeader")
    assert linked_bytes(ROM, location, 6) == bytes(
        (0xF0, text_id & 0xFF, 0xEA, trainer & 0xFF, trainer >> 8, 0xC9)
    )

    for symbol, current_script in (
        ("SilphCo11FSetCurScript", "wSilphCo11FCurScript"),
        ("SilphCo7FSetCurScript", "wSilphCo7FCurScript"),
    ):
        location = symbol_location(SYMBOLS, symbol)
        current = symbol_location(SYMBOLS, current_script).address
        map_script = symbol_location(SYMBOLS, "wCurMapScript").address
        assert linked_bytes(ROM, location, 7) == bytes(
            (
                0xEA, current & 0xFF, current >> 8,
                0xEA, map_script & 0xFF, map_script >> 8,
                0xC9,
            )
        )


def _store_trainer_header_assembly(
    inputs: dict[str, claripy.ast.BV]
) -> Endpoint:
    location = symbol_location(SYMBOLS, "StoreTrainerHeaderPointer")
    addresses = (
        symbol_location(SYMBOLS, "wTrainerHeaderPtr").address,
        symbol_location(SYMBOLS, "wTrainerHeaderPtr").address + 1,
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
    for offset, address in zip((1, 5), addresses):
        project.hook(
            location.address + offset,
            Sm83StoreAImmediate(address, location.address + offset + 3),
            length=3,
        )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    for index, address in enumerate(addresses):
        state.memory.store(address, inputs[f"memory{index}"])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    assert len(returned) == 1
    end = returned[0]
    return Endpoint(
        **assembly_registers(end),
        memory0=end.memory.load(addresses[0], 1),
        memory1=end.memory.load(addresses[1], 1),
        memory2=inputs["memory2"],
        constraints=tuple(end.solver.constraints),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_store_trainer_header_pointer_symbolic_equivalence() -> None:
    inputs = symbolic_registers("store_trainer_header_pointer")
    for index in range(3):
        inputs[f"memory{index}"] = claripy.BVS(
            f"store_trainer_header_pointer_memory{index}", 8
        )
    assert_pathwise_equivalent(
        [_store_trainer_header_assembly(inputs)],
        [_native("port_store_trainer_header_pointer", inputs)],
        (*REGISTERS, "memory0", "memory1"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_store_trainer_header_pointer_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "StoreTrainerHeaderPointer")
    destination = symbol_location(SYMBOLS, "wTrainerHeaderPtr").address
    assert linked_bytes(ROM, location, 9) == bytes(
        (
            0x7C,
            0xEA, destination & 0xFF, destination >> 8,
            0x7D,
            0xEA, (destination + 1) & 0xFF, (destination + 1) >> 8,
            0xC9,
        )
    )
