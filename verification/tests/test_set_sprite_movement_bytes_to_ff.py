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
    Sm83AddHlRegisterPair,
    Sm83AddImmediate,
    Sm83AddRegister,
    Sm83DecRegister,
    Sm83LoadAHighImmediate,
    Sm83SwapRegister,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xFFFF
SPRITE_INDEX = 0xFF8C
SPRITE_STATE_DATA2 = 0xC200
MAP_SPRITE_DATA = 0xD4E4
MAP_SPRITE_DATA_SIZE = 511
EXPECTED_BODY = bytes.fromhex("e5cd4e3536ffcd583536ffe1c9")


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


def _memory(state: angr.SimState, base: int = 0) -> claripy.ast.BV:
    return claripy.Concat(
        state.memory.load(base + SPRITE_INDEX, 1),
        state.memory.load(base + SPRITE_STATE_DATA2, 256),
        state.memory.load(base + MAP_SPRITE_DATA, MAP_SPRITE_DATA_SIZE),
    )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "SetSpriteMovementBytesToFF")
    pointer1 = symbol_location(SYMBOLS, "GetSpriteMovementByte1Pointer")
    pointer2 = symbol_location(SYMBOLS, "GetSpriteMovementByte2Pointer")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY
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
        pointer1.address + 2,
        Sm83LoadAHighImmediate(0x8C, pointer1.address + 4),
        length=2,
    )
    project.hook(
        pointer1.address + 4,
        Sm83SwapRegister("a", pointer1.address + 6),
        length=2,
    )
    project.hook(
        pointer1.address + 6,
        Sm83AddImmediate(6, pointer1.address + 8),
        length=2,
    )
    project.hook(
        pointer2.address + 4,
        Sm83LoadAHighImmediate(0x8C, pointer2.address + 6),
        length=2,
    )
    project.hook(
        pointer2.address + 6,
        Sm83DecRegister("a", pointer2.address + 7),
        length=1,
    )
    project.hook(
        pointer2.address + 7,
        Sm83AddRegister("a", pointer2.address + 8),
        length=1,
    )
    project.hook(
        pointer2.address + 11,
        Sm83AddHlRegisterPair("de", pointer2.address + 12),
        length=1,
    )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.memory.store(SPRITE_INDEX, values["sprite_index"])
    state.memory.store(SPRITE_STATE_DATA2, values["sprite_state_data2"])
    state.memory.store(MAP_SPRITE_DATA, values["map_sprite_data"])
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    return [
        Endpoint(
            **assembly_registers(end),
            memory=_memory(end),
            constraints=tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, RETURN)
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_set_sprite_movement_bytes_to_ff")
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_MEMORY + SPRITE_INDEX, values["sprite_index"])
    state.memory.store(
        NATIVE_MEMORY + SPRITE_STATE_DATA2, values["sprite_state_data2"]
    )
    state.memory.store(
        NATIVE_MEMORY + MAP_SPRITE_DATA, values["map_sprite_data"]
    )
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=_memory(end, NATIVE_MEMORY),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_set_sprite_movement_bytes_to_ff_pathwise_equivalence() -> None:
    values = symbolic_registers("set_sprite_movement_bytes_to_ff")
    values["sprite_index"] = claripy.BVS("sprite_index", 8)
    values["sprite_state_data2"] = claripy.BVS("sprite_state_data2", 256 * 8)
    values["map_sprite_data"] = claripy.BVS(
        "map_sprite_data", MAP_SPRITE_DATA_SIZE * 8
    )
    assert_pathwise_equivalent(
        _assembly(values), _native(values), (*REGISTERS, "memory")
    )
