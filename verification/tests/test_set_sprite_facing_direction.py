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
    Sm83AddRegister,
    Sm83LoadAHighImmediate,
    Sm83StoreAHighImmediate,
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
SPRITE_DATA_OFFSET = 0xFF8B
SPRITE_INDEX = 0xFF8C
SPRITE_FACING_DIRECTION = 0xFF8D
SPRITE_STATE_DATA1 = 0xC100
EXPECTED_BODY = bytes.fromhex("3e09e08bcdfc34f08d77c9")


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
        state.memory.load(base + SPRITE_DATA_OFFSET, 1),
        state.memory.load(base + SPRITE_INDEX, 1),
        state.memory.load(base + SPRITE_FACING_DIRECTION, 1),
        state.memory.load(base + SPRITE_STATE_DATA1, 256),
    )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "SetSpriteFacingDirection")
    callee = symbol_location(SYMBOLS, "GetPointerWithinSpriteStateData1")
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
    base = location.address
    project.hook(
        base + 2,
        Sm83StoreAHighImmediate(0x8B, base + 4),
        length=2,
    )
    project.hook(
        base + 7,
        Sm83LoadAHighImmediate(0x8D, base + 9),
        length=2,
    )
    project.hook(
        callee.address + 6,
        Sm83LoadAHighImmediate(0x8B, callee.address + 8),
        length=2,
    )
    project.hook(
        callee.address + 9,
        Sm83LoadAHighImmediate(0x8C, callee.address + 11),
        length=2,
    )
    project.hook(
        callee.address + 11,
        Sm83SwapRegister("a", callee.address + 13),
        length=2,
    )
    project.hook(
        callee.address + 13,
        Sm83AddRegister("b", callee.address + 14),
        length=1,
    )
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.memory.store(SPRITE_DATA_OFFSET, values["sprite_data_offset"])
    state.memory.store(SPRITE_INDEX, values["sprite_index"])
    state.memory.store(SPRITE_FACING_DIRECTION, values["facing_direction"])
    state.memory.store(SPRITE_STATE_DATA1, values["sprite_data"])
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
    function = project.loader.find_symbol("port_set_sprite_facing_direction")
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(
        NATIVE_MEMORY + SPRITE_DATA_OFFSET, values["sprite_data_offset"]
    )
    state.memory.store(NATIVE_MEMORY + SPRITE_INDEX, values["sprite_index"])
    state.memory.store(
        NATIVE_MEMORY + SPRITE_FACING_DIRECTION, values["facing_direction"]
    )
    state.memory.store(NATIVE_MEMORY + SPRITE_STATE_DATA1, values["sprite_data"])
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
def test_set_sprite_facing_direction_pathwise_equivalence() -> None:
    values = symbolic_registers("set_sprite_facing_direction")
    values["sprite_data_offset"] = claripy.BVS("sprite_data_offset", 8)
    values["sprite_index"] = claripy.BVS("sprite_index", 8)
    values["facing_direction"] = claripy.BVS("facing_direction", 8)
    values["sprite_data"] = claripy.BVS("sprite_data", 256 * 8)
    assert_pathwise_equivalent(
        _assembly(values), _native(values), (*REGISTERS, "memory")
    )
