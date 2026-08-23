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
    symbol_location,
)
from verification.harness.sm83_shims import (
    Sm83AddRegister,
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
SPRITE_DATA_OFFSET = 0xFF8B
SPRITE_INDEX = 0xFF8C
EXPECTED_BODY = bytes.fromhex("f08b47f08ccb37806fc9")


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


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["sprite_data_offset"] = claripy.BVS(
        f"{prefix}_sprite_data_offset", 8
    )
    values["sprite_index"] = claripy.BVS(f"{prefix}_sprite_index", 8)
    return values


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "_GetPointerWithinSpriteStateData")
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
        base,
        Sm83LoadAHighImmediate(0x8B, base + 2),
        length=2,
    )
    project.hook(
        base + 3,
        Sm83LoadAHighImmediate(0x8C, base + 5),
        length=2,
    )
    project.hook(base + 5, Sm83SwapRegister("a", base + 7), length=2)
    project.hook(base + 7, Sm83AddRegister("b", base + 8), length=1)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.memory.store(SPRITE_DATA_OFFSET, values["sprite_data_offset"])
    state.memory.store(SPRITE_INDEX, values["sprite_index"])
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    return [
        Endpoint(
            **assembly_registers(end),
            memory=claripy.Concat(
                end.memory.load(SPRITE_DATA_OFFSET, 1),
                end.memory.load(SPRITE_INDEX, 1),
            ),
            constraints=tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, RETURN)
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(
        "port_get_pointer_within_sprite_state_data"
    )
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(
        NATIVE_MEMORY + SPRITE_DATA_OFFSET, values["sprite_data_offset"]
    )
    state.memory.store(NATIVE_MEMORY + SPRITE_INDEX, values["sprite_index"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=claripy.Concat(
                end.memory.load(NATIVE_MEMORY + SPRITE_DATA_OFFSET, 1),
                end.memory.load(NATIVE_MEMORY + SPRITE_INDEX, 1),
            ),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_get_pointer_within_sprite_state_data_pathwise_equivalence() -> None:
    values = _inputs("get_pointer_within_sprite_state_data")
    assert_pathwise_equivalent(
        _assembly(values), _native(values), (*REGISTERS, "memory")
    )
