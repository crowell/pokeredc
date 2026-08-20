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
from verification.harness.rom import collect_returns, rom_window, symbol_location
from verification.harness.sm83_shims import Sm83CpImmediate, Sm83LoadAAtHlIncrement

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
DONE = 0xEFFF
COMMAND = 0xC500
ANIMATION_END = 0xFF


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
    values["command"] = claripy.BVS(f"{prefix}_command", 8)
    return values


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "PlayAnimation")
    loop = symbol_location(SYMBOLS, "PlayAnimation.animationLoop").address
    project = angr.Project(
        rom_window(ROM, location.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": loop,
        },
    )
    project.hook(loop, Sm83LoadAAtHlIncrement(loop + 1), length=1)
    project.hook(loop + 1, Sm83CpImmediate(ANIMATION_END, loop + 3), length=2)
    state = project.factory.blank_state(addr=loop)
    set_assembly_registers(state, values)
    state.regs.h = claripy.BVV(COMMAND >> 8, 8)
    state.regs.l = claripy.BVV(COMMAND & 0xFF, 8)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(DONE, 16), endness="Iend_LE")
    state.memory.store(COMMAND, claripy.BVV(ANIMATION_END, 8))
    manager = project.factory.simulation_manager(state)
    returned = collect_returns(project, state, DONE)
    return [
        Endpoint(
            **assembly_registers(end),
            memory=end.memory.load(COMMAND, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in returned
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_play_animation_over")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_MEMORY + COMMAND, claripy.BVV(ANIMATION_END, 8))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=end.memory.load(NATIVE_MEMORY + COMMAND, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_play_animation_animation_over_pathwise_equivalence() -> None:
    values = _inputs("play_animation_over")
    values["h"] = claripy.BVV(COMMAND >> 8, 8)
    values["l"] = claripy.BVV(COMMAND & 0xFF, 8)
    assert_pathwise_equivalent(_assembly(values), _native(values), (*REGISTERS, "memory"))
