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
from verification.harness.rom import rom_window, symbol_location

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF
W_ANIM_SOUND_ID = 0xCF07
W_SUBANIM_TRANSFORM = 0xD08B
W_SUBANIM_SUBENTRY_ADDR = 0xD096
W_UNUSED_MOVE_ANIM_BYTE = 0xD09B
FIELDS = (
    "subentry_low",
    "subentry_high",
    "unused_move_byte",
    "transform",
    "anim_sound",
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
    memory: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class FinishSummary(angr.SimProcedure):
    def run(self) -> None:
        self.state.memory.store(W_SUBANIM_SUBENTRY_ADDR, claripy.BVV(0, 8))
        self.state.memory.store(W_UNUSED_MOVE_ANIM_BYTE, claripy.BVV(0, 8))
        self.state.memory.store(W_SUBANIM_TRANSFORM, claripy.BVV(0, 8))
        self.state.memory.store(W_ANIM_SOUND_ID, claripy.BVV(0xFF, 8))
        self.jump(DONE)


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for field in FIELDS:
        values[field] = claripy.BVS(f"{prefix}_{field}", 8)
    return values


def _store_memory(state: angr.SimState, base: int, values: dict[str, claripy.ast.BV]) -> None:
    state.memory.store(base + W_SUBANIM_SUBENTRY_ADDR, values["subentry_low"])
    state.memory.store(base + W_SUBANIM_SUBENTRY_ADDR + 1, values["subentry_high"])
    state.memory.store(base + W_UNUSED_MOVE_ANIM_BYTE, values["unused_move_byte"])
    state.memory.store(base + W_SUBANIM_TRANSFORM, values["transform"])
    state.memory.store(base + W_ANIM_SOUND_ID, values["anim_sound"])


def _memory_endpoint(state: angr.SimState, base: int) -> claripy.ast.BV:
    addresses = (
        W_SUBANIM_SUBENTRY_ADDR,
        W_SUBANIM_SUBENTRY_ADDR + 1,
        W_UNUSED_MOVE_ANIM_BYTE,
        W_SUBANIM_TRANSFORM,
        W_ANIM_SOUND_ID,
    )
    return claripy.Concat(*(state.memory.load(base + address, 1) for address in addresses))


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "MoveAnimation.animationFinished")
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
    project.hook(location.address, FinishSummary(), length=1)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    _store_memory(state, 0, values)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored
    return [
        Endpoint(**assembly_registers(end), memory=_memory_endpoint(end, 0), constraints=tuple(end.solver.constraints))
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_move_animation_finished")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _store_memory(state, NATIVE_MEMORY, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=_memory_endpoint(end, NATIVE_MEMORY),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_move_animation_finished_pathwise_equivalence() -> None:
    values = _inputs("move_animation_finished")
    assert_pathwise_equivalent(_assembly(values), _native(values), (*REGISTERS, "memory"))
