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
from verification.harness.rom import linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import (
    Sm83DecRegister,
    Sm83StoreAImmediate,
    Sm83XorA,
)
ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF
STACK = 0xD000
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


class CallBoundary(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.jump(self.next_address)


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
    project.hook(location.address, CallBoundary(location.address + 3), length=3)
    project.hook(location.address + 3, Sm83XorA(location.address + 4), length=1)
    project.hook(
        location.address + 4,
        Sm83StoreAImmediate(W_SUBANIM_SUBENTRY_ADDR, location.address + 7),
        length=3,
    )
    project.hook(
        location.address + 7,
        Sm83StoreAImmediate(W_UNUSED_MOVE_ANIM_BYTE, location.address + 10),
        length=3,
    )
    project.hook(
        location.address + 10, Sm83StoreAImmediate(W_SUBANIM_TRANSFORM, location.address + 13), length=3
    )
    project.hook(
        location.address + 13, Sm83DecRegister("a", location.address + 14), length=1
    )
    project.hook(
        location.address + 14,
        Sm83StoreAImmediate(W_ANIM_SOUND_ID, location.address + 17),
        length=3,
    )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    _store_memory(state, 0, values)
    state.regs.sp = STACK
    state.memory.store(
        STACK,
        claripy.Concat(state.regs.a, state.regs.f),
        endness="Iend_LE",
    )
    state.memory.store(
        STACK + 2,
        claripy.Concat(state.regs.b, state.regs.c),
        endness="Iend_LE",
    )
    state.memory.store(
        STACK + 4,
        claripy.Concat(state.regs.d, state.regs.e),
        endness="Iend_LE",
    )
    state.memory.store(
        STACK + 6,
        claripy.Concat(state.regs.h, state.regs.l),
        endness="Iend_LE",
    )
    state.memory.store(STACK + 8, claripy.BVV(DONE, 16), endness="Iend_LE")
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
    location = symbol_location(SYMBOLS, "MoveAnimation.animationFinished")
    assert linked_bytes(ROM, location, 24) == bytes.fromhex(
        "cd4837afea96d0ea9bd0ea8bd03dea07cff1c1d1e1c9f0f3"
    )
    assert_pathwise_equivalent(
        _assembly(values), _native(values), (*REGISTERS, "memory")
    )
