"""Pathwise proof for CheckWarpsCollision's bounded warp scan."""

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
    linked_bytes,
    rom_window,
    sm83_flags_to_z80,
    symbol_location,
)
from verification.harness.sm83_shims import (
    Sm83CpRegister,
    Sm83DecRegister,
    Sm83LoadAAtHlIncrement,
    Sm83LoadAImmediate,
    Sm83StoreAHighImmediate,
    Sm83StoreAImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF
W_NUMBER_OF_WARPS = 0xD3AE
W_WARP_ENTRIES = 0xD3AF
W_Y_COORD = 0xD361
W_X_COORD = 0xD362
W_DESTINATION_WARP_ID = 0xD42F
H_WARP_DESTINATION_MAP = 0xFF8B
W_WARPED_FROM_WHICH_WARP = 0xD73B
W_WARPED_FROM_WHICH_MAP = 0xD73C
W_CUR_MAP = 0xD35E
EXPECTED = bytes.fromhex(
    "faaed34f21afd32a47fa61d3b820112a47fa62d3b8200a2aea2fd47ee08b18162323230d20e1c3ff03"
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


class LoadHLImmediate(angr.SimProcedure):
    def __init__(self, value: int, target: int) -> None:
        super().__init__()
        self._value = value
        self._target = target

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = claripy.BVV(self._value >> 8, 8)
        self.state.regs.l = claripy.BVV(self._value & 0xFF, 8)
        self.jump(self._target)


class LoadAAtHl(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__()
        self._target = target

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self.state.regs.hl, 1)
        self.jump(self._target)


class WarpFound2Boundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        state = self.state
        state.regs.a = state.memory.load(W_NUMBER_OF_WARPS, 1) - state.regs.c
        state.memory.store(W_WARPED_FROM_WHICH_WARP, state.regs.a)
        state.regs.a = state.memory.load(W_CUR_MAP, 1)
        state.memory.store(W_WARPED_FROM_WHICH_MAP, state.regs.a)
        state.regs.f = sm83_flags_to_z80(claripy.BVV(0x70, 8))
        self.jump(DONE)


def _store_map(state: angr.SimState, base: int, target: int) -> None:
    entries = (
        (0x20, 0x30, 0x41, 0x51),
        (0x21, 0x31, 0x42, 0x52),
        (0x22, 0x32, 0x43, 0x53),
    )
    for index, entry in enumerate(entries):
        values = entry if index == target else (
            (entry[0] + 0x10) & 0xFF,
            (entry[1] + 0x10) & 0xFF,
            entry[2],
            entry[3],
        )
        for offset, value in enumerate(values):
            state.memory.store(base + W_WARP_ENTRIES + index * 4 + offset, claripy.BVV(value, 8))
        if index == target:
            state.memory.store(base + W_Y_COORD, claripy.BVV(values[0], 8))
            state.memory.store(base + W_X_COORD, claripy.BVV(values[1], 8))
    state.memory.store(base + W_NUMBER_OF_WARPS, claripy.BVV(3, 8))
    state.memory.store(base + W_CUR_MAP, claripy.BVV(1, 8))


def _assembly(inputs: dict[str, claripy.ast.BV], target: int) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "CheckWarpsCollision")
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
    project.hook(base, Sm83LoadAImmediate(W_NUMBER_OF_WARPS, base + 3), length=3)
    project.hook(base + 4, LoadHLImmediate(W_WARP_ENTRIES, base + 7), length=3)
    project.hook(base + 7, Sm83LoadAAtHlIncrement(base + 8), length=1)
    project.hook(base + 9, Sm83LoadAImmediate(W_Y_COORD, base + 12), length=3)
    project.hook(base + 12, Sm83CpRegister("b", base + 13), length=1)
    project.hook(base + 15, Sm83LoadAAtHlIncrement(base + 16), length=1)
    project.hook(base + 17, Sm83LoadAImmediate(W_X_COORD, base + 20), length=3)
    project.hook(base + 20, Sm83CpRegister("b", base + 21), length=1)
    project.hook(base + 23, Sm83LoadAAtHlIncrement(base + 24), length=1)
    project.hook(base + 24, Sm83StoreAImmediate(W_DESTINATION_WARP_ID, base + 27), length=3)
    project.hook(base + 27, LoadAAtHl(base + 28), length=1)
    project.hook(base + 28, Sm83StoreAHighImmediate(0x8B, base + 30), length=2)
    project.hook(base + 35, Sm83DecRegister("c", base + 36), length=1)
    project.hook(symbol_location(SYMBOLS, "WarpFound2").address, WarpFound2Boundary(), length=1)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    _store_map(state, 0, target)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored
    return [
        Endpoint(
            **assembly_registers(end),
            memory=claripy.Concat(
                end.memory.load(W_DESTINATION_WARP_ID, 1),
                end.memory.load(H_WARP_DESTINATION_MAP, 1),
                end.memory.load(W_WARPED_FROM_WHICH_WARP, 1),
                end.memory.load(W_WARPED_FROM_WHICH_MAP, 1),
            ),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(inputs: dict[str, claripy.ast.BV], target: int) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_check_warps_collision")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, inputs)
    _store_map(state, NATIVE_MEMORY, target)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=claripy.Concat(
                end.memory.load(NATIVE_MEMORY + W_DESTINATION_WARP_ID, 1),
                end.memory.load(NATIVE_MEMORY + H_WARP_DESTINATION_MAP, 1),
                end.memory.load(NATIVE_MEMORY + W_WARPED_FROM_WHICH_WARP, 1),
                end.memory.load(NATIVE_MEMORY + W_WARPED_FROM_WHICH_MAP, 1),
            ),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
@pytest.mark.parametrize("target", (0, 1, 2))
def test_check_warps_collision_pathwise_equivalence(target: int) -> None:
    inputs = symbolic_registers(f"check_warps_collision_{target}")
    assert_pathwise_equivalent(
        _assembly(inputs, target),
        _native(inputs, target),
        (*REGISTERS, "memory"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_check_warps_collision_exact_body() -> None:
    location = symbol_location(SYMBOLS, "CheckWarpsCollision")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
