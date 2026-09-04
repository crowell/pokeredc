from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
    REGISTERS, assembly_registers, native_registers, set_assembly_registers,
    store_native_registers,
)
from verification.harness.rom import collect_returns, linked_bytes, rom_window, symbol_location

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xEFFF

W_PLAYER_Y_PIXELS = 0xC104
W_PLAYER_X_PIXELS = 0xC106
W_PLAYER_FACING = 0xC109
W_WHICH_OFFSETS = 0xCD50
W_SHADOW_OAM = 0xC300


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


class OffsetsBoundary(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.b = claripy.BVV(0x64, 8)
        self.state.regs.c = claripy.BVV(0x48, 8)
        self.state.regs.a = self.state.memory.load(W_PLAYER_FACING, 1)
        self.jump(self.next_address)


class WriteOAMBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        values = (0x64, 0x48, 0xFC, 0x10, 0x64, 0x50, 0xFD, 0x10,
                  0x6C, 0x48, 0xFE, 0x10, 0x6C, 0x50, 0xFF, 0x10)
        for index, value in enumerate(values):
            self.state.memory.store(W_SHADOW_OAM + 0x90 + index,
                                    claripy.BVV(value, 8))
        self.state.regs.a = claripy.BVV(0x10, 8)
        self.state.regs.f = claripy.BVV(0x10, 8)
        self.state.regs.b = claripy.BVV(0x6C, 8)
        self.state.regs.c = claripy.BVV(0x50, 8)
        self.state.regs.h = claripy.BVV(0xC3, 8)
        self.state.regs.l = claripy.BVV(0xA0, 8)
        self.state.regs.d = claripy.BVV(0x70, 8)
        self.state.regs.e = claripy.BVV(0x68, 8)
        self.jump(RETURN)


def _setup(state: angr.SimState, base: int) -> None:
    for address, value in ((W_PLAYER_Y_PIXELS, 0x30),
                           (W_PLAYER_X_PIXELS, 0x40),
                           (W_PLAYER_FACING, 0x00),
                           (W_WHICH_OFFSETS, 0x01)):
        state.memory.store(base + address, claripy.BVV(value, 8))
    state.memory.store(base + 0x7097, claripy.BVV(0x08, 8))
    state.memory.store(base + 0x7098, claripy.BVV(0x34, 8))
    for i in range(16):
        state.memory.store(base + W_SHADOW_OAM + 0x90 + i,
                           claripy.BVV((0x20 + i) & 0xff, 8))


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(*(state.memory.load(base + address, 1)
                            for address in (W_SHADOW_OAM + 0x90 + i
                                            for i in range(16))))


def _endpoint(state: angr.SimState, *, native: bool, base: int) -> Endpoint:
    return Endpoint(
        **(native_registers(state, NATIVE_STATE) if native else assembly_registers(state)),
        memory=_memory(state, base), constraints=tuple(state.solver.constraints),
    )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "WriteCutOrBoulderDustAnimationOAMBlock")
    offsets = symbol_location(SYMBOLS, "GetCutOrBoulderDustAnimationOffsets")
    assert linked_bytes(ROM, location, offsets.address - location.address) == bytes.fromhex(
        "cd68703e09116070c3973afc10fd10fe10ff10"
    )
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    q = location.address
    project.hook(q, OffsetsBoundary(q + 3), length=3)
    project.hook(q + 8, WriteOAMBoundary(), length=3)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    _setup(state, 0)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    return [_endpoint(end, native=False, base=0)
            for end in collect_returns(project, state, RETURN)]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol(
        "port_write_cut_or_boulder_dust_animation_oam_block"
    )
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, NATIVE_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and manager.deadended
    return [_endpoint(end, native=True, base=NATIVE_MEMORY)
            for end in manager.deadended]


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),
                    reason="build artifacts missing")
def test_write_cut_or_boulder_dust_animation_oam_block_pathwise_equivalence() -> None:
    values = {register: claripy.BVV((index * 19 + 5) & 0xff, 8)
              for index, register in enumerate(REGISTERS)}
    assert_pathwise_equivalent(_assembly(values), _native(values),
                               (*REGISTERS, "memory"))
