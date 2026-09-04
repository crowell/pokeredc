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
from verification.harness.rom import linked_bytes, rom_window, sm83_flags_to_z80, symbol_location
from verification.harness.sm83_shims import Sm83BitRegister, Sm83LoadAImmediate

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xEFFF

W_Y = 0xD361
W_X = 0xD362
W_MOVEMENT = 0xD736
W_TILESET = 0xD367
W_TILE_FRONT = 0xCFC6
W_STANDING = 0xC45C
W_FACING = 0xC109
W_TILEMAP = 0xC3A0
TABLE = 0x9000


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


def _return_from_call(procedure: angr.SimProcedure) -> None:
    target = procedure.state.memory.load(procedure.state.regs.sp, 2, endness="Iend_LE")
    procedure.state.regs.sp += 2
    procedure.jump(target)


class GetTileBoundary(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__()
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        m = self.state.memory
        front = m.load(W_TILEMAP + 8 + 11 * 20, 1)
        self.state.regs.a = front
        self.state.regs.c = front
        self.state.regs.d = claripy.BVV(11, 8)
        self.state.regs.e = claripy.BVV(10, 8)
        m.store(W_TILE_FRONT, front)
        self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0, 8))
        self.jump(self.target)


class HandleLedgesBoundary(angr.SimProcedure):
    """Complete non-matching/early-return HandleLedges transition."""

    def __init__(self, target: int) -> None:
        super().__init__()
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        m = self.state.memory
        movement = m.load(W_MOVEMENT, 1)
        tileset = m.load(W_TILESET, 1)
        if self.state.solver.eval(movement & 0x40) != 0:
            self.state.regs.a = movement
        elif self.state.solver.eval(tileset) != 0:
            self.state.regs.a = tileset
        else:
            # The concrete proof cases use a non-matching front tile; the
            # proven HandleLedges table therefore terminates at $66f0.
            self.state.regs.a = claripy.BVV(0xFF, 8)
            self.state.regs.hl = claripy.BVV(0x66F0, 16)
        self.jump(self.target)


class PopPair(angr.SimProcedure):
    def __init__(self, high: str, low: str, target: int) -> None:
        super().__init__()
        self.high = high
        self.low = low
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        value = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp += 2
        setattr(self.state.regs, self.high, value[15:8])
        setattr(self.state.regs, self.low, value[7:0])
        self.jump(self.target)


class TilePairBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        m = self.state.memory
        pointer = self.state.solver.eval(self.state.regs.hl)
        front = self.state.solver.eval(m.load(W_TILE_FRONT, 1))
        tileset = self.state.solver.eval(m.load(W_TILESET, 1))
        standing = self.state.solver.eval(m.load(W_TILEMAP + 9 * 20 + 8, 1))
        m.store(W_STANDING, claripy.BVV(standing, 8))
        self.state.regs.a = claripy.BVV(front, 8)
        self.state.regs.c = claripy.BVV(front, 8)
        found = False
        while True:
            entry = self.state.solver.eval(m.load(pointer, 1))
            pointer = (pointer + 1) & 0xFFFF
            if entry == 0xFF:
                self.state.regs.a = claripy.BVV(0xFF, 8)
                self.state.regs.b = claripy.BVV(tileset, 8)
                self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0x20, 8))
                break
            first = self.state.solver.eval(m.load(pointer, 1))
            second = self.state.solver.eval(m.load((pointer + 1) & 0xFFFF, 1))
            if entry != tileset:
                pointer = (pointer + 2) & 0xFFFF
                continue
            if (standing == first and front == second) or (standing == second and front == first):
                pointer = (pointer + 1) & 0xFFFF
                self.state.regs.b = claripy.BVV(standing, 8)
                self.state.regs.a = claripy.BVV(front, 8)
                self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0x90, 8))
                found = True
                break
            pointer = (pointer + 1) & 0xFFFF
        self.state.regs.hl = claripy.BVV(pointer, 16)
        _return_from_call(self)


def _setup(state: angr.SimState, base: int, *, movement: int, tileset: int,
           standing: int, front: int, records: tuple[int, ...]) -> None:
    for address, value in ((W_MOVEMENT, movement), (W_TILESET, tileset),
                           (W_FACING, 0), (W_Y, 10), (W_X, 10),
                           (W_TILEMAP + 9 * 20 + 8, standing),
                           (W_TILEMAP + 8 + 11 * 20, front)):
        state.memory.store(base + address, claripy.BVV(value, 8))
    for index in range(8):
        value = records[index] if index < len(records) else 0
        state.memory.store(base + TABLE + index, claripy.BVV(value, 8))


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(*(state.memory.load(base + address, 1) for address in (
        W_MOVEMENT, W_TILESET, W_TILE_FRONT, W_STANDING,
        W_TILEMAP + 9 * 20 + 8, TABLE, TABLE + 1, TABLE + 2,
        TABLE + 3, TABLE + 4, TABLE + 5,
    )))


def _endpoint(state: angr.SimState, *, native: bool, base: int) -> Endpoint:
    return Endpoint(
        **(native_registers(state, NATIVE_STATE) if native else assembly_registers(state)),
        memory=_memory(state, base), constraints=tuple(state.solver.constraints)
    )


def _assembly(values: dict[str, claripy.ast.BV], **case: int) -> list[Endpoint]:
    loc = symbol_location(SYMBOLS, "CheckForJumpingAndTilePairCollisions")
    next_symbol = symbol_location(SYMBOLS, "CheckForTilePairCollisions2")
    body = linked_bytes(ROM, loc, next_symbol.address - loc.address)
    assert body == bytes.fromhex(
        "e53e35cd6d3ed5c50606217266cdd635c1d1e1a7fa36d7cb77c0"
    )
    project = angr.Project(rom_window(ROM, loc.bank), auto_load_libs=False,
                           rebase_granularity=0x100,
                           main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                                      "base_addr": 0, "entry_point": loc.address})
    q = loc.address
    project.hook(q + 3, GetTileBoundary(q + 6), length=3)
    project.hook(q + 0xD, HandleLedgesBoundary(q + 0x10), length=3)
    project.hook(q + 0x14, Sm83LoadAImmediate(W_MOVEMENT, q + 0x17), length=3)
    project.hook(q + 0x17, Sm83BitRegister(6, "a", q + 0x19), length=2)
    project.hook(q + 0x10, PopPair("b", "c", q + 0x11), length=1)
    project.hook(q + 0x11, PopPair("d", "e", q + 0x12), length=1)
    project.hook(q + 0x12, PopPair("h", "l", q + 0x13), length=1)
    project.hook(q + 0x1A, TilePairBoundary(), length=1)
    state = project.factory.blank_state(addr=loc.address)
    set_assembly_registers(state, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    _setup(state, 0, **case)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN, num_find=8)
    assert not manager.errored and manager.found
    return [_endpoint(end, native=False, base=0) for end in manager.found]


def _native(values: dict[str, claripy.ast.BV], **case: int) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_check_for_jumping_and_tile_pair_collisions")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, NATIVE_MEMORY, **case)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and manager.deadended
    return [_endpoint(end, native=True, base=NATIVE_MEMORY) for end in manager.deadended]


CASES = (
    dict(movement=0, tileset=0, standing=0x11, front=0x22,
         records=(0, 0x11, 0x22, 0xFF)),
    dict(movement=0, tileset=0, standing=0x11, front=0x33,
         records=(1, 0x11, 0x22, 0xFF)),
    dict(movement=0x40, tileset=0, standing=0x11, front=0x22,
         records=(0, 0x11, 0x22, 0xFF)),
    dict(movement=0, tileset=1, standing=0x11, front=0x22,
         records=(0, 0x11, 0x22, 0xFF)),
)


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),
                    reason="build artifacts missing")
@pytest.mark.parametrize("case", CASES)
def test_check_for_jumping_and_tile_pair_collisions_pathwise_equivalence(case: dict[str, object]) -> None:
    values = {register: claripy.BVV(0, 8) for register in REGISTERS}
    values["h"] = claripy.BVV(TABLE >> 8, 8)
    values["l"] = claripy.BVV(TABLE & 0xFF, 8)
    assert_pathwise_equivalent(
        _assembly(values, **case), _native(values, **case),
        (*REGISTERS, "memory"),
    )


def test_exact_body() -> None:
    loc = symbol_location(SYMBOLS, "CheckForJumpingAndTilePairCollisions")
    nxt = symbol_location(SYMBOLS, "CheckForTilePairCollisions2")
    assert linked_bytes(ROM, loc, nxt.address - loc.address) == bytes.fromhex(
        "e53e35cd6d3ed5c50606217266cdd635c1d1e1a7fa36d7cb77c0"
    )
