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
from verification.harness.rom import linked_bytes, rom_window, sm83_flags_to_z80, symbol_location
from verification.harness.sm83_shims import Sm83LoadAImmediate, Sm83StoreAImmediate

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF
S_GAME = 0xA598
S_GAME_END = 0xB523
S_CHECKSUM = 0xB523
S_BOX = 0xB0C0
W_BOX = 0xDA80
W_BOX_END = 0xDEE2
R_RAMG = 0x0000
R_RAMB = 0x4000
R_BMODE = 0x6000


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


def _pattern(address: int) -> int:
    return (address * 13 + 7) & 0xFF


def _setup(state: angr.SimState, base: int, bad: bool) -> None:
    total = 0
    for address in range(S_GAME, S_GAME_END):
        value = _pattern(address)
        total = (total + value) & 0xFF
        state.memory.store(base + address, claripy.BVV(value, 8))
    checksum = (~total) & 0xFF
    if bad:
        checksum ^= 1
    state.memory.store(base + S_CHECKSUM, claripy.BVV(checksum, 8))
    for address in range(W_BOX, W_BOX_END):
        state.memory.store(base + address, claripy.BVV(_pattern(address + 0x31), 8))


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        state.memory.load(base + R_RAMG, 1),
        state.memory.load(base + R_RAMB, 1),
        state.memory.load(base + R_BMODE, 1),
        state.memory.load(base + S_CHECKSUM, 1),
        state.memory.load(base + W_BOX, W_BOX_END - W_BOX),
    )


class ChecksumBranch(angr.SimProcedure):
    def __init__(self, success: int, failure: int) -> None:
        super().__init__()
        self.success = success
        self.failure = failure

    def run(self) -> None:  # type: ignore[override]
        z = self.state.regs.a == self.state.regs.c
        self.inhibit_autoret = True
        matched = self.state.copy()
        failed = self.state.copy()
        matched.solver.add(z)
        failed.solver.add(claripy.Not(z))
        self.successors.add_successor(matched, self.success, z, "Ijk_Boring")
        self.successors.add_successor(failed, self.failure, claripy.Not(z), "Ijk_Boring")


class CalcBoundary(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        total = 0
        for address in range(S_GAME, S_GAME_END):
            total = (total + self.state.memory.load(address, 1)) & 0xFF
        value = (~total) & 0xFF
        self.state.regs.a = value
        self.state.regs.d = total
        self.state.regs.b = claripy.BVV(0, 8)
        self.state.regs.c = claripy.BVV(0, 8)
        self.state.regs.h = claripy.BVV(S_GAME_END >> 8, 8)
        self.state.regs.l = claripy.BVV(S_GAME_END & 0xFF, 8)
        self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0x60, 8))
        self.jump(self.next_address)


class CopyBoundary(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        hl = (self.state.solver.eval(self.state.regs.h) << 8) | self.state.solver.eval(self.state.regs.l)
        de = (self.state.solver.eval(self.state.regs.d) << 8) | self.state.solver.eval(self.state.regs.e)
        count = (self.state.solver.eval(self.state.regs.b) << 8) | self.state.solver.eval(self.state.regs.c)
        last = claripy.BVV(0, 8)
        for offset in range(count):
            last = self.state.memory.load((hl + offset) & 0xFFFF, 1)
            self.state.memory.store((de + offset) & 0xFFFF, last)
        end_hl = (hl + count) & 0xFFFF
        end_de = (de + count) & 0xFFFF
        self.state.regs.h = claripy.BVV(end_hl >> 8, 8)
        self.state.regs.l = claripy.BVV(end_hl & 0xFF, 8)
        self.state.regs.d = claripy.BVV(end_de >> 8, 8)
        self.state.regs.e = claripy.BVV(end_de & 0xFF, 8)
        self.state.regs.b = claripy.BVV(0, 8)
        self.state.regs.c = claripy.BVV(0, 8)
        self.state.regs.a = last
        self.state.regs.f = claripy.BVV(0x40, 8)
        self.jump(self.next_address)


class GoodSummary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        final_a = self.state.regs.a
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x10, 8) | claripy.If(
            final_a == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)
        )
        self.state.memory.store(R_BMODE, claripy.BVV(0, 8))
        self.state.memory.store(R_RAMG, claripy.BVV(0, 8))
        self.jump(DONE)


class FailSummary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x01, 8)
        self.state.memory.store(R_BMODE, claripy.BVV(0, 8))
        self.state.memory.store(R_RAMG, claripy.BVV(0, 8))
        self.jump(DONE)


class NativeCalcBoundary(angr.SimProcedure):
    def run(self, registers: claripy.ast.BV, memory: claripy.ast.BV) -> None:  # type: ignore[override]
        total: claripy.ast.BV | int = 0
        for offset in range(S_GAME_END - S_GAME):
            total = (total + self.state.memory.load(memory + offset, 1)) & 0xFF
        value = (~total) & 0xFF
        old_f = self.state.memory.load(registers + 1, 1)
        self.state.memory.store(registers + 0, value)
        self.state.memory.store(registers + 2, claripy.BVV(0, 8))
        self.state.memory.store(registers + 3, claripy.BVV(0, 8))
        self.state.memory.store(registers + 4, total)
        self.state.memory.store(registers + 6, claripy.BVV(S_GAME_END >> 8, 8))
        self.state.memory.store(registers + 7, claripy.BVV(S_GAME_END & 0xFF, 8))
        self.state.memory.store(registers + 1, claripy.BVV(0x60, 8) | (old_f & 0x10))


class NativeCopyBoundary(angr.SimProcedure):
    def run(self, registers: claripy.ast.BV, memory: claripy.ast.BV) -> None:  # type: ignore[override]
        values = {name: self.state.solver.eval(self.state.memory.load(registers + i, 1)) for i, name in enumerate(REGISTERS)}
        hl = (values["h"] << 8) | values["l"]
        de = (values["d"] << 8) | values["e"]
        count = (values["b"] << 8) | values["c"]
        last: claripy.ast.BV = claripy.BVV(0, 8)
        for offset in range(count):
            last = self.state.memory.load(memory + ((hl + offset) & 0xFFFF), 1)
            self.state.memory.store(memory + ((de + offset) & 0xFFFF), last)
        end_hl = (hl + count) & 0xFFFF
        end_de = (de + count) & 0xFFFF
        updates = (last, claripy.BVV(0x80, 8), claripy.BVV(0, 8), claripy.BVV(0, 8), claripy.BVV(end_de >> 8, 8), claripy.BVV(end_de & 0xFF, 8), claripy.BVV(end_hl >> 8, 8), claripy.BVV(end_hl & 0xFF, 8))
        for i, value in enumerate(updates):
            self.state.memory.store(registers + i, value)


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    return symbolic_registers(prefix)


def _assembly(values: dict[str, claripy.ast.BV], bad: bool) -> list[Endpoint]:
    loc = symbol_location(SYMBOLS, "LoadCurrentBoxData")
    failed = symbol_location(SYMBOLS, "CheckSumFailed")
    end = symbol_location(SYMBOLS, "LoadPartyAndDexData")
    expected = bytes.fromhex("3e0aea00003e01ea0060ea00402198a5018b0fcd56784ffa23b5b9204a21c0b01180da016204cdb500a7c3f876")
    assert linked_bytes(ROM, loc, end.address - loc.address) == expected
    p = angr.Project(rom_window(ROM, loc.bank), auto_load_libs=False, rebase_granularity=0x100, main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0, "entry_point": loc.address})
    b = loc.address
    for off, address, next_off in ((2, R_RAMG, 5), (7, R_BMODE, 10), (10, R_RAMB, 13)):
        p.hook(b + off, Sm83StoreAImmediate(address, b + next_off), length=3)
    p.hook(b + 0x13, CalcBoundary(b + 0x16), length=3)
    p.hook(b + 0x17, Sm83LoadAImmediate(S_CHECKSUM, b + 0x1A), length=3)
    p.hook(b + 0x1A, ChecksumBranch(b + 0x1D, failed.address), length=1)
    p.hook(b + 0x26, CopyBoundary(b + 0x29), length=3)
    p.hook(b + 0x29, GoodSummary(), length=3)
    p.hook(failed.address, FailSummary(), length=1)
    s = p.factory.blank_state(addr=b)
    set_assembly_registers(s, values)
    _setup(s, 0, bad)
    m = p.factory.simulation_manager(s)
    m.explore(find=DONE, num_find=2)
    assert not m.errored and len(m.found) == 1
    return [Endpoint(**assembly_registers(x), memory=_memory(x, 0), constraints=tuple(x.solver.constraints)) for x in m.found]


def _native(values: dict[str, claripy.ast.BV], bad: bool) -> list[Endpoint]:
    p = angr.Project(ELF, auto_load_libs=False)
    fn = p.loader.find_symbol("port_load_current_box_data")
    calc = p.loader.find_symbol("port_calc_checksum")
    copy = p.loader.find_symbol("port_copy_data")
    assert fn is not None and calc is not None and copy is not None
    p.hook(calc.rebased_addr, NativeCalcBoundary())
    p.hook(copy.rebased_addr, NativeCopyBoundary())
    s = p.factory.call_state(fn.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(s, NATIVE_STATE, values)
    _setup(s, NATIVE_MEMORY, bad)
    m = p.factory.simulation_manager(s)
    m.run()
    assert not m.errored and len(m.deadended) == 1
    return [Endpoint(**native_registers(x, NATIVE_STATE), memory=_memory(x, NATIVE_MEMORY), constraints=tuple(x.solver.constraints)) for x in m.deadended]


@pytest.mark.parametrize("bad", [False, True], ids=["checksum-match", "checksum-fail"])
@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_load_current_box_data_pathwise_equivalence(bad: bool) -> None:
    values = _inputs(f"load_current_box_data_{bad}")
    assert_pathwise_equivalent(_assembly(values, bad), _native(values, bad), (*REGISTERS, "memory"))
