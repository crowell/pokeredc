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
from verification.harness.sm83_shims import (
    Sm83LoadAImmediate,
    Sm83SetAtHl,
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
S_GAME = 0xA598
S_GAME_END = 0xB523
S_CHECKSUM = 0xB523
W_PLAYER = 0xD158
W_MAIN = 0xD2F7
W_MAIN_END = 0xDA80
W_SPRITE = 0xC100
W_SPRITE_END = 0xC300
S_TILE_ANIMATIONS = 0xB522
H_TILE = 0xFFD7
W_BOX = 0xDA80
W_BOX_END = 0xDEE2
W_TILESET = 0xD367
R_RAMG = 0x0000
R_RAMB = 0x4000
R_BMODE = 0x6000
EXPECTED = bytes.fromhex(
    "3e0aea00003e01ea0060ea00402198a5018b0fcd56784ffa23b5b9ca"
    "52762198a5018b0fcd56784ffa23b5b9c2f7762198a51158d1010b00"
    "cdb50021a3a511f7d2018907cdb5002167d3cbfe212cad1100c1010002"
    "cdb500fa22b5e0d721c0b01180da016204cdb500a7c3f876"
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


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    return symbolic_registers(prefix)


def _pattern(address: int) -> int:
    return (address * 13 + 7) & 0xFF


def _setup(state: angr.SimState, base: int, bad: bool = False) -> None:
    total = 0
    for address in range(S_GAME, S_GAME_END):
        value = _pattern(address)
        total = (total + value) & 0xFF
        state.memory.store(base + address, claripy.BVV(value, 8))
    checksum = (~total) & 0xFF
    if bad:
        checksum ^= 1
    state.memory.store(base + S_CHECKSUM, claripy.BVV(checksum, 8))
    for start, end in (
        (W_PLAYER, W_PLAYER + 11),
        (W_MAIN, W_MAIN_END),
        (W_SPRITE, W_SPRITE_END),
        (H_TILE, H_TILE + 1),
        (W_BOX, W_BOX_END),
        (W_TILESET, W_TILESET + 1),
    ):
        for address in range(start, end):
            state.memory.store(base + address, claripy.BVV(_pattern(address + 0x31), 8))


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        state.memory.load(base + R_RAMG, 1),
        state.memory.load(base + R_RAMB, 1),
        state.memory.load(base + R_BMODE, 1),
        state.memory.load(base + S_CHECKSUM, 1),
        state.memory.load(base + W_PLAYER, 11),
        state.memory.load(base + W_MAIN, W_MAIN_END - W_MAIN),
        state.memory.load(base + W_SPRITE, W_SPRITE_END - W_SPRITE),
        state.memory.load(base + H_TILE, 1),
        state.memory.load(base + W_BOX, W_BOX_END - W_BOX),
        state.memory.load(base + W_TILESET, 1),
    )


class Skip(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__(); self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.jump(self.next_address)


class CalcBoundary(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__(); self.next_address = next_address

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
        self.state.regs.f = sm83_flags_to_z80(
            claripy.BVV(0x60, 8) |
            claripy.If(value == 0, claripy.BVV(0x80, 8), claripy.BVV(0, 8))
        )
        self.jump(self.next_address)


class BranchChecksum(angr.SimProcedure):
    def __init__(self, matched: int, retry: int, invert: bool) -> None:
        super().__init__(); self.matched = matched; self.retry = retry; self.invert = invert

    def run(self) -> None:  # type: ignore[override]
        z = ((self.state.regs.f >> 6) & 1) == 1
        if self.invert:
            z = claripy.Not(z)
        ts = self.state.copy(); fs = self.state.copy()
        ts.solver.add(z); fs.solver.add(claripy.Not(z))
        self.inhibit_autoret = True
        self.successors.add_successor(ts, self.matched, z, "Ijk_Boring")
        self.successors.add_successor(fs, self.retry, claripy.Not(z), "Ijk_Boring")


class CopyBoundary(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__(); self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        hl = (self.state.solver.eval(self.state.regs.h) << 8) | self.state.solver.eval(self.state.regs.l)
        de = (self.state.solver.eval(self.state.regs.d) << 8) | self.state.solver.eval(self.state.regs.e)
        count = (self.state.solver.eval(self.state.regs.b) << 8) | self.state.solver.eval(self.state.regs.c)
        last = claripy.BVV(0, 8)
        for i in range(count):
            last = self.state.memory.load((hl + i) & 0xFFFF, 1)
            self.state.memory.store((de + i) & 0xFFFF, last)
        end_hl = (hl + count) & 0xFFFF; end_de = (de + count) & 0xFFFF
        self.state.regs.h = claripy.BVV(end_hl >> 8, 8); self.state.regs.l = claripy.BVV(end_hl & 0xFF, 8)
        self.state.regs.d = claripy.BVV(end_de >> 8, 8); self.state.regs.e = claripy.BVV(end_de & 0xFF, 8)
        self.state.regs.b = claripy.BVV(0, 8); self.state.regs.c = claripy.BVV(0, 8)
        self.state.regs.a = last; self.state.regs.f = claripy.BVV(0x40, 8)
        self.jump(self.next_address)


class NativeCalcBoundary(angr.SimProcedure):
    """Native-ABI summary for the already-proven CalcCheckSum port."""

    def run(
        self, register_address: claripy.ast.BV, memory_address: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        total: claripy.ast.BV | int = 0
        for offset in range(S_GAME_END - S_GAME):
            total = (total + self.state.memory.load(memory_address + offset, 1)) & 0xFF
        value = (~total) & 0xFF
        old_f = self.state.memory.load(register_address + 1, 1)
        self.state.memory.store(register_address + 0, value)
        self.state.memory.store(register_address + 2, claripy.BVV(0, 8))
        self.state.memory.store(register_address + 3, claripy.BVV(0, 8))
        self.state.memory.store(register_address + 4, total)
        self.state.memory.store(register_address + 6, claripy.BVV(S_GAME_END >> 8, 8))
        self.state.memory.store(register_address + 7, claripy.BVV(S_GAME_END & 0xFF, 8))
        self.state.memory.store(
            register_address + 1,
            claripy.BVV(0x60, 8)
            | (old_f & claripy.BVV(0x10, 8))
            | claripy.If(value == 0, claripy.BVV(0x80, 8), claripy.BVV(0, 8)),
        )


class NativeCopyBoundary(angr.SimProcedure):
    """Native-ABI summary for the already-proven CopyData port."""

    def run(
        self, register_address: claripy.ast.BV, memory_address: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        regs = {
            name: self.state.solver.eval(self.state.memory.load(register_address + i, 1))
            for i, name in enumerate(REGISTERS)
        }
        hl = (regs["h"] << 8) | regs["l"]
        de = (regs["d"] << 8) | regs["e"]
        count = (regs["b"] << 8) | regs["c"]
        last: claripy.ast.BV = claripy.BVV(0, 8)
        for offset in range(count):
            last = self.state.memory.load(memory_address + ((hl + offset) & 0xFFFF), 1)
            self.state.memory.store(memory_address + ((de + offset) & 0xFFFF), last)
        end_hl = (hl + count) & 0xFFFF
        end_de = (de + count) & 0xFFFF
        updates = {
            "a": last,
            "f": claripy.BVV(0x80, 8),
            "b": claripy.BVV(0, 8),
            "c": claripy.BVV(0, 8),
            "d": claripy.BVV(end_de >> 8, 8),
            "e": claripy.BVV(end_de & 0xFF, 8),
            "h": claripy.BVV(end_hl >> 8, 8),
            "l": claripy.BVV(end_hl & 0xFF, 8),
        }
        for offset, name in enumerate(REGISTERS):
            self.state.memory.store(register_address + offset, updates[name])


class GoodSummary(angr.SimProcedure):
    def run(self) -> None:
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.memory.store(R_BMODE, claripy.BVV(0, 8))
        self.state.memory.store(R_RAMG, claripy.BVV(0, 8))
        self.jump(DONE)


class FailSummary(angr.SimProcedure):
    def run(self) -> None:
        # The preceding CP is a known mismatch on this path; SCF then leaves
        # only carry set before GoodCheckSum writes the bank controls.
        self.state.regs.f = claripy.BVV(0x01, 8)
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.memory.store(R_BMODE, claripy.BVV(0, 8))
        self.state.memory.store(R_RAMG, claripy.BVV(0, 8))
        self.jump(DONE)


def _assembly(values: dict[str, claripy.ast.BV], bad: bool) -> list[Endpoint]:
    loc = symbol_location(SYMBOLS, "LoadMainData")
    nxt = symbol_location(SYMBOLS, "LoadCurrentBoxData")
    failed = symbol_location(SYMBOLS, "CheckSumFailed")
    assert linked_bytes(ROM, loc, nxt.address - loc.address) == EXPECTED
    p = angr.Project(rom_window(ROM, loc.bank), auto_load_libs=False, rebase_granularity=0x100,
                     main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                                "base_addr": 0, "entry_point": loc.address})
    b = loc.address
    for off, address, nxt_off in ((2, R_RAMG, 5), (7, R_BMODE, 10), (10, R_RAMB, 13)):
        p.hook(b + off, Sm83StoreAImmediate(address, b + nxt_off), length=3)
    p.hook(b + 0x13, CalcBoundary(b + 0x16), length=3)
    p.hook(b + 0x17, Sm83LoadAImmediate(S_CHECKSUM, b + 0x1A), length=3)
    p.hook(b + 0x1B, BranchChecksum(b + 0x2F, b + 0x1E, False), length=3)
    p.hook(b + 0x24, CalcBoundary(b + 0x27), length=3)
    p.hook(b + 0x28, Sm83LoadAImmediate(S_CHECKSUM, b + 0x2B), length=3)
    p.hook(b + 0x2C, BranchChecksum(failed.address, b + 0x2F, True), length=3)
    for off, nxt_off in ((0x38, 0x3B), (0x44, 0x47), (0x55, 0x58), (0x66, 0x69)):
        p.hook(b + off, CopyBoundary(b + nxt_off), length=3)
    p.hook(b + 0x4A, Sm83SetAtHl(7, b + 0x4C), length=2)
    p.hook(b + 0x58, Sm83LoadAImmediate(S_TILE_ANIMATIONS, b + 0x5B), length=3)
    p.hook(b + 0x5B, Sm83StoreAHighImmediate(0xD7, b + 0x5D), length=2)
    p.hook(b + 0x6A, GoodSummary(), length=3)
    p.hook(failed.address, FailSummary(), length=1)
    s = p.factory.blank_state(addr=b); set_assembly_registers(s, values); _setup(s, 0, bad)
    m = p.factory.simulation_manager(s); m.explore(find=DONE, num_find=4)
    assert not m.errored and len(m.found) == 1
    return [Endpoint(**assembly_registers(x), memory=_memory(x, 0), constraints=tuple(x.solver.constraints)) for x in m.found]


def _native(values: dict[str, claripy.ast.BV], bad: bool) -> list[Endpoint]:
    p = angr.Project(ELF, auto_load_libs=False); f = p.loader.find_symbol("port_load_main_data"); assert f is not None
    calc = p.loader.find_symbol("port_calc_checksum")
    copy = p.loader.find_symbol("port_copy_data")
    assert calc is not None and copy is not None
    p.hook(calc.rebased_addr, NativeCalcBoundary())
    p.hook(copy.rebased_addr, NativeCopyBoundary())
    s = p.factory.call_state(f.rebased_addr, NATIVE_STATE, NATIVE_MEMORY); store_native_registers(s, NATIVE_STATE, values); _setup(s, NATIVE_MEMORY, bad)
    m = p.factory.simulation_manager(s); m.run(); assert not m.errored and len(m.deadended) == 1
    return [Endpoint(**native_registers(x, NATIVE_STATE), memory=_memory(x, NATIVE_MEMORY), constraints=tuple(x.solver.constraints)) for x in m.deadended]


@pytest.mark.parametrize("bad", [False, True], ids=["checksum-match", "checksum-fail"])
@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_load_main_data_pathwise_equivalence(bad: bool) -> None:
    values = _inputs(f"load_main_data_{bad}")
    assert_pathwise_equivalent(_assembly(values, bad), _native(values, bad), (*REGISTERS, "memory"))
