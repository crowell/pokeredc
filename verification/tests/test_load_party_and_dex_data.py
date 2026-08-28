from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS, assembly_registers, native_registers, set_assembly_registers, store_native_registers, symbolic_registers
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
S_PARTY = 0xAF2C
W_PARTY = 0xD163
W_PARTY_END = 0xD2F7
S_MAIN = 0xA5A3
W_DEX = 0xD2F7
W_DEX_END = 0xD31D
R_RAMG = 0x0000
R_RAMB = 0x4000
R_BMODE = 0x6000


@dataclass(frozen=True)
class Endpoint:
    a: claripy.ast.BV; f: claripy.ast.BV; b: claripy.ast.BV; c: claripy.ast.BV
    d: claripy.ast.BV; e: claripy.ast.BV; h: claripy.ast.BV; l: claripy.ast.BV
    memory: claripy.ast.BV; constraints: tuple[claripy.ast.Bool, ...]


def _pattern(address: int) -> int:
    return (address * 13 + 7) & 0xFF


def _setup(state: angr.SimState, base: int, bad: bool) -> None:
    total = 0
    for address in range(S_GAME, S_GAME_END):
        value = _pattern(address); total = (total + value) & 0xFF
        state.memory.store(base + address, claripy.BVV(value, 8))
    checksum = (~total) & 0xFF
    if bad: checksum ^= 1
    state.memory.store(base + S_CHECKSUM, claripy.BVV(checksum, 8))
    for start, end in ((W_PARTY, W_PARTY_END), (W_DEX, W_DEX_END)):
        for address in range(start, end):
            state.memory.store(base + address, claripy.BVV(_pattern(address + 0x31), 8))


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        state.memory.load(base + R_RAMG, 1), state.memory.load(base + R_RAMB, 1),
        state.memory.load(base + R_BMODE, 1), state.memory.load(base + S_CHECKSUM, 1),
        state.memory.load(base + W_PARTY, W_PARTY_END - W_PARTY),
        state.memory.load(base + W_DEX, W_DEX_END - W_DEX),
    )


class Branch(angr.SimProcedure):
    def __init__(self, success: int, failure: int) -> None:
        super().__init__(); self.success = success; self.failure = failure
    def run(self) -> None:  # type: ignore[override]
        z = self.state.regs.a == self.state.regs.c
        self.inhibit_autoret = True
        good = self.state.copy(); bad = self.state.copy(); good.solver.add(z); bad.solver.add(claripy.Not(z))
        self.successors.add_successor(good, self.success, z, "Ijk_Boring")
        self.successors.add_successor(bad, self.failure, claripy.Not(z), "Ijk_Boring")


class Calc(angr.SimProcedure):
    def __init__(self, nxt: int) -> None: super().__init__(); self.nxt = nxt
    def run(self) -> None:  # type: ignore[override]
        total = 0
        for address in range(S_GAME, S_GAME_END): total = (total + self.state.memory.load(address, 1)) & 0xFF
        self.state.regs.a = (~total) & 0xFF; self.state.regs.d = total
        self.state.regs.b = claripy.BVV(0, 8); self.state.regs.c = claripy.BVV(0, 8)
        self.state.regs.h = claripy.BVV(S_GAME_END >> 8, 8); self.state.regs.l = claripy.BVV(S_GAME_END & 0xFF, 8)
        self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0x60, 8)); self.jump(self.nxt)


class Copy(angr.SimProcedure):
    def __init__(self, nxt: int) -> None: super().__init__(); self.nxt = nxt
    def run(self) -> None:  # type: ignore[override]
        hl = (self.state.solver.eval(self.state.regs.h) << 8) | self.state.solver.eval(self.state.regs.l)
        de = (self.state.solver.eval(self.state.regs.d) << 8) | self.state.solver.eval(self.state.regs.e)
        count = (self.state.solver.eval(self.state.regs.b) << 8) | self.state.solver.eval(self.state.regs.c); last = claripy.BVV(0, 8)
        for offset in range(count): last = self.state.memory.load((hl + offset) & 0xFFFF, 1); self.state.memory.store((de + offset) & 0xFFFF, last)
        hl = (hl + count) & 0xFFFF; de = (de + count) & 0xFFFF
        self.state.regs.h = hl >> 8; self.state.regs.l = hl & 0xFF; self.state.regs.d = de >> 8; self.state.regs.e = de & 0xFF
        self.state.regs.b = 0; self.state.regs.c = 0; self.state.regs.a = last; self.state.regs.f = claripy.BVV(0x40, 8); self.jump(self.nxt)


class Finish(angr.SimProcedure):
    def __init__(self, failed: bool = False) -> None: super().__init__(); self.failed = failed
    def run(self) -> None:  # type: ignore[override]
        final_a = self.state.regs.a
        self.state.regs.a = claripy.BVV(0, 8); self.state.regs.f = claripy.BVV(1, 8) if self.failed else claripy.BVV(0x10, 8) | claripy.If(final_a == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        self.state.memory.store(R_BMODE, claripy.BVV(0, 8)); self.state.memory.store(R_RAMG, claripy.BVV(0, 8)); self.jump(DONE)


class NativeCalc(angr.SimProcedure):
    def run(self, registers: claripy.ast.BV, memory: claripy.ast.BV) -> None:  # type: ignore[override]
        total: claripy.ast.BV | int = 0
        for offset in range(S_GAME_END - S_GAME): total = (total + self.state.memory.load(memory + offset, 1)) & 0xFF
        old_f = self.state.memory.load(registers + 1, 1); self.state.memory.store(registers, (~total) & 0xFF)
        self.state.memory.store(registers + 1, claripy.BVV(0x60, 8) | (old_f & 0x10)); self.state.memory.store(registers + 2, claripy.BVV(0, 8)); self.state.memory.store(registers + 3, claripy.BVV(0, 8)); self.state.memory.store(registers + 4, total); self.state.memory.store(registers + 6, claripy.BVV(S_GAME_END >> 8, 8)); self.state.memory.store(registers + 7, claripy.BVV(S_GAME_END & 0xFF, 8))


class NativeCopy(angr.SimProcedure):
    def run(self, registers: claripy.ast.BV, memory: claripy.ast.BV) -> None:  # type: ignore[override]
        vals = {n: self.state.solver.eval(self.state.memory.load(registers + i, 1)) for i, n in enumerate(REGISTERS)}; hl = vals['h'] << 8 | vals['l']; de = vals['d'] << 8 | vals['e']; count = vals['b'] << 8 | vals['c']; last = claripy.BVV(0, 8)
        for offset in range(count): last = self.state.memory.load(memory + ((hl + offset) & 0xFFFF), 1); self.state.memory.store(memory + ((de + offset) & 0xFFFF), last)
        hl = (hl + count) & 0xFFFF; de = (de + count) & 0xFFFF; updates = (last, claripy.BVV(0x80, 8), claripy.BVV(0, 8), claripy.BVV(0, 8), claripy.BVV(de >> 8, 8), claripy.BVV(de & 0xFF, 8), claripy.BVV(hl >> 8, 8), claripy.BVV(hl & 0xFF, 8))
        for i, value in enumerate(updates): self.state.memory.store(registers + i, value)


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]: return symbolic_registers(prefix)


def _assembly(values: dict[str, claripy.ast.BV], bad: bool) -> list[Endpoint]:
    loc = symbol_location(SYMBOLS, "LoadPartyAndDexData"); failed = symbol_location(SYMBOLS, "CheckSumFailed")
    expected = bytes.fromhex("3e0aea00003e01ea0060ea00402198a5018b0fcd56784ffa23b5b9c2f776212caf1163d1019401cdb50021a3a511f7d2012600cdb500a7c3f876")
    assert linked_bytes(ROM, loc, failed.address - loc.address) == expected
    p = angr.Project(rom_window(ROM, loc.bank), auto_load_libs=False, rebase_granularity=0x100, main_opts={"backend":"blob", "arch":ArchPcode("z80:LE:16:default"), "base_addr":0, "entry_point":loc.address}); b = loc.address
    for off, address, nxt in ((2,R_RAMG,5),(7,R_BMODE,10),(10,R_RAMB,13)): p.hook(b+off, Sm83StoreAImmediate(address,b+nxt), length=3)
    p.hook(b+0x13, Calc(b+0x16), length=3); p.hook(b+0x17, Sm83LoadAImmediate(S_CHECKSUM,b+0x1A), length=3); p.hook(b+0x1B, Branch(b+0x1E,failed.address), length=3)
    p.hook(b+0x27, Copy(b+0x2A), length=3); p.hook(b+0x33, Copy(b+0x36), length=3); p.hook(b+0x36, Finish(), length=3); p.hook(failed.address, Finish(True), length=1)
    s=p.factory.blank_state(addr=b); set_assembly_registers(s,values); _setup(s,0,bad); m=p.factory.simulation_manager(s); m.explore(find=DONE,num_find=2); assert not m.errored and len(m.found)==1
    return [Endpoint(**assembly_registers(x),memory=_memory(x,0),constraints=tuple(x.solver.constraints)) for x in m.found]


def _native(values: dict[str, claripy.ast.BV], bad: bool) -> list[Endpoint]:
    p=angr.Project(ELF,auto_load_libs=False); fn=p.loader.find_symbol("port_load_party_and_dex_data"); calc=p.loader.find_symbol("port_calc_checksum"); copy=p.loader.find_symbol("port_copy_data"); assert fn and calc and copy
    p.hook(calc.rebased_addr,NativeCalc()); p.hook(copy.rebased_addr,NativeCopy()); s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE,NATIVE_MEMORY); store_native_registers(s,NATIVE_STATE,values); _setup(s,NATIVE_MEMORY,bad); m=p.factory.simulation_manager(s); m.run(); assert not m.errored and len(m.deadended)==1
    return [Endpoint(**native_registers(x,NATIVE_STATE),memory=_memory(x,NATIVE_MEMORY),constraints=tuple(x.solver.constraints)) for x in m.deadended]


@pytest.mark.parametrize("bad",[False,True],ids=["checksum-match","checksum-fail"])
@pytest.mark.skipif(not ELF.exists(),reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason="run `make red`")
def test_load_party_and_dex_data_pathwise_equivalence(bad: bool) -> None:
    values=_inputs(f"load_party_and_dex_data_{bad}"); assert_pathwise_equivalent(_assembly(values,bad),_native(values,bad),(*REGISTERS,"memory"))
