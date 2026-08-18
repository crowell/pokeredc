from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
    native_registers,
    set_assembly_registers,
    store_native_registers,
    symbolic_registers,
)
from verification.harness.rom import (
    linked_bytes,
    rom_window,
    symbol_location,
    z80_flags_to_sm83,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
DONE = 0xEFFF
MEM_BASE = 0x300000
MEM_SIZE = 0x10000
R_DIV = 0xFF04
H_RANDOM_ADD = 0xFFD3
H_RANDOM_SUB = 0xFFD4


@dataclass(frozen=True)
class E:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    h_random_add: claripy.ast.BV
    h_random_sub: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class Random(angr.SimProcedure):
    def __init__(self, n: int) -> None:
        super().__init__()
        self._n = n

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        # Model the whole Random (bank 0) wrapper, which calls the Random_
        # LCG at 0x7a8f (bank 4) via a bank-switch trampoline, then returns
        # the updated hRandomAdd in A.
        f_in = self.state.regs.f
        rdiv = self.state.memory.load(R_DIV, 1)
        hsub = self.state.memory.load(H_RANDOM_SUB, 1)
        ha = self.state.memory.load(H_RANDOM_ADD, 1)
        # Carry-in is the real (sm83) C flag; the Pcode register holds it in
        # z80 layout (bit 0), matching the native C flag at sm83 bit 4.
        c_in = (f_in & 0x01) != 0
        wide1 = (
            claripy.ZeroExt(1, ha)
            + claripy.ZeroExt(1, rdiv)
            + claripy.If(c_in, claripy.BVV(1, 9), claripy.BVV(0, 9))
        )
        ha_new = wide1[7:0]
        c1 = wide1[8] == 1
        wide2 = (
            claripy.ZeroExt(1, hsub)
            - claripy.ZeroExt(1, rdiv)
            - claripy.If(c1, claripy.BVV(1, 9), claripy.BVV(0, 9))
        )
        hsub_new = wide2[7:0]
        c2 = wide2[8] == 1
        z2 = hsub_new == 0
        h_half = (hsub & 0x0F) < ((rdiv & 0x0F) + claripy.If(c1, claripy.BVV(1, 8), claripy.BVV(0, 8)))
        # Final flags come from the sbc (block 2): N=1, plus Z/H/C.
        f_out = claripy.BVV(0x02, 8)
        f_out = f_out | claripy.If(z2, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        f_out = f_out | claripy.If(h_half, claripy.BVV(0x10, 8), claripy.BVV(0, 8))
        f_out = f_out | claripy.If(c2, claripy.BVV(0x01, 8), claripy.BVV(0, 8))
        self.state.regs.a = ha_new
        self.state.regs.f = f_out
        self.state.memory.store(H_RANDOM_ADD, ha_new)
        self.state.memory.store(H_RANDOM_SUB, hsub_new)
        self.jump(self._n)


def inputs(p: str) -> dict:
    i = symbolic_registers(p)
    i["rdiv"] = claripy.BVS(f"{p}_rdiv", 8)
    i["ha"] = claripy.BVS(f"{p}_ha", 8)
    i["hsub"] = claripy.BVS(f"{p}_hsub", 8)
    return i


def assembly(i: dict) -> list[E]:
    loc = symbol_location(SYMBOLS, "Random")
    q = loc.address
    p = angr.Project(
        rom_window(ROM, loc.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": q,
        },
    )
    p.hook(q, Random(DONE), length=17)
    s = p.factory.blank_state(addr=q)
    s.memory.store(R_DIV, i["rdiv"])
    s.memory.store(H_RANDOM_ADD, i["ha"])
    s.memory.store(H_RANDOM_SUB, i["hsub"])
    set_assembly_registers(s, i)
    m = p.factory.simulation_manager(s)
    m.explore(find=DONE, num_find=1)
    assert len(m.found) == 1
    x = m.found[0]
    return [
        E(
            a=x.regs.a,
            f=z80_flags_to_sm83(x.regs.f),
            b=x.regs.b,
            c=x.regs.c,
            d=x.regs.d,
            e=x.regs.e,
            h=x.regs.h,
            l=x.regs.l,
            h_random_add=x.memory.load(H_RANDOM_ADD, 1),
            h_random_sub=x.memory.load(H_RANDOM_SUB, 1),
            constraints=tuple(x.solver.constraints),
        )
    ]


def native(i: dict) -> list[E]:
    p = angr.Project(NATIVE_ELF, auto_load_libs=False)
    fn = p.loader.find_symbol("port_random_generate")
    assert fn
    s = p.factory.call_state(fn.rebased_addr, NATIVE_STATE, claripy.BVV(MEM_BASE, 64))
    store_native_registers(s, NATIVE_STATE, i)
    s.memory.store(MEM_BASE + R_DIV, i["rdiv"])
    s.memory.store(MEM_BASE + H_RANDOM_ADD, i["ha"])
    s.memory.store(MEM_BASE + H_RANDOM_SUB, i["hsub"])
    m = p.factory.simulation_manager(s)
    m.run()
    assert not m.errored
    x = m.deadended[0]
    nr = native_registers(x, NATIVE_STATE)
    return [
        E(
            a=nr["a"],
            f=nr["f"],
            b=nr["b"],
            c=nr["c"],
            d=nr["d"],
            e=nr["e"],
            h=nr["h"],
            l=nr["l"],
            h_random_add=x.memory.load(MEM_BASE + H_RANDOM_ADD, 1),
            h_random_sub=x.memory.load(MEM_BASE + H_RANDOM_SUB, 1),
            constraints=tuple(x.solver.constraints),
        )
    ]


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native")
def test_transition_equivalence() -> None:
    i = inputs("random")
    assert_pathwise_equivalent(assembly(i), native(i), ("a", "b", "c", "d", "e", "h", "l", "h_random_add", "h_random_sub"))


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_exact_body() -> None:
    loc = symbol_location(SYMBOLS, "Random")
    assert linked_bytes(ROM, loc, 17) == bytes.fromhex("e5d5c50604218f7acdd635f0d3c1d1e1c9")
