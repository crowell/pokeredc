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

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
DONE = 0xEFFF


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
    memory: claripy.ast.BV
    result: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class SrlE(angr.SimProcedure):
    def __init__(self, n: int) -> None:
        super().__init__()
        self._n = n

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        e = self.state.regs.e
        self.state.globals["carry"] = e & 0x1
        e_out = claripy.LShR(e, 1)
        self.state.globals["e_out"] = e_out
        self.state.regs.e = e_out
        self.jump(self._n)
class LdA0(angr.SimProcedure):
    def __init__(self, n: int) -> None:
        super().__init__()
        self._n = n

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.state.regs.a = claripy.BVV(0, 8)
        self.jump(self._n)



class AdcC(angr.SimProcedure):
    def __init__(self, n: int) -> None:
        super().__init__()
        self._n = n

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        c = self.state.regs.c
        carry = self.state.globals["carry"]
        wide = claripy.ZeroExt(1, c) + claripy.ZeroExt(1, carry)
        a = wide[7:0]
        self.state.regs.a = a
        z = a == 0
        h = (claripy.ZeroExt(4, c & 0xF) + claripy.ZeroExt(4, carry))[4]
        # shim-Z80 layout: Z@bit6, N@bit1=0, H@bit4, C@bit0.
        self.state.regs.f = claripy.Concat(
            claripy.BVV(0, 1), z, claripy.BVV(0, 1), h,
            claripy.BVV(0, 2), claripy.BVV(0, 1), wide[8],
        )
        self.jump(self._n)


class LdC(angr.SimProcedure):
    def __init__(self, n: int) -> None:
        super().__init__()
        self._n = n

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.state.regs.c = self.state.regs.a
        self.jump(self._n)


class DecD(angr.SimProcedure):
    def __init__(self, done: int) -> None:
        super().__init__()
        self._done = done

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        f_adc = self.state.regs.f
        # regs.f is shim-Z80 (C@bit0, N@bit1, H@bit4, Z@bit6).
        incoming_c = (f_adc & 0x01) == 0x01
        d = self.state.regs.d
        d_new = d - 1
        z = d_new == 0
        h = (d & 0xF) == 0
        self.state.regs.d = d_new
        # shim-Z80: Z@bit6, N@bit1, H@bit4, C@bit0.
        self.state.regs.f = claripy.Concat(
            claripy.BVV(0, 1), z, claripy.BVV(0, 1), h,
            claripy.BVV(0, 2), claripy.BVV(1, 1), incoming_c,
        )
        self.state.globals["result"] = claripy.If(z, claripy.BVV(1, 8), claripy.BVV(0, 8))
        self.jump(self._done)


def inputs(tag: str) -> dict:
    return symbolic_registers(tag)


def assembly(i: dict) -> list[E]:
    loc = symbol_location(SYMBOLS, "CountSetBits")
    # Inner loop starts at .loop + 4 (srl e).
    q = symbol_location(SYMBOLS, "CountSetBits.loop").address + 4
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
    # `cb 3b` (srl e) and `3e 00` (ld a,0) are two-byte instructions.
    p.hook(q, SrlE(q + 2), length=2)          # srl e
    p.hook(q + 2, LdA0(q + 4), length=2)      # ld a, 0
    p.hook(q + 4, AdcC(q + 5), length=1)      # adc c
    p.hook(q + 5, LdC(q + 6), length=1)       # ld c, a
    p.hook(q + 6, DecD(DONE), length=1)       # dec d
    s = p.factory.blank_state(addr=q)
    set_assembly_registers(s, i)
    m = p.factory.simulation_manager(s)
    m.explore(find=DONE)
    assert len(m.found) == 1
    x = m.found[0]
    vals = assembly_registers(x)
    # The Pcode register file reads `e` from the `de` varnode, not the `e`
    # sub-register the step wrote, so use the shifted value captured in SrlE.
    vals["e"] = x.globals["e_out"]
    return [
        E(
            **vals,
            memory=x.globals["e_out"],
            result=x.globals["result"],
            constraints=tuple(x.solver.constraints),
        )
    ]


def native(i: dict) -> list[E]:
    p = angr.Project(NATIVE_ELF, auto_load_libs=False)
    fn = p.loader.find_symbol("port_count_set_bits_inner_step")
    assert fn is not None
    s = p.factory.call_state(fn.rebased_addr, NATIVE_STATE)
    store_native_registers(s, NATIVE_STATE, i)
    m = p.factory.simulation_manager(s)
    m.run()
    assert not m.errored
    return [
        E(
            **native_registers(x, NATIVE_STATE),
            memory=x.memory.load(NATIVE_STATE + 5, 1),
            result=x.regs.rax[7:0],
            constraints=tuple(x.solver.constraints),
        )
        for x in m.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_transition_equivalence() -> None:
    i = inputs("csb")
    assert_pathwise_equivalent(assembly(i), native(i), (*REGISTERS, "memory", "result"))


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_exact_body() -> None:
    loc = symbol_location(SYMBOLS, "CountSetBits")
    assert linked_bytes(ROM, loc, 23) == bytes.fromhex(
        "0e002a5f1608cb3b3e00894f1520f70520f079ea1ed1c9"
    )
