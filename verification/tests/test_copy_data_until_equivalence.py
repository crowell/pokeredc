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


class Fetch(angr.SimProcedure):
    def __init__(self, n: int) -> None:
        super().__init__()
        self._n = n

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.state.regs.a = self.state.globals["fetched"]
        self.state.regs.hl = self.state.regs.hl + 1
        self.jump(self._n)


class Store(angr.SimProcedure):
    def __init__(self, n: int) -> None:
        super().__init__()
        self._n = n

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.state.globals["written"] = self.state.regs.a
        self.jump(self._n)


class IncDe(angr.SimProcedure):
    def __init__(self, n: int) -> None:
        super().__init__()
        self._n = n

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.state.regs.de = self.state.regs.de + 1
        self.jump(self._n)


class Compare(angr.SimProcedure):
    """Models `ld a,h; cp b; jr nz; ld a,l; cp c; jr nz; ret`.

    The native port_copy_data_until_step runs copy_until_compare (a subtraction
    that sets N always, plus Z/H/C), with an early return when h != b. We pack
    the resulting native flags into the shim-Z80 F layout (Z=bit6, N=bit1,
    H=bit4, C=bit0), which assembly_registers converts to SM83 to match the
    native raw F. a ends up h (early return) or l, mirroring the C.
    """

    def __init__(self, done: int) -> None:
        super().__init__()
        self._done = done

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        h = self.state.regs.h
        l = self.state.regs.l
        b = self.state.regs.b
        c = self.state.regs.c

        def flags(left, right):
            z = left == right
            hh = (left & 0x0F) < (right & 0x0F)
            cc = left < right
            # shim-Z80 layout: Z@bit6, N@bit1, H@bit4, C@bit0 (N always set).
            return claripy.Concat(
                claripy.BVV(0, 1), z, claripy.BVV(0, 1), hh,
                claripy.BVV(0, 2), claripy.BVV(1, 1), cc,
            )

        f_hb = flags(h, b)       # `cp b` result
        f_lc = flags(l, c)       # `cp c` result
        h_eq_b = h == b
        done = claripy.And(h_eq_b, l == c)
        self.state.regs.a = claripy.If(h_eq_b, l, h)
        self.state.regs.f = claripy.If(h_eq_b, f_lc, f_hb)
        self.state.globals["result"] = claripy.If(done, claripy.BVV(1, 8), claripy.BVV(0, 8))
        self.jump(self._done)


def inputs(tag: str) -> dict:
    i = symbolic_registers(tag)
    i["fetched"] = claripy.BVS(f"{tag}_fetched", 8)
    i["written"] = claripy.BVS(f"{tag}_written", 8)
    return i


def assembly(i: dict) -> list[E]:
    loc = symbol_location(SYMBOLS, "CopyDataUntil")
    p = angr.Project(
        rom_window(ROM, loc.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": loc.address,
        },
    )
    q = loc.address
    p.hook(q, Fetch(q + 1), length=1)
    p.hook(q + 1, Store(q + 2), length=1)
    p.hook(q + 2, IncDe(q + 3), length=1)
    p.hook(q + 3, Compare(DONE), length=9)  # ld a,h; cp b; jr nz; ld a,l; cp c; jr nz; ret
    s = p.factory.blank_state(addr=q)
    set_assembly_registers(s, i)
    s.globals["fetched"] = i["fetched"]
    s.globals["written"] = i["written"]
    m = p.factory.simulation_manager(s)
    m.explore(find=DONE)
    assert len(m.found) == 1
    x = m.found[0]
    return [
        E(
            **assembly_registers(x),
            memory=claripy.Concat(x.globals["fetched"], x.globals["written"]),
            result=x.globals["result"],
            constraints=tuple(x.solver.constraints),
        )
    ]


def native(i: dict) -> list[E]:
    p = angr.Project(NATIVE_ELF, auto_load_libs=False)
    fn = p.loader.find_symbol("port_copy_data_until_step")
    assert fn is not None
    s = p.factory.call_state(fn.rebased_addr, NATIVE_STATE)
    store_native_registers(s, NATIVE_STATE, i)
    s.memory.store(NATIVE_STATE + 8, i["fetched"])
    s.memory.store(NATIVE_STATE + 9, i["written"])
    m = p.factory.simulation_manager(s)
    m.run()
    assert not m.errored
    return [
        E(
            **native_registers(x, NATIVE_STATE),
            memory=x.memory.load(NATIVE_STATE + 8, 2),
            result=x.regs.rax[7:0],
            constraints=tuple(x.solver.constraints),
        )
        for x in m.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_transition_equivalence() -> None:
    i = inputs("copy_data_until")
    assert_pathwise_equivalent(assembly(i), native(i), (*REGISTERS, "memory", "result"))


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_exact_body() -> None:
    loc = symbol_location(SYMBOLS, "CopyDataUntil")
    assert linked_bytes(ROM, loc, 16) == bytes.fromhex("2a12137cb820f97db920f5c921687b06")
