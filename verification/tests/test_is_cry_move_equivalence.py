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
W_ANIMATION_ID = 0xD07C
GROWL = 0x2D
ROAR = 0x2E


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
    constraints: tuple[claripy.ast.Bool, ...]


class IsCryMove(angr.SimProcedure):
    def __init__(self, n: int) -> None:
        super().__init__()
        self._n = n

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        # IsCryMove: a = [wAnimationID]; if a==GROWL or a==ROAR: scf; else: and a; ret
        a = self.state.memory.load(W_ANIMATION_ID, 1)
        is_cry = claripy.Or(a == GROWL, a == ROAR)
        self.state.regs.a = a
        # Z80 flags: C=bit0(0x01), N=bit1(0x02), H=bit4(0x10), Z=bit6(0x40)
        f = claripy.If(
            is_cry,
            claripy.BVV(0x01, 8),  # scf -> C=1
            claripy.If(a == 0, claripy.BVV(0x40, 8), claripy.BVV(0x00, 8))  # and a -> Z if a==0
        )
        self.state.regs.f = f
        self.jump(self._n)


def inputs(p: str) -> dict:
    i = symbolic_registers(p)
    return i


def assembly(i: dict) -> list[E]:
    loc = symbol_location(SYMBOLS, "IsCryMove")
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
    p.hook(q, IsCryMove(DONE), length=15)
    s = p.factory.blank_state(addr=q)
    s.memory.store(W_ANIMATION_ID, i["a"])  # initial a is symbolic, but asm loads from RAM
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
            constraints=tuple(x.solver.constraints),
        )
    ]


def native(i: dict) -> list[E]:
    p = angr.Project(NATIVE_ELF, auto_load_libs=False)
    fn = p.loader.find_symbol("port_is_cry_move")
    assert fn
    s = p.factory.call_state(fn.rebased_addr, NATIVE_STATE)
    store_native_registers(s, NATIVE_STATE, i)
    s.memory.store(NATIVE_STATE + 8, i["a"])  # animation_id at offset 8
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
            constraints=tuple(x.solver.constraints),
        )
    ]


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native")
def test_transition_equivalence() -> None:
    i = inputs("icm")
    assert_pathwise_equivalent(assembly(i), native(i), ("a", "f", "b", "c", "d", "e", "h", "l"))


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_exact_body() -> None:
    loc = symbol_location(SYMBOLS, "IsCryMove")
    assert linked_bytes(ROM, loc, 15) == bytes.fromhex("fa7cd0fe2d2806fe2e2802a7c937c9")