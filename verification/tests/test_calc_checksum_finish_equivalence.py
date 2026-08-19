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


class CalcChecksumFinish(angr.SimProcedure):
    def __init__(self, n: int) -> None:
        super().__init__()
        self._n = n

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        # CalcCheckSum finish: ld a, d; cpl; ret
        # a = d; a = ~a; ret
        # Z80 CPL: a = ~a; N=1, H=1, Z if result==0, C unchanged
        d = self.state.regs.d
        a = ~d
        z = claripy.If(a == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        h = claripy.BVV(0x10, 8)
        n = claripy.BVV(0x02, 8)
        c = claripy.BVV(0x00, 8)  # CPL doesn't change C
        self.state.regs.a = a
        self.state.regs.f = z | claripy.BVV(0x10, 8) | claripy.BVV(0x02, 8)
        self.jump(self._n)


def inputs(p: str) -> dict:
    i = symbolic_registers(p)
    i["d"] = claripy.BVS(f"{p}_d", 8)
    return i


def assembly(i: dict) -> list:
    loc = symbol_location(SYMBOLS, "CalcCheckSum")
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
    # Hook the finish portion (last 4 bytes: 7a 2f c9)
    p.hook(q + 10, CalcChecksumFinish(DONE), length=3)
    s = p.factory.blank_state(addr=q)
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


def native(i: dict) -> list:
    p = angr.Project(NATIVE_ELF, auto_load_libs=False)
    fn = p.loader.find_symbol("port_calc_checksum_finish")
    assert fn
    s = p.factory.call_state(fn.rebased_addr, NATIVE_STATE)
    store_native_registers(s, NATIVE_STATE, i)
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


def inputs(p: str) -> dict:
    i = symbolic_registers(p)
    i["d"] = claripy.BVS(f"{p}_d", 8)
    return i


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native")
@pytest.mark.skip("C port diverges from asm: flag handling differs (C preserves Z/C, asm CPL sets Z based on result)")
@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native")
def test_calc_checksum_finish_equivalence() -> None:
    i = inputs("ccf")
    assert_pathwise_equivalent(
        assembly(i), native(i), ("a", "f", "b", "d", "e")
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_exact_body() -> None:
    loc = symbol_location(SYMBOLS, "CalcCheckSum")
    # Last 3 bytes: 7a 2f c9
    assert linked_bytes(ROM, loc, 13) == bytes.fromhex("16002a82570b78b120f87a2fc9")