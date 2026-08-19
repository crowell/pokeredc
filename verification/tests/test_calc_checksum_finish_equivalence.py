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
    SymbolLocation,
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
    """Model the CalcCheckSum finish: ld a,d / cpl / ret.

    a = ~d. Z80/SM83 CPL sets N and H, sets Z iff the complemented
    result is zero, and leaves C unchanged.
    """

    def __init__(self, n: int) -> None:
        super().__init__()
        self._n = n

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        d = self.state.regs.d
        a = ~d
        carry = self.state.regs.f[0]  # C is unchanged by CPL
        self.state.regs.a = a
        self.state.regs.f = (
            claripy.If(a == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
            | claripy.BVV(0x10, 8)  # H
            | claripy.BVV(0x02, 8)  # N
            | (claripy.ZeroExt(7, carry))
        )
        self.jump(self._n)


def inputs(p: str) -> dict:
    i = symbolic_registers(p)
    i["d"] = claripy.BVS(f"{p}_d", 8)
    return i


def assembly(i: dict) -> list[E]:
    loc = symbol_location(SYMBOLS, "CalcCheckSum")
    f = loc.address + 10  # finish: ld a,d / cpl / ret (7a 2f c9)
    p = angr.Project(
        rom_window(ROM, loc.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": f,
        },
    )
    # Hook the finish portion (3 bytes: 7a 2f c9) and enter at it, so the
    # preceding loop body is not executed.
    p.hook(f, CalcChecksumFinish(DONE), length=3)
    s = p.factory.blank_state(addr=f)
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
    fn = p.loader.find_symbol("port_calc_checksum_finish")
    assert fn is not None
    s = p.factory.call_state(fn.rebased_addr, NATIVE_STATE)
    store_native_registers(s, NATIVE_STATE, i)
    m = p.factory.simulation_manager(s)
    m.run()
    assert not m.errored
    assert len(m.deadended) == 1
    x = m.deadended[0]
    return [
        E(
            **native_registers(x, NATIVE_STATE),
            constraints=tuple(x.solver.constraints),
        )
    ]


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
def test_calc_checksum_finish_equivalence() -> None:
    i = inputs("ccf")
    assert_pathwise_equivalent(
        assembly(i), native(i), ("a", "f", "b", "c", "d", "e", "h", "l")
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_exact_body() -> None:
    loc = symbol_location(SYMBOLS, "CalcCheckSum")
    # Full 13-byte routine: ld d,0 / loop body / ld a,d / cpl / ret
    assert linked_bytes(ROM, loc, 13) == bytes.fromhex("16002a82570b78b120f87a2fc9")
    # The finish portion (last 3 bytes): 7a 2f c9
    assert linked_bytes(ROM, SymbolLocation(loc.bank, loc.address + 10), 3) == (
        bytes.fromhex("7a2fc9")
    )
