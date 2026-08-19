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
FETCHED_OFF = 8
DONE = 0xEFFF

# CalcCheckSum: 16 00 | 2a 82 57 0b 78 b1 20 f8 | 7a 2f c9
#   ld d,0  |  <loop body, 8 bytes>  |  ld a,d / cpl / ret
# The loop body is at .loop (offset 2):
#   ld a,[hli] ; add d ; ld d,a ; dec bc ; ld a,b ; or c ; jr nz,.loop


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


class LoopBody(angr.SimProcedure):
    """Model one CalcCheckSum loop iteration as a single transition.

    Reads the byte from [hl] (symbolic via ``fetched``), increments hl,
    accumulates into d, decrements bc, and evaluates ``b|c``. OR clears
    N/H/C and sets Z iff the result is zero. Records whether the counter
    reached zero (``result``) and jumps to the DONE sentinel; the loop
    back-edge is not modeled — this is the one-iteration transition the
    C step implements, so it matches ``port_calc_checksum_step`` exactly.
    """

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        s = self.state

        # ld a,[hli]
        byte = s.globals["fetched"]
        s.regs.a = byte
        s.regs.hl = s.regs.hl + 1

        # add d ; ld d,a
        a = (byte + s.regs.d) & 0xFF
        s.regs.a = a
        s.regs.d = a

        # dec bc
        s.regs.bc = s.regs.bc - 1

        # ld a,b ; or c  (OR clears N/H/C, sets Z iff result is zero)
        a = s.regs.b | s.regs.c
        s.regs.a = a
        s.regs.f = claripy.If(a == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))

        s.globals["result"] = claripy.If(a == 0, claripy.BVV(1, 8), claripy.BVV(0, 8))
        self.jump(DONE)


def inputs(tag: str) -> dict:
    i = symbolic_registers(tag)
    i["fetched"] = claripy.BVS(f"{tag}_fetched", 8)
    return i


def assembly(i: dict) -> list[E]:
    loc = symbol_location(SYMBOLS, "CalcCheckSum")
    q = loc.address + 2  # .loop
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
    p.hook(q, LoopBody(), length=8)  # ld a,[hli] .. or c ; jr nz,.loop
    s = p.factory.blank_state(addr=q)
    set_assembly_registers(s, i)
    s.globals["fetched"] = i["fetched"]
    m = p.factory.simulation_manager(s)
    m.explore(find=DONE)
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
            memory=x.globals["fetched"],
            result=x.globals["result"],
            constraints=tuple(x.solver.constraints),
        )
    ]


def native(i: dict) -> list[E]:
    p = angr.Project(NATIVE_ELF, auto_load_libs=False)
    fn = p.loader.find_symbol("port_calc_checksum_step")
    assert fn is not None
    s = p.factory.call_state(fn.rebased_addr, NATIVE_STATE)
    store_native_registers(s, NATIVE_STATE, i)
    s.memory.store(NATIVE_STATE + FETCHED_OFF, i["fetched"])
    m = p.factory.simulation_manager(s)
    m.run()
    assert not m.errored
    assert len(m.deadended) == 1
    x = m.deadended[0]
    return [
        E(
            **native_registers(x, NATIVE_STATE),
            memory=x.memory.load(NATIVE_STATE + FETCHED_OFF, 1),
            result=x.regs.rax[7:0],
            constraints=tuple(x.solver.constraints),
        )
    ]


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
def test_calc_checksum_step_equivalence() -> None:
    i = inputs("ccs")
    assert_pathwise_equivalent(
        assembly(i),
        native(i),
        ("a", "f", "b", "c", "d", "e", "h", "l", "memory", "result"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_exact_body() -> None:
    loop = symbol_location(SYMBOLS, "CalcCheckSum.loop")
    # The 8-byte loop body.
    assert linked_bytes(ROM, loop, 8) == bytes.fromhex("2a82570b78b120f8")
    # The full 13-byte routine: ld d,0 / body / ld a,d / cpl / ret
    loc = symbol_location(SYMBOLS, "CalcCheckSum")
    assert linked_bytes(ROM, loc, 13) == bytes.fromhex("16002a82570b78b120f87a2fc9")
