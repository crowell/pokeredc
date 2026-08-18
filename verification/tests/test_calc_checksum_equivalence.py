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

FETCHED_OFF = 8


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


class AddD(angr.SimProcedure):
    def __init__(self, n: int) -> None:
        super().__init__()
        self._n = n

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.state.regs.a = (self.state.globals["fetched"] + self.state.regs.d) & 0xFF
        self.state.regs.d = self.state.regs.a
        self.jump(self._n)


class LdD(angr.SimProcedure):
    def __init__(self, n: int) -> None:
        super().__init__()
        self._n = n

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.state.regs.d = self.state.regs.a
        self.jump(self._n)


class DecBc(angr.SimProcedure):
    def __init__(self, n: int) -> None:
        super().__init__()
        self._n = n

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.state.regs.bc = self.state.regs.bc - 1
        self.jump(self._n)


class LdAb(angr.SimProcedure):
    def __init__(self, n: int) -> None:
        super().__init__()
        self._n = n

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.state.regs.a = self.state.regs.b
        self.jump(self._n)

class OrC(angr.SimProcedure):
    def __init__(self, done: int) -> None:
        super().__init__()
        self._done = done

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        a = self.state.regs.b | self.state.regs.c
        self.state.regs.a = a
        # OR clears N/H/C and sets Z iff result is zero (shim-Z80: Z@bit6).
        self.state.regs.f = claripy.If(
            a == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)
        )
        self.state.globals["result"] = claripy.If(a == 0, claripy.BVV(1, 8), claripy.BVV(0, 8))
        self.jump(self._done)


def inputs(tag: str) -> dict:
    i = symbolic_registers(tag)
    i["fetched"] = claripy.BVS(f"{tag}_fetched", 8)
    return i


def assembly(i: dict) -> list[E]:
    loc = symbol_location(SYMBOLS, "CalcCheckSum")
    q = symbol_location(SYMBOLS, "CalcCheckSum.loop").address
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
    p.hook(q, Fetch(q + 1), length=1)        # ld a, [hli]
    p.hook(q + 1, AddD(q + 2), length=1)     # add d
    p.hook(q + 2, LdD(q + 3), length=1)      # ld d, a
    p.hook(q + 3, DecBc(q + 4), length=1)    # dec bc
    p.hook(q + 4, LdAb(q + 5), length=1)     # ld a, b
    p.hook(q + 5, OrC(DONE), length=1)       # or c
    s = p.factory.blank_state(addr=q)
    set_assembly_registers(s, i)
    s.globals["fetched"] = i["fetched"]
    m = p.factory.simulation_manager(s)
    m.explore(find=DONE)
    assert len(m.found) == 1
    x = m.found[0]
    return [
        E(
            **assembly_registers(x),
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
    return [
        E(
            **native_registers(x, NATIVE_STATE),
            memory=x.memory.load(NATIVE_STATE + FETCHED_OFF, 1),
            result=x.regs.rax[7:0],
            constraints=tuple(x.solver.constraints),
        )
        for x in m.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_transition_equivalence() -> None:
    i = inputs("cks")
    assert_pathwise_equivalent(assembly(i), native(i), (*REGISTERS, "memory", "result"))


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_exact_body() -> None:
    loc = symbol_location(SYMBOLS, "CalcCheckSum")
    assert linked_bytes(ROM, loc, 13) == bytes.fromhex("16002a82570b78b120f87a2fc9")
