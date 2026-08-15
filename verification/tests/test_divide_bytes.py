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
from verification.harness.sm83_shims import Sm83LoadAImmediate


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification" / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
DONE = 0xEFFF


class LoadDividendHigh(angr.SimProcedure):
    def __init__(self, addr: int, n: int) -> None:
        super().__init__()
        self.addr = addr
        self.n = n

    def run(self) -> None:
        self.state.regs.a = self.state.memory.load(self.addr, 1, endness="big")
        self.jump(self.n)  # type: ignore[override]


class LoadDivisor(angr.SimProcedure):
    def __init__(self, addr: int, n: int) -> None:
        super().__init__()
        self.addr = addr
        self.n = n

    def run(self) -> None:
        self.state.regs.a = self.state.memory.load(self.addr, 1, endness="big")
        self.jump(self.n)  # type: ignore[override]


class StoreQuotient(angr.SimProcedure):
    def __init__(self, addr: int, n: int) -> None:
        super().__init__()
        self.addr = addr
        self.n = n

    def run(self) -> None:
        self.state.memory.store(self.addr, self.state.regs.a, endness="big")
        self.jump(self.n)  # type: ignore[override]


class SubDivisor(angr.SimProcedure):
    def __init__(self, addr: int, n: int) -> None:
        super().__init__()
        self.addr = addr
        self.n = n

    def run(self) -> None:
        val = self.state.memory.load(self.addr, 1, endness="big")
        self.state.regs.a = self.state.regs.a - val
        self.state.regs.f = claripy.If(self.state.regs.a == 0, claripy.BVV(0x80, 8), claripy.BVV(0, 8))
        if self.state.regs.a > 0xFF:
            self.state.regs.f |= 0x10  # carry
        self.jump(self.n)  # type: ignore[override]


class IncQuotient(angr.SimProcedure):
    def __init__(self, addr: int, n: int) -> None:
        super().__init__()
        self.addr = addr
        self.n = n

    def run(self) -> None:
        val = self.state.memory.load(self.addr, 1, endness="big")
        self.state.memory.store(self.addr, val + 1, endness="big")
        self.jump(self.n)  # type: ignore[override]


class Stop(angr.SimProcedure):
    def run(self) -> None:
        self.jump(DONE)  # type: ignore[override]


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
    dividend: claripy.ast.BV
    divisor: claripy.ast.BV
    quotient: claripy.ast.BV
    saved_h: claripy.ast.BV
    saved_l: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    i = symbolic_registers(prefix)
    for k in ("dividend", "divisor", "quotient", "saved_h", "saved_l"):
        i[k] = claripy.BVS(f"{prefix}_{k}", 8)
    return i


def project():
    loc = symbol_location(SYMBOLS, "DivideBytes")
    return loc, angr.Project(
        rom_window(ROM, loc.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0, "entry_point": loc.address},
    )


def setup(state: angr.SimState, i: dict[str, claripy.ast.BV]) -> None:
    set_assembly_registers(state, i)
    for k in ("dividend", "divisor", "quotient", "saved_h", "saved_l"):
        state.globals[k] = i[k]


def endpoint(state: angr.SimState, i: dict[str, claripy.ast.BV]) -> E:
    constraints = tuple(state.solver.constraints)
    return E(
        **assembly_registers(state),
        dividend=state.globals["dividend"],
        divisor=state.globals["divisor"],
        quotient=state.globals["quotient"],
        saved_h=state.globals["saved_h"],
        saved_l=state.globals["saved_l"],
        constraints=constraints,
    )


def assembly(i: dict[str, claripy.ast.BV]) -> list[E]:
    loc, p = project()
    q = loc.address
    p.hook(q, Sm83LoadAImmediate(i["saved_h"], q + 1), length=1)
    p.hook(q + 1, Sm83LoadAImmediate(i["saved_l"], q + 3), length=2)
    p.hook(q + 3, LoadDividendHigh(0xFFE5, q + 6), length=3)
    p.hook(q + 6, StoreQuotient(0xFFE7, q + 9), length=3)
    p.hook(q + 9, LoadDivisor(0xFFE6, q + 12), length=3)
    p.hook(q + 12, SubDivisor(0xFFE6, q + 15), length=3)
    p.hook(q + 15, IncQuotient(0xFFE8, q + 18), length=3)
    p.hook(q + 18, Stop())
    s = p.factory.blank_state(addr=q)
    setup(s, i)
    m = p.factory.simulation_manager(s)
    m.explore(find=DONE)
    return [endpoint(m.found[0], i)]


def native(symbol: str, i: dict[str, claripy.ast.BV]) -> list[E]:
    p = angr.Project(NATIVE_ELF, auto_load_libs=False)
    fn = p.loader.find_symbol(symbol)
    assert fn
    s = p.factory.call_state(fn.rebased_addr, NATIVE_STATE)
    store_native_registers(s, NATIVE_STATE, i)
    s.memory.store(NATIVE_STATE + 8, claripy.Concat(i["dividend"], i["divisor"], i["quotient"], i["saved_h"], i["saved_l"]))
    m = p.factory.simulation_manager(s)
    m.run()
    assert not m.errored
    return [
        E(
            **native_registers(x, NATIVE_STATE),
            dividend=x.memory.load(NATIVE_STATE + 8, 1),
            divisor=x.memory.load(NATIVE_STATE + 9, 1),
            quotient=x.memory.load(NATIVE_STATE + 10, 1),
            saved_h=x.memory.load(NATIVE_STATE + 11, 1),
            saved_l=x.memory.load(NATIVE_STATE + 12, 1),
            constraints=tuple(x.solver.constraints),
        )
        for x in m.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
def test_divide_bytes_equivalence():
    i = inputs("divide_bytes")
    assert_pathwise_equivalent(assembly(i), native("port_divide_bytes", i), (*REGISTERS, "dividend", "divisor", "quotient", "saved_h", "saved_l"))


def test_divide_bytes_exact_body():
    loc = symbol_location(SYMBOLS, "DivideBytes")
    assert linked_bytes(ROM, loc, 21) == bytes.fromhex(
        "e521e7ffaf323aa728092a96380523342b18f8e1c9"
    )