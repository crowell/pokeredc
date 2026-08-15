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

KEYS = ("dividend0", "dividend1", "dividend2", "dividend3", "divisor", "quotient0", "quotient1", "quotient2", "quotient3", "remainder")


class LoadDividend(angr.SimProcedure):
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


class StoreRemainder(angr.SimProcedure):
    def __init__(self, addr: int, n: int) -> None:
        super().__init__()
        self.addr = addr
        self.n = n

    def run(self) -> None:
        self.state.memory.store(self.addr, self.state.regs.a, endness="big")
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
    memory: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    i = symbolic_registers(prefix)
    for k in KEYS:
        i[k] = claripy.BVS(f"{prefix}_{k}", 8)
    return i


def project_divide():
    loc = symbol_location(SYMBOLS, "_Divide")
    return loc, angr.Project(
        rom_window(ROM, loc.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0, "entry_point": loc.address},
    )


def setup_divide(state: angr.SimState, i: dict[str, claripy.ast.BV]) -> None:
    set_assembly_registers(state, i)
    for k in KEYS:
        state.globals[k] = i[k]


def endpoint_divide(state: angr.SimState, i: dict[str, claripy.ast.BV]) -> E:
    constraints = tuple(state.solver.constraints)
    return E(
        **assembly_registers(state),
        memory=claripy.Concat(*(state.globals[k] for k in KEYS)),
        constraints=constraints,
    )


def assembly_divide(i: dict[str, claripy.ast.BV]) -> list[E]:
    loc, p = project_divide()
    q = loc.address
    p.hook(q + 4, LoadDividend(0xFF95, q + 7), length=3)
    p.hook(q + 7, LoadDividend(0xFF96, q + 10), length=3)
    p.hook(q + 10, LoadDividend(0xFF97, q + 13), length=3)
    p.hook(q + 13, LoadDividend(0xFF98, q + 16), length=3)
    p.hook(q + 16, LoadDivisor(0xFF99, q + 19), length=3)
    p.hook(q + 19, StoreQuotient(0xFF95, q + 22), length=3)
    p.hook(q + 22, StoreQuotient(0xFF96, q + 25), length=3)
    p.hook(q + 25, StoreQuotient(0xFF97, q + 28), length=3)
    p.hook(q + 28, StoreQuotient(0xFF98, q + 31), length=3)
    p.hook(q + 31, StoreRemainder(0xFF99, q + 34), length=3)
    p.hook(q + 34, Stop())
    s = p.factory.blank_state(addr=q)
    set_assembly_registers(s, i)
    for k in KEYS:
        s.globals[k] = i[k]
    m = p.factory.simulation_manager(s)
    m.explore(find=DONE)
    return [endpoint_divide(m.found[0], i)]


def native_divide(symbol: str, i: dict[str, claripy.ast.BV]) -> list[E]:
    p = angr.Project(NATIVE_ELF, auto_load_libs=False)
    fn = p.loader.find_symbol(symbol)
    assert fn
    s = p.factory.call_state(fn.rebased_addr, NATIVE_STATE)
    store_native_registers(s, NATIVE_STATE, i)
    s.memory.store(NATIVE_STATE + 8, claripy.Concat(*(i[k] for k in KEYS)))
    m = p.factory.simulation_manager(s)
    m.run()
    assert not m.errored
    return [
        E(
            **native_registers(x, NATIVE_STATE),
            memory=x.memory.load(NATIVE_STATE + 8, len(KEYS)),
            constraints=tuple(x.solver.constraints),
        )
        for x in m.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
def test_divide_equivalence():
    i = inputs("divide")
    assert_pathwise_equivalent(assembly_divide(i), native_divide("port_divide", i), (*REGISTERS, "memory"))


def test_divide_exact_body():
    loc = symbol_location(SYMBOLS, "_Divide")
    assert linked_bytes(ROM, loc, 120) == bytes.fromhex(
        "afe09ae09be09ce09de09e3e095ff09a4ff0969157f0994ff09599380ce0957ae096f09e3ce09e18e578fe012845f09ecb27e09ef09dcb17e09df09ccb17e09cf09bcb17e09b1d20163e085ff09ae099afe09af096e095f097e096f098e0977bfe01200105f099cb3fe099f09acb1fe09a189bf096e099f0"
    )