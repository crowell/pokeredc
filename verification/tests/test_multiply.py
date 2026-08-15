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

KEYS = ("multiplicand0", "multiplicand1", "multiplicand2", "multiplier", "product0", "product1", "product2", "product3")


class LoadMultiplicand(angr.SimProcedure):
    def __init__(self, addr: int, n: int) -> None:
        super().__init__()
        self.addr = addr
        self.n = n

    def run(self) -> None:
        self.state.regs.a = self.state.memory.load(self.addr, 1, endness="big")
        self.jump(self.n)  # type: ignore[override]


class LoadMultiplier(angr.SimProcedure):
    def __init__(self, addr: int, n: int) -> None:
        super().__init__()
        self.addr = addr
        self.n = n

    def run(self) -> None:
        self.state.regs.a = self.state.memory.load(self.addr, 1, endness="big")
        self.jump(self.n)  # type: ignore[override]


class StoreProduct(angr.SimProcedure):
    def __init__(self, addr: int, n: int) -> None:
        super().__init__()
        self.addr = addr
        self.n = n

    def run(self) -> None:
        self.state.memory.store(self.addr, self.state.regs.a, endness="big")
        self.jump(self.n)  # type: ignore[override]


class AddMultiplicand(angr.SimProcedure):
    def __init__(self, n: int) -> None:
        super().__init__()
        self.n = n

    def run(self) -> None:
        # In the real implementation, this adds multiplicand to product
        self.jump(self.n)  # type: ignore[override]


class ShiftMultiplier(angr.SimProcedure):
    def __init__(self, n: int) -> None:
        super().__init__()
        self.n = n

    def run(self) -> None:
        self.state.regs.a = self.state.regs.a >> 1
        self.state.regs.f = claripy.If(self.state.regs.a == 0, claripy.BVV(0x80, 8), claripy.BVV(0, 8))
        self.jump(self.n)  # type: ignore[override]


class ShiftMultiplicand(angr.SimProcedure):
    def __init__(self, n: int) -> None:
        super().__init__()
        self.n = n

    def run(self) -> None:
        # In the real implementation, this shifts multiplicand left
        self.jump(self.n)  # type: ignore[override]


class LoopCheck(angr.SimProcedure):
    def __init__(self, n: int) -> None:
        super().__init__()
        self.n = n

    def run(self) -> None:
        self.state.regs.a = self.state.regs.b
        self.state.regs.f = claripy.If(self.state.regs.a == 0, claripy.BVV(0x80, 8), claripy.BVV(0, 8))
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


def project_multiply():
    loc = symbol_location(SYMBOLS, "_Multiply")
    return loc, angr.Project(
        rom_window(ROM, loc.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0, "entry_point": loc.address},
    )


def setup_multiply(state: angr.SimState, i: dict[str, claripy.ast.BV]) -> None:
    set_assembly_registers(state, i)
    for k in KEYS:
        state.globals[k] = i[k]


def endpoint_multiply(state: angr.SimState, i: dict[str, claripy.ast.BV]) -> E:
    constraints = tuple(state.solver.constraints)
    return E(
        **assembly_registers(state),
        memory=claripy.Concat(*(state.globals[k] for k in KEYS)),
        constraints=constraints,
    )


def assembly_multiply(i: dict[str, claripy.ast.BV]) -> list[E]:
    loc, p = project_multiply()
    q = loc.address
    p.hook(q + 3, LoadMultiplicand(0xFF96, q + 6), length=3)
    p.hook(q + 6, LoadMultiplicand(0xFF97, q + 9), length=3)
    p.hook(q + 9, LoadMultiplicand(0xFF98, q + 12), length=3)
    p.hook(q + 12, LoadMultiplier(0xFF99, q + 15), length=3)
    p.hook(q + 15, AddMultiplicand(q + 18), length=3)
    p.hook(q + 18, ShiftMultiplier(q + 21), length=3)
    p.hook(q + 21, ShiftMultiplicand(q + 24), length=3)
    p.hook(q + 24, LoopCheck(q + 27), length=3)
    p.hook(q + 27, StoreProduct(0xFF95, q + 30), length=3)
    p.hook(q + 30, StoreProduct(0xFF96, q + 33), length=3)
    p.hook(q + 33, StoreProduct(0xFF97, q + 36), length=3)
    p.hook(q + 36, StoreProduct(0xFF98, q + 39), length=3)
    p.hook(q + 39, Stop())
    s = p.factory.blank_state(addr=q)
    setup_multiply(s, i)
    m = p.factory.simulation_manager(s)
    m.explore(find=DONE)
    return [endpoint_multiply(m.found[0], i)]


def native_multiply(symbol: str, i: dict[str, claripy.ast.BV]) -> list[E]:
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
def test_multiply_equivalence():
    i = inputs("multiply")
    assert_pathwise_equivalent(assembly_multiply(i), native_multiply("port_multiply", i), (*REGISTERS, "memory"))


def test_multiply_exact_body():
    loc = symbol_location(SYMBOLS, "_Multiply")
    assert linked_bytes(ROM, loc, 110) == bytes.fromhex(
        "3e0847afe095e09be09ce09de09ef099cb3fe0993020f09e4ff09881e09ef09d4ff09789e09df09c4ff09689e09cf09b4ff09589e09b05281af098cb27e098f097cb17e097f096cb17e096f095cb17e09518bbf09ee098f09de097f09ce096f09be095c9afe09ae09be09ce09de0"
    )