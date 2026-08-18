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

TX_END = 0x50


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
        self.jump(self._n)


class IncDe(angr.SimProcedure):
    def __init__(self, n: int) -> None:
        super().__init__()
        self._n = n

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.state.regs.de = self.state.regs.de + 1
        self.jump(self._n)


class StoreInc(angr.SimProcedure):
    def __init__(self, n: int) -> None:
        super().__init__()
        self._n = n

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.state.globals["written"] = self.state.regs.a
        self.state.regs.hl = self.state.regs.hl + 1
        self.jump(self._n)


class Compare(angr.SimProcedure):
    """Models `cp 0x50; jr nz` (the string terminator check).

    The native port_copy_string_step sets N always, Z if fetched==TX_END, and C
    if fetched<TX_END. We pack those into the shim-Z80 F layout so
    assembly_registers converts it to the native raw F. result = (fetched==0x50).
    """

    def __init__(self, done: int) -> None:
        super().__init__()
        self._done = done

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        fetched = self.state.globals["fetched"]
        z = fetched == TX_END
        c = fetched < TX_END
        # shim-Z80 layout: Z@bit6, N@bit1, H@bit4, C@bit0 (N always set, H clear).
        self.state.regs.f = claripy.Concat(
            claripy.BVV(0, 1), z, claripy.BVV(0, 1), claripy.BVV(0, 1),
            claripy.BVV(0, 2), claripy.BVV(1, 1), c,
        )
        self.state.globals["result"] = claripy.If(z, claripy.BVV(1, 8), claripy.BVV(0, 8))
        self.jump(self._done)


def inputs(tag: str) -> dict:
    i = symbolic_registers(tag)
    i["fetched"] = claripy.BVS(f"{tag}_fetched", 8)
    i["written"] = claripy.BVS(f"{tag}_written", 8)
    return i


def assembly(i: dict) -> list[E]:
    loc = symbol_location(SYMBOLS, "CopyString")
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
    p.hook(q, Fetch(q + 1), length=1)        # ld a, [de]
    p.hook(q + 1, IncDe(q + 2), length=1)    # inc de
    p.hook(q + 2, StoreInc(q + 3), length=1)  # ld [hli], a
    p.hook(q + 3, Compare(DONE), length=4)    # cp 0x50 ; jr nz
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
            memory=x.globals["written"],
            result=x.globals["result"],
            constraints=tuple(x.solver.constraints),
        )
    ]


def native(i: dict) -> list[E]:
    p = angr.Project(NATIVE_ELF, auto_load_libs=False)
    fn = p.loader.find_symbol("port_copy_string_step")
    assert fn is not None
    s = p.factory.call_state(
        fn.rebased_addr, NATIVE_STATE, claripy.ZeroExt(56, i["fetched"])
    )
    store_native_registers(s, NATIVE_STATE, i)
    s.memory.store(NATIVE_STATE + 8, i["written"])
    m = p.factory.simulation_manager(s)
    m.run()
    assert not m.errored
    return [
        E(
            **native_registers(x, NATIVE_STATE),
            memory=x.memory.load(NATIVE_STATE + 8, 1),
            result=x.regs.rax[7:0],
            constraints=tuple(x.solver.constraints),
        )
        for x in m.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_transition_equivalence() -> None:
    i = inputs("copy_string")
    assert_pathwise_equivalent(assembly(i), native(i), (*REGISTERS, "memory", "result"))


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_exact_body() -> None:
    loc = symbol_location(SYMBOLS, "CopyString")
    assert linked_bytes(ROM, loc, 8) == bytes.fromhex("1a1322fe5020f9c9")
