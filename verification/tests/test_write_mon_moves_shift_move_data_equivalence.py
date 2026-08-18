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
WRITTEN_OFF = 9


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


class IncDe(angr.SimProcedure):
    def __init__(self, n: int) -> None:
        super().__init__()
        self._n = n

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.state.regs.de = self.state.regs.de + 1
        self.jump(self._n)


class FetchDe(angr.SimProcedure):
    def __init__(self, n: int) -> None:
        super().__init__()
        self._n = n

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.state.regs.a = self.state.globals["fetched"]
        self.jump(self._n)


class StoreIncHl(angr.SimProcedure):
    def __init__(self, n: int) -> None:
        super().__init__()
        self._n = n

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.state.globals["written"] = self.state.regs.a
        self.state.regs.hl = self.state.regs.hl + 1
        self.jump(self._n)


class DecC(angr.SimProcedure):
    """Models `dec c` with carry preservation (see CopyMapConnectionHeader)."""

    def __init__(self, done: int) -> None:
        super().__init__()
        self._done = done

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        f_in = self.state.regs.f
        # regs.f is stored in shim-Z80 layout (C@bit0, N@bit1, H@bit4, Z@bit6).
        incoming_c = (f_in & 0x01) == 0x01
        c = self.state.regs.c
        c_new = c - 1
        z = c_new == 0
        h = (c & 0xF) == 0
        self.state.regs.c = c_new
        # shim-Z80 layout: Z@bit6, N@bit1, H@bit4, C@bit0.
        self.state.regs.f = claripy.Concat(
            claripy.BVV(0, 1), z, claripy.BVV(0, 1), h,
            claripy.BVV(0, 2), claripy.BVV(1, 1), incoming_c,
        )
        self.state.globals["result"] = claripy.If(z, claripy.BVV(1, 8), claripy.BVV(0, 8))
        self.jump(self._done)


def inputs(tag: str) -> dict:
    i = symbolic_registers(tag)
    i["fetched"] = claripy.BVS(f"{tag}_fetched", 8)
    i["written"] = claripy.BVS(f"{tag}_written", 8)
    return i


def assembly(i: dict) -> list[E]:
    loc = symbol_location(SYMBOLS, "WriteMonMoves_ShiftMoveData")
    q = symbol_location(SYMBOLS, "WriteMonMoves_ShiftMoveData.loop").address
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
    p.hook(q, IncDe(q + 1), length=1)       # inc de
    p.hook(q + 1, FetchDe(q + 2), length=1) # ld a, [de]
    p.hook(q + 2, StoreIncHl(q + 3), length=1)  # ld [hli], a
    p.hook(q + 3, DecC(DONE), length=1)     # dec c
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
    fn = p.loader.find_symbol("port_write_mon_moves_shift_move_data_step")
    assert fn is not None
    s = p.factory.call_state(fn.rebased_addr, NATIVE_STATE)
    store_native_registers(s, NATIVE_STATE, i)
    s.memory.store(NATIVE_STATE + FETCHED_OFF, i["fetched"])
    s.memory.store(NATIVE_STATE + WRITTEN_OFF, i["written"])
    m = p.factory.simulation_manager(s)
    m.run()
    assert not m.errored
    return [
        E(
            **native_registers(x, NATIVE_STATE),
            memory=x.memory.load(NATIVE_STATE + WRITTEN_OFF, 1),
            result=x.regs.rax[7:0],
            constraints=tuple(x.solver.constraints),
        )
        for x in m.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_transition_equivalence() -> None:
    i = inputs("wmmsmd")
    assert_pathwise_equivalent(assembly(i), native(i), (*REGISTERS, "memory", "result"))


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_exact_body() -> None:
    loc = symbol_location(SYMBOLS, "WriteMonMoves_ShiftMoveData")
    assert linked_bytes(ROM, loc, 9) == bytes.fromhex("0e03131a220d20fac9")
