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

WRITTEN_OFF = 8


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


class StoreHl(angr.SimProcedure):
    def __init__(self, n: int) -> None:
        super().__init__()
        self._n = n

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.state.globals["written"] = self.state.regs.a
        self.jump(self._n)


class AddHlDe(angr.SimProcedure):
    def __init__(self, n: int) -> None:
        super().__init__()
        self._n = n

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        hl = self.state.regs.hl
        de = self.state.regs.de
        wide = claripy.ZeroExt(16, hl) + claripy.ZeroExt(16, de)
        c_add = wide[16]
        self.state.regs.hl = wide[15:0]
        # ADD HL,DE: only the carry (bit0) survives DEC B; N/Z/H are recomputed.
        self.state.regs.f = claripy.Concat(claripy.BVV(0, 7), c_add)
        self.jump(self._n)


class DecB(angr.SimProcedure):
    def __init__(self, done: int) -> None:
        super().__init__()
        self._done = done

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        f_add = self.state.regs.f
        # regs.f is shim-Z80 (C@bit0, N@bit1, H@bit4, Z@bit6).
        incoming_c = (f_add & 0x01) == 0x01
        b = self.state.regs.b
        b_new = b - 1
        z = b_new == 0
        h = (b & 0xF) == 0
        self.state.regs.b = b_new
        # shim-Z80: Z@bit6, N@bit1, H@bit4, C@bit0.
        self.state.regs.f = claripy.Concat(
            claripy.BVV(0, 1), z, claripy.BVV(0, 1), h,
            claripy.BVV(0, 2), claripy.BVV(1, 1), incoming_c,
        )
        self.state.globals["result"] = claripy.If(z, claripy.BVV(1, 8), claripy.BVV(0, 8))
        self.jump(self._done)


def inputs(tag: str) -> dict:
    return symbolic_registers(tag)


def assembly(i: dict) -> list[E]:
    loc = symbol_location(SYMBOLS, "HideSprites")
    # Loop body begins 10 bytes into the function (after ld a/ld hl/ld de/ld b).
    q = loc.address + 10
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
    p.hook(q, StoreHl(q + 1), length=1)        # ld [hl], a
    p.hook(q + 1, AddHlDe(q + 2), length=1)    # add hl, de
    p.hook(q + 2, DecB(DONE), length=1)        # dec b
    s = p.factory.blank_state(addr=q)
    set_assembly_registers(s, i)
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
    fn = p.loader.find_symbol("port_hide_sprites_step")
    assert fn is not None
    s = p.factory.call_state(fn.rebased_addr, NATIVE_STATE)
    store_native_registers(s, NATIVE_STATE, i)
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
    i = inputs("hs")
    assert_pathwise_equivalent(assembly(i), native(i), (*REGISTERS, "memory", "result"))


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_exact_body() -> None:
    loc = symbol_location(SYMBOLS, "HideSprites")
    assert linked_bytes(ROM, loc, 16) == bytes.fromhex("3ea02100c3110400062877190520fbc9")
