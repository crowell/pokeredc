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
W_AUTO_TEXT_BOX_DRAWING_CONTROL = 0xCF0C
W_DO_NOT_WAIT = 0xCC3C


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
    auto_ctrl: claripy.ast.BV
    do_not_wait: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class EnableAutoTextBoxDrawing(angr.SimProcedure):
    def __init__(self, n: int) -> None:
        super().__init__()
        self._n = n

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        # xor a (a=0, Z=1); jr +2 (skip DisableAutoTextBoxDrawing's ld a,1)
        # Fall through to AutoTextBoxDrawingCommon:
        #   ld [wAutoTextBoxDrawingControl], a
        #   xor a (a=0, Z=1)
        #   ld [wDoNotWait...], a
        #   ret
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x40, 8)  # Z flag
        self.state.memory.store(0xCF0C, claripy.BVV(0, 8))
        self.state.memory.store(0xCC3C, claripy.BVV(0, 8))
        self.jump(self._n)


class DisableAutoTextBoxDrawing(angr.SimProcedure):
    def __init__(self, n: int) -> None:
        super().__init__()
        self._n = n

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        # ld a, 1; ld [wAutoTextBoxDrawingControl], a; xor a; ld [wDoNotWait...], a; ret
        self.state.memory.store(0xCF0C, claripy.BVV(1, 8))
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x40, 8)
        self.state.memory.store(0xCC3C, claripy.BVV(0, 8))
        self.jump(self._n)


def inputs(p: str) -> dict:
    return symbolic_registers(p)


def assembly(i: dict, asm_symbol: str):
    loc = symbol_location(SYMBOLS, asm_symbol)
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
    if asm_symbol == "EnableAutoTextBoxDrawing":
        p.hook(q, EnableAutoTextBoxDrawing(DONE), length=5)  # af 18 02 3e 01
    else:
        p.hook(q, DisableAutoTextBoxDrawing(DONE), length=11)
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
            auto_ctrl=x.memory.load(W_AUTO_TEXT_BOX_DRAWING_CONTROL, 1),
            do_not_wait=x.memory.load(W_DO_NOT_WAIT, 1),
            constraints=tuple(x.solver.constraints),
        )
    ]


def native(i: dict, native_symbol: str):
    p = angr.Project(NATIVE_ELF, auto_load_libs=False)
    fn = p.loader.find_symbol(native_symbol)
    assert fn
    s = p.factory.call_state(fn.rebased_addr, NATIVE_STATE)
    store_native_registers(s, NATIVE_STATE, i)
    m = p.factory.simulation_manager(s)
    m.run()
    assert not m.errored
    x = m.deadended[0]
    nr = native_registers(x, NATIVE_STATE)
    auto_ctrl = x.memory.load(NATIVE_STATE + 8, 1)
    do_not_wait = x.memory.load(NATIVE_STATE + 9, 1)
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
            auto_ctrl=auto_ctrl,
            do_not_wait=do_not_wait,
            constraints=tuple(x.solver.constraints),
        )
    ]


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native")
def test_enable_auto_text_box_drawing_equivalence() -> None:
    i = inputs("eatb")
    assert_pathwise_equivalent(
        assembly(i, "EnableAutoTextBoxDrawing"),
        native(i, "port_enable_auto_text_box_drawing"),
        ("a", "f", "b", "c", "d", "e", "h", "l", "auto_ctrl", "do_not_wait")
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native")
def test_disable_auto_text_box_drawing_equivalence() -> None:
    i = inputs("datb")
    assert_pathwise_equivalent(
        assembly(i, "DisableAutoTextBoxDrawing"),
        native(i, "port_disable_auto_text_box_drawing"),
        ("a", "f", "b", "c", "d", "e", "h", "l", "auto_ctrl", "do_not_wait")
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_exact_body() -> None:
    loc1 = symbol_location(SYMBOLS, "EnableAutoTextBoxDrawing")
    assert linked_bytes(ROM, loc1, 5) == bytes.fromhex("af18023e01"), f"Enable: {linked_bytes(ROM, loc1, 5).hex()}"
    loc2 = symbol_location(SYMBOLS, "DisableAutoTextBoxDrawing")
    loc3 = symbol_location(SYMBOLS, "AutoTextBoxDrawingCommon")
    assert linked_bytes(ROM, loc3, 10) == bytes.fromhex("ea0ccfafea3cccc9e53e"), f"Common: {linked_bytes(ROM, loc3, 10).hex()}"