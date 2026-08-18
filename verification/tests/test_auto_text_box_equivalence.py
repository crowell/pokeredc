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
    auto_text_box_drawing_control: claripy.ast.BV
    do_not_wait_for_button_press: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class AutoTextBoxDrawingCommon(angr.SimProcedure):
    def __init__(self, n: int) -> None:
        super().__init__()
        self._n = n

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        # asm: ld [wAutoTextBoxDrawingControl], a; xor a; ld [wDoNotWait...], a; ret
        a_in = self.state.regs.a
        self.state.memory.store(W_AUTO_TEXT_BOX_DRAWING_CONTROL, a_in)
        # xor a: a=0, f=Z (Z=1, N=0, H=0, C=0 in Z80 layout -> Z=bit6=0x40)
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x40, 8)
        self.state.memory.store(W_DO_NOT_WAIT, claripy.BVV(0, 8))
        self.jump(self._n)


class DisableWaitingAfterTextDisplay(angr.SimProcedure):
    def __init__(self, n: int) -> None:
        super().__init__()
        self._n = n

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        # asm: ld a, 1; ld [wDoNotWait...], a; ret
        # ld a,1 doesn't set flags; store doesn't either
        self.state.regs.a = claripy.BVV(1, 8)
        self.state.memory.store(W_DO_NOT_WAIT, claripy.BVV(1, 8))
        self.jump(self._n)


def inputs(p: str) -> dict:
    i = symbolic_registers(p)
    return i


def assembly(i: dict, asm_symbol: str) -> list[E]:
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
    if asm_symbol == "AutoTextBoxDrawingCommon":
        p.hook(q, AutoTextBoxDrawingCommon(DONE), length=8)
    else:
        p.hook(q, DisableWaitingAfterTextDisplay(DONE), length=6)
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
            auto_text_box_drawing_control=x.memory.load(W_AUTO_TEXT_BOX_DRAWING_CONTROL, 1),
            do_not_wait_for_button_press=x.memory.load(W_DO_NOT_WAIT, 1),
            constraints=tuple(x.solver.constraints),
        )
    ]


def native(i: dict, native_symbol: str) -> list[E]:
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
    # Native stores to struct fields at offsets 8 and 9
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
            auto_text_box_drawing_control=auto_ctrl,
            do_not_wait_for_button_press=do_not_wait,
            constraints=tuple(x.solver.constraints),
        )
    ]


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native")
def test_auto_text_box_drawing_common_equivalence() -> None:
    i = inputs("atb")
    assert_pathwise_equivalent(
        assembly(i, "AutoTextBoxDrawingCommon"),
        native(i, "port_auto_text_box_drawing_common"),
        ("a", "f", "b", "c", "d", "e", "h", "l", "auto_text_box_drawing_control", "do_not_wait_for_button_press")
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native")
def test_disable_waiting_after_text_display_equivalence() -> None:
    i = inputs("dwt")
    assert_pathwise_equivalent(
        assembly(i, "DisableWaitingAfterTextDisplay"),
        native(i, "port_disable_waiting_after_text_display"),
        ("a", "b", "c", "d", "e", "h", "l", "do_not_wait_for_button_press")
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_exact_body() -> None:
    loc1 = symbol_location(SYMBOLS, "AutoTextBoxDrawingCommon")
    assert linked_bytes(ROM, loc1, 8) == bytes.fromhex("ea0ccfafea3cccc9"), f"{loc1}: {linked_bytes(ROM, loc1, 8).hex()}"
    loc2 = symbol_location(SYMBOLS, "DisableWaitingAfterTextDisplay")
    assert linked_bytes(ROM, loc2, 6) == bytes.fromhex("3e01ea3cccc9"), f"{loc2}: {linked_bytes(ROM, loc2, 6).hex()}"