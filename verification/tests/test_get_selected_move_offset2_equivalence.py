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
OFFSET_RAM = 0xCC26


@dataclass(frozen=True)
class E:
    a: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    f: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class GetSelectedMoveOffset2(angr.SimProcedure):
    def __init__(self, n: int) -> None:
        super().__init__()
        self._n = n

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        # Model the whole GetSelectedMoveOffset2 (bank 3) as one SimProcedure:
        #   offset = [OFFSET_RAM]   (the native reads state->value)
        #   c = offset; b = 0; add hl, bc
        #   add hl,bc keeps Z, clears N, sets H (bit11 carry) and C (bit15 carry).
        f_in = self.state.regs.f
        h = self.state.regs.h
        l = self.state.regs.l
        offset = self.state.memory.load(OFFSET_RAM, 1)
        hl = claripy.Concat(h, l)
        wide = claripy.ZeroExt(1, hl) + claripy.ZeroExt(9, offset)
        c_flag = wide[16] == 1
        low12 = claripy.Extract(11, 0, hl)
        hsum = claripy.ZeroExt(1, low12) + claripy.ZeroExt(5, offset)
        h_flag = hsum[12] == 1
        new_hl = wide[15:0]
        self.state.regs.a = offset
        self.state.regs.b = claripy.BVV(0, 8)
        self.state.regs.c = offset
        self.state.regs.h = new_hl[15:8]
        self.state.regs.l = new_hl[7:0]
        # Preserve incoming Z (z80 bit 6); set H/C from the 16-bit add; N = 0.
        f = (f_in & 0x40) | claripy.If(h_flag, claripy.BVV(0x10, 8), claripy.BVV(0, 8))
        f = f | claripy.If(c_flag, claripy.BVV(0x01, 8), claripy.BVV(0, 8))
        self.state.regs.f = f
        self.jump(self._n)


def inputs(p: str) -> dict:
    i = symbolic_registers(p)
    i["offset"] = claripy.BVS(f"{p}_offset", 8)
    return i


def assembly(i: dict) -> list[E]:
    loc = symbol_location(SYMBOLS, "GetSelectedMoveOffset2")
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
    p.hook(q, GetSelectedMoveOffset2(DONE), length=8)
    s = p.factory.blank_state(addr=q)
    s.memory.store(OFFSET_RAM, i["offset"])
    set_assembly_registers(s, i)
    m = p.factory.simulation_manager(s)
    m.explore(find=DONE, num_find=1)
    assert len(m.found) == 1
    x = m.found[0]
    return [
        E(
            a=x.regs.a,
            b=x.regs.b,
            c=x.regs.c,
            d=x.regs.d,
            h=x.regs.h,
            l=x.regs.l,
            f=z80_flags_to_sm83(x.regs.f),
            constraints=tuple(x.solver.constraints),
        )
    ]


def native(i: dict) -> list[E]:
    p = angr.Project(NATIVE_ELF, auto_load_libs=False)
    fn = p.loader.find_symbol("port_get_selected_move_offset2")
    assert fn
    s = p.factory.call_state(fn.rebased_addr, NATIVE_STATE)
    store_native_registers(s, NATIVE_STATE, i)
    s.memory.store(NATIVE_STATE + 8, i["offset"])
    m = p.factory.simulation_manager(s)
    m.run()
    assert not m.errored
    x = m.deadended[0]
    nr = native_registers(x, NATIVE_STATE)
    return [
        E(
            a=nr["a"],
            b=nr["b"],
            c=nr["c"],
            d=nr["d"],
            h=nr["h"],
            l=nr["l"],
            f=nr["f"],
            constraints=tuple(x.solver.constraints),
        )
    ]


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native")
def test_transition_equivalence() -> None:
    i = inputs("gsmo")
    assert_pathwise_equivalent(assembly(i), native(i), ("a", "b", "c", "d", "h", "l", "f"))


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_exact_body() -> None:
    loc = symbol_location(SYMBOLS, "GetSelectedMoveOffset2")
    assert linked_bytes(ROM, loc, 8) == bytes.fromhex("fa26cc4f060009c9")
