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
    sm83_flags_to_z80,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
DONE = 0xEFFF
H_WHOSE_TURN = 0xFFF3


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
    whose_turn: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class CallWithTurnFlippedReturn(angr.SimProcedure):
    def __init__(self, n: int) -> None:
        super().__init__()
        self._n = n

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        # asm: pop af; ldh [hWhoseTurn], a; ret
        # pop af: f = [sp], a = [sp+1]; sp += 2
        sp = self.state.regs.sp
        f = self.state.memory.load(sp, 1)
        a = self.state.memory.load(sp + 1, 1)
        self.state.regs.sp = sp + 2
        self.state.regs.a = a
        self.state.regs.f = f
        # ldh [hWhoseTurn], a
        self.state.memory.store(H_WHOSE_TURN, a)
        self.jump(self._n)


def inputs(p: str) -> dict:
    i = symbolic_registers(p)
    i["saved_a"] = claripy.BVS(f"{p}_sa", 8)
    i["saved_f"] = claripy.BVS(f"{p}_sf", 8)
    return i


def assembly(i: dict) -> list[E]:
    loc = symbol_location(SYMBOLS, "CallWithTurnFlipped")
    q = loc.address + 12  # return portion at offset 12
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
    p.hook(q, CallWithTurnFlippedReturn(DONE), length=4)
    s = p.factory.blank_state(addr=q)
    # Set up stack with saved_f, saved_a (pop af pops f first, then a)
    # Convert saved_f from SM83 (native layout) to Z80 (asm layout)
    saved_f_z80 = sm83_flags_to_z80(i["saved_f"])
    sp_val = claripy.BVV(0xD000, 16)
    s.regs.sp = sp_val
    s.memory.store(sp_val, saved_f_z80)
    s.memory.store(sp_val + 1, i["saved_a"])
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
            whose_turn=x.memory.load(H_WHOSE_TURN, 1),
            constraints=tuple(x.solver.constraints),
        )
    ]


def native(i: dict) -> list[E]:
    p = angr.Project(NATIVE_ELF, auto_load_libs=False)
    fn = p.loader.find_symbol("port_call_with_turn_flipped_return")
    assert fn
    s = p.factory.call_state(fn.rebased_addr, NATIVE_STATE)
    store_native_registers(s, NATIVE_STATE, i)
    s.memory.store(NATIVE_STATE + 9, i["saved_a"])  # saved_a at offset 9
    s.memory.store(NATIVE_STATE + 10, i["saved_f"])  # saved_f at offset 10
    m = p.factory.simulation_manager(s)
    m.run()
    assert not m.errored
    x = m.deadended[0]
    nr = native_registers(x, NATIVE_STATE)
    whose_turn = x.memory.load(NATIVE_STATE + 8, 1)  # whose_turn at offset 8
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
            whose_turn=whose_turn,
            constraints=tuple(x.solver.constraints),
        )
    ]


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native")
def test_transition_equivalence() -> None:
    i = inputs("ctf")
    assert_pathwise_equivalent(
        assembly(i), native(i), ("a", "b", "c", "d", "e", "h", "l", "whose_turn")
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_exact_body() -> None:
    loc = symbol_location(SYMBOLS, "CallWithTurnFlipped")
    body = linked_bytes(ROM, loc, 16)
    assert body[12:16] == bytes.fromhex("f1e0f3c9"), f"return: {body[12:16].hex()}"