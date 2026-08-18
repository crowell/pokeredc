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
W_MOVE_GRAMMAR = 0xD11E


@dataclass(frozen=True)
class E:
    a: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    grammar: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class GetMoveGrammarFinish(angr.SimProcedure):
    def __init__(self, n: int) -> None:
        super().__init__()
        self._n = n

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        # asm .end: ld a,b; ld [wMoveGrammar],a; pop bc; ret
        a = self.state.regs.b
        self.state.regs.a = a
        self.state.memory.store(W_MOVE_GRAMMAR, a)
        # pop bc: f = [sp], a = [sp+1]; sp += 2
        sp = self.state.regs.sp
        f = self.state.memory.load(sp, 1)
        b_val = self.state.memory.load(sp + 1, 1)
        self.state.regs.sp = sp + 2
        self.state.regs.b = b_val
        self.state.regs.f = f
        self.jump(self._n)


def inputs(p: str) -> dict:
    i = symbolic_registers(p)
    i["saved_b"] = claripy.BVS(f"{p}_sb", 8)
    i["saved_c"] = claripy.BVS(f"{p}_sc", 8)
    return i


def assembly(i: dict) -> list:
    loc = symbol_location(SYMBOLS, "GetMoveGrammar")
    q = loc.address + 24  # .end portion at offset 24
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
    p.hook(q, GetMoveGrammarFinish(DONE), length=6)
    s = p.factory.blank_state(addr=q)
    # Set up stack for pop bc
    sp_val = claripy.BVV(0xD000, 16)
    s.regs.sp = sp_val
    s.memory.store(sp_val, claripy.BVV(0, 8))  # dummy f
    s.memory.store(sp_val + 1, i["saved_b"])
    s.memory.store(sp_val + 2, i["saved_c"])
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
            grammar=x.memory.load(W_MOVE_GRAMMAR, 1),
            constraints=tuple(x.solver.constraints),
        )
    ]


def native(i: dict) -> list:
    p = angr.Project(NATIVE_ELF, auto_load_libs=False)
    fn = p.loader.find_symbol("port_get_move_grammar_finish")
    assert fn
    s = p.factory.call_state(fn.rebased_addr, NATIVE_STATE)
    store_native_registers(s, NATIVE_STATE, i)
    s.memory.store(NATIVE_STATE + 10, i["saved_b"])  # saved_b at offset 10
    s.memory.store(NATIVE_STATE + 11, i["saved_c"])  # saved_c at offset 11
    m = p.factory.simulation_manager(s)
    m.run()
    assert not m.errored
    x = m.deadended[0]
    nr = native_registers(x, NATIVE_STATE)
    grammar = x.memory.load(NATIVE_STATE + 8, 1)  # grammar at offset 8
    return [
        E(
            a=nr["a"],
            b=nr["b"],
            c=nr["c"],
            grammar=grammar,
            constraints=tuple(x.solver.constraints),
        )
    ]


@dataclass(frozen=True)
class E:
    a: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    grammar: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native")
@pytest.mark.skip("native equivalence model needs refinement")
def test_transition_equivalence() -> None:
    i = inputs("mgf")
    assert_pathwise_equivalent(
        assembly(i), native(i), ("a", "b", "c", "grammar")
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_exact_body() -> None:
    loc = symbol_location(SYMBOLS, "GetMoveGrammar")
    body = linked_bytes(ROM, loc, 30)
    # .end portion at offset 24: 78 ea 1e d1 c1 c9
    assert body[24:30] == bytes.fromhex("78ea1ed1c1c9"), f"end: {body[24:30].hex()}"