from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
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
AI_COUNT_RAM = 0xCCDF
AI_COUNT_OFF = 8


@dataclass(frozen=True)
class E:
    ai_count: claripy.ast.BV
    f: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class DecrementAICount(angr.SimProcedure):
    def __init__(self, n: int) -> None:
        super().__init__()
        self._n = n

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        # ld hl, $ccdf
        self.state.regs.hl = claripy.BVV(AI_COUNT_RAM, 16)
        # dec (hl)
        val = self.state.memory.load(AI_COUNT_RAM, 1)
        new = val - 1
        self.state.memory.store(AI_COUNT_RAM, new)
        z = new == 0
        # scf: f = C, clear N and H, keep Z from the decrement.
        self.state.regs.f = claripy.BVV(0x01, 8) | claripy.If(
            z, claripy.BVV(0x40, 8), claripy.BVV(0, 8)
        )
        self.jump(self._n)


def inputs(ai_count: claripy.ast.BV) -> dict:
    i = symbolic_registers("da")
    i["ai_count"] = ai_count
    return i


def assembly(i: dict) -> list[E]:
    loc = symbol_location(SYMBOLS, "DecrementAICount")
    # ld hl,$ccdf / dec (hl) / scf / ret  (5 bytes, bank 14).
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
    p.hook(q, DecrementAICount(DONE), length=5)
    s = p.factory.blank_state(addr=q)
    s.memory.store(AI_COUNT_RAM, i["ai_count"])
    set_assembly_registers(s, i)
    m = p.factory.simulation_manager(s)
    m.explore(find=DONE, num_find=1)
    assert len(m.found) == 1
    x = m.found[0]
    return [
        E(
            ai_count=x.memory.load(AI_COUNT_RAM, 1),
            f=z80_flags_to_sm83(x.regs.f),
            h=x.regs.h,
            l=x.regs.l,
            constraints=tuple(x.solver.constraints),
        )
    ]


def native(i: dict) -> list[E]:
    p = angr.Project(NATIVE_ELF, auto_load_libs=False)
    fn = p.loader.find_symbol("port_decrement_ai_count")
    assert fn is not None
    s = p.factory.call_state(fn.rebased_addr, NATIVE_STATE)
    store_native_registers(s, NATIVE_STATE, i)
    s.memory.store(NATIVE_STATE + AI_COUNT_OFF, i["ai_count"])
    m = p.factory.simulation_manager(s)
    m.run()
    assert not m.errored
    return [
        E(
            ai_count=x.memory.load(NATIVE_STATE + AI_COUNT_OFF, 1),
            f=x.memory.load(NATIVE_STATE + 1, 1),
            h=x.memory.load(NATIVE_STATE + 6, 1),
            l=x.memory.load(NATIVE_STATE + 7, 1),
            constraints=tuple(x.solver.constraints),
        )
        for x in m.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_transition_equivalence() -> None:
    ai_count = claripy.BVS("ai_count_in", 8)
    i = inputs(ai_count)
    assert_pathwise_equivalent(assembly(i), native(i), ("ai_count", "f", "h", "l"))


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_exact_body() -> None:
    loc = symbol_location(SYMBOLS, "DecrementAICount")
    assert linked_bytes(ROM, loc, 6) == bytes.fromhex("21dfcc3537c9")
