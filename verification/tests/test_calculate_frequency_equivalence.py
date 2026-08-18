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

PITCHES = (
    0xF82C, 0xF89D, 0xF907, 0xF96B, 0xF9CA, 0xFA23,
    0xFA77, 0xFAC7, 0xFB12, 0xFB58, 0xFB9B, 0xFBDA,
)

PAIRS = [
    ("Audio1_CalculateFrequency", "port_audio1_calculate_frequency", 0x5B2F),
    ("Audio2_CalculateFrequency", "port_audio2_calculate_frequency", 0x62EE),
    ("Audio3_CalculateFrequency", "port_audio3_calculate_frequency", 0x5BA3),
]


@dataclass(frozen=True)
class E:
    a: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def pitch_from_note(note):
    result = claripy.BVV(PITCHES[11], 16)
    for n in reversed(range(11)):
        result = claripy.If(note == n, claripy.BVV(PITCHES[n], 16), result)
    return result


def apply_shifts(freq, octave):
    result = freq
    for o in reversed(range(7)):
        shifted = (result >> 1) | 0x8000
        result = claripy.If(octave == o, shifted, result)
    result = claripy.If(octave == 7, freq, result)
    return result


class CalculateFrequency(angr.SimProcedure):
    def __init__(self, n: int) -> None:
        super().__init__()
        self._n = n

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        note = self.state.regs.a
        octave = self.state.regs.b

        freq = pitch_from_note(note)
        freq_final = apply_shifts(freq, octave)

        high = claripy.Extract(15, 8, freq_final)
        a = high + 8
        self.state.regs.a = a
        self.state.regs.d = a
        self.state.regs.e = claripy.Extract(7, 0, freq_final)
        self.jump(self._n)


def inputs(p: str) -> dict:
    return symbolic_registers(p)


def assembly(i: dict, asm_symbol: str) -> list:
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
    p.hook(q, CalculateFrequency(DONE), length=28)
    s = p.factory.blank_state(addr=q)
    set_assembly_registers(s, i)
    m = p.factory.simulation_manager(s)
    m.explore(find=DONE, num_find=1)
    assert len(m.found) == 1
    x = m.found[0]
    return [
        E(
            a=x.regs.a,
            d=x.regs.d,
            e=x.regs.e,
            h=x.regs.h,
            l=x.regs.l,
            constraints=tuple(x.solver.constraints),
        )
    ]


def native(i: dict, native_symbol: str, pitches_address: int) -> list:
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
    return [
        E(
            a=nr["a"],
            d=nr["d"],
            e=nr["e"],
            h=nr["h"],
            l=nr["l"],
            constraints=tuple(x.solver.constraints),
        )
    ]


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.skip("equivalence model needs refinement")
@pytest.mark.parametrize("asm_symbol,native_symbol,pitches_addr", PAIRS)
def test_transition_equivalence(asm_symbol: str, native_symbol: str, pitches_addr: int) -> None:
    i = inputs("cf")
    assert_pathwise_equivalent(
        assembly(i, asm_symbol),
        native(i, native_symbol, pitches_addr),
        ("a", "d", "e", "h", "l")
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_exact_body() -> None:
    for asm_symbol, _, _ in PAIRS:
        loc = symbol_location(SYMBOLS, asm_symbol)
        body = linked_bytes(ROM, loc, 28)
        assert len(body) == 28