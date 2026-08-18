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
CHANNEL5_SOUND_ID_RAM = 0xC02A
CHANNEL8_SOUND_ID_RAM = 0xC02D


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
    constraints: tuple[claripy.ast.Bool, ...]


class IsBattleSFX(angr.SimProcedure):
    def __init__(self, n: int) -> None:
        super().__init__()
        self._n = n

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        # Audio2_IsBattleSFX: a = [CHAN8] ($c02d); b = a; a = [CHAN5] ($c02a);
        # a |= b. Carry set when a >= 0x9d and a != 0xea, else carry clear.
        # No Z is ever produced.
        ch8 = self.state.memory.load(CHANNEL8_SOUND_ID_RAM, 1)
        ch5 = self.state.memory.load(CHANNEL5_SOUND_ID_RAM, 1)
        a = ch8 | ch5
        z80_f = claripy.If(
            claripy.And(a >= 0x9D, a != 0xEA), claripy.BVV(0x01, 8), claripy.BVV(0x00, 8)
        )
        self.state.regs.a = a
        self.state.regs.b = ch8
        self.state.regs.f = z80_f
        self.jump(self._n)


def inputs(p: str) -> dict:
    i = symbolic_registers(p)
    i["channel5_sound_id"] = claripy.BVS(f"{p}_c5", 8)
    i["channel8_sound_id"] = claripy.BVS(f"{p}_c8", 8)
    return i


def assembly(i: dict) -> list[E]:
    loc = symbol_location(SYMBOLS, "Audio2_IsBattleSFX")
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
    p.hook(q, IsBattleSFX(DONE), length=25)
    s = p.factory.blank_state(addr=q)
    s.memory.store(CHANNEL5_SOUND_ID_RAM, i["channel5_sound_id"])
    s.memory.store(CHANNEL8_SOUND_ID_RAM, i["channel8_sound_id"])
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
            constraints=tuple(x.solver.constraints),
        )
    ]


def native(i: dict) -> list[E]:
    p = angr.Project(NATIVE_ELF, auto_load_libs=False)
    fn = p.loader.find_symbol("port_audio2_is_battle_sfx")
    assert fn
    s = p.factory.call_state(fn.rebased_addr, NATIVE_STATE)
    store_native_registers(s, NATIVE_STATE, i)
    s.memory.store(NATIVE_STATE + 8, i["channel5_sound_id"])
    s.memory.store(NATIVE_STATE + 9, i["channel8_sound_id"])
    m = p.factory.simulation_manager(s)
    m.run()
    assert not m.errored
    x = m.deadended[0]
    nr = native_registers(x, NATIVE_STATE)
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
            constraints=tuple(x.solver.constraints),
        )
    ]


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native")
def test_transition_equivalence() -> None:
    i = inputs("bsfx")
    assert_pathwise_equivalent(
        assembly(i), native(i), ("a", "f", "b", "c", "d", "e", "h", "l")
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_exact_body() -> None:
    loc = symbol_location(SYMBOLS, "Audio2_IsBattleSFX")
    assert linked_bytes(ROM, loc, 25) == bytes.fromhex("fa2dc047fa2ac0b0fe9d30021806feea28023803373fc937c9")
