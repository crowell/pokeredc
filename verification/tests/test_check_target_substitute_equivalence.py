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
WHOSE_TURN_RAM = 0xF3
ENEMY_STATUS2_RAM = 0xD068
PLAYER_STATUS2_RAM = 0xD063


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


class CheckTargetSubstitute(angr.SimProcedure):
    def __init__(self, n: int) -> None:
        super().__init__()
        self._n = n

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        # Model the whole CheckTargetSubstitute (bank 15) as one SimProcedure:
        #   a = whose_turn (HRAM $f3)
        #   status = (whose_turn == 0) ? enemy_status2 ($d068) : player_status2 ($d063)
        #   f = H | (Z if (status & 0x10) == 0)
        #   hl is pushed/popped (preserved) by the real function.
        wt = self.state.memory.load(WHOSE_TURN_RAM, 1)
        enemy = self.state.memory.load(ENEMY_STATUS2_RAM, 1)
        player = self.state.memory.load(PLAYER_STATUS2_RAM, 1)
        status = claripy.If(wt == 0, enemy, player)
        bit4_clear = (status & 0x10) == 0
        self.state.regs.a = wt
        f = claripy.BVV(0x10, 8) | claripy.If(bit4_clear, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        self.state.regs.f = f
        self.jump(self._n)


def inputs(p: str) -> dict:
    i = symbolic_registers(p)
    i["whose_turn"] = claripy.BVS(f"{p}_wt", 8)
    i["enemy_status2"] = claripy.BVS(f"{p}_es", 8)
    i["player_status2"] = claripy.BVS(f"{p}_ps", 8)
    return i


def assembly(i: dict) -> list[E]:
    loc = symbol_location(SYMBOLS, "CheckTargetSubstitute")
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
    p.hook(q, CheckTargetSubstitute(DONE), length=16)
    s = p.factory.blank_state(addr=q)
    s.memory.store(WHOSE_TURN_RAM, i["whose_turn"])
    s.memory.store(ENEMY_STATUS2_RAM, i["enemy_status2"])
    s.memory.store(PLAYER_STATUS2_RAM, i["player_status2"])
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
    fn = p.loader.find_symbol("port_check_target_substitute")
    assert fn
    s = p.factory.call_state(fn.rebased_addr, NATIVE_STATE)
    store_native_registers(s, NATIVE_STATE, i)
    s.memory.store(NATIVE_STATE + 8, i["whose_turn"])
    s.memory.store(NATIVE_STATE + 10, i["enemy_status2"])
    s.memory.store(NATIVE_STATE + 9, i["player_status2"])
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
    i = inputs("cts")
    assert_pathwise_equivalent(assembly(i), native(i), ("a", "f", "b", "c", "d", "e", "h", "l"))


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_exact_body() -> None:
    loc = symbol_location(SYMBOLS, "CheckTargetSubstitute")
    assert linked_bytes(ROM, loc, 16) == bytes.fromhex("e52168d0f0f3a728032163d0cb66e1c9")
