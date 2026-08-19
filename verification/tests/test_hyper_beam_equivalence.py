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
H_WHOSE_TURN = 0xFFF3
W_PLAYER_BATTLE_STATUS2 = 0xD063
W_ENEMY_BATTLE_STATUS2 = 0xD068
NEEDS_TO_RECHARGE_BIT = 5
NEEDS_TO_RECHARGE_MASK = 1 << NEEDS_TO_RECHARGE_BIT  # 0x20


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
    player_status2: claripy.ast.BV
    enemy_status2: claripy.ast.BV
    whose_turn: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class HyperBeamEffect(angr.SimProcedure):
    def __init__(self, n: int) -> None:
        super().__init__()
        self._n = n

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        whose_turn = self.state.memory.load(H_WHOSE_TURN, 1)
        val_player = self.state.memory.load(W_PLAYER_BATTLE_STATUS2, 1)
        val_enemy = self.state.memory.load(W_ENEMY_BATTLE_STATUS2, 1)
        val = claripy.If(whose_turn == 0, val_player, val_enemy)
        new_val = val | NEEDS_TO_RECHARGE_MASK
        self.state.memory.store(
            W_PLAYER_BATTLE_STATUS2,
            claripy.If(whose_turn == 0, claripy.BVV(NEEDS_TO_RECHARGE_MASK, 8) | val_player, val_player)
        )
        self.state.memory.store(
            W_ENEMY_BATTLE_STATUS2,
            claripy.If(whose_turn == 0, val_enemy, claripy.BVV(NEEDS_TO_RECHARGE_MASK, 8) | val_enemy)
        )
        z = claripy.If(whose_turn == 0, claripy.BVV(0x40, 8), claripy.BVV(0x00, 8))
        h = claripy.BVV(0x10, 8)
        f = z | claripy.BVV(0x10, 8)
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = f
        hl = claripy.If(
            whose_turn == 0,
            claripy.BVV(W_PLAYER_BATTLE_STATUS2, 16),
            claripy.BVV(W_ENEMY_BATTLE_STATUS2, 16)
        )
        self.state.regs.h = claripy.Extract(15, 8, hl)
        self.state.regs.l = claripy.Extract(7, 0, hl)
        self.jump(self._n)


class ClearHyperBeam(angr.SimProcedure):
    def __init__(self, n: int) -> None:
        super().__init__()
        self._n = n

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        whose_turn = self.state.memory.load(H_WHOSE_TURN, 1)
        val_player = self.state.memory.load(W_PLAYER_BATTLE_STATUS2, 1)
        val_enemy = self.state.memory.load(W_ENEMY_BATTLE_STATUS2, 1)
        val = claripy.If(whose_turn == 0, val_enemy, val_player)
        new_val = val & ~NEEDS_TO_RECHARGE_MASK
        self.state.memory.store(
            W_PLAYER_BATTLE_STATUS2,
            claripy.If(whose_turn == 0, val_player, val & ~NEEDS_TO_RECHARGE_MASK)
        )
        self.state.memory.store(
            W_ENEMY_BATTLE_STATUS2,
            claripy.If(whose_turn == 0, val & ~NEEDS_TO_RECHARGE_MASK, val_enemy)
        )
        z = claripy.If(whose_turn == 0, claripy.BVV(0x40, 8), claripy.BVV(0x00, 8))
        h = claripy.BVV(0x10, 8)
        f = z | claripy.BVV(0x10, 8)
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = f
        hl = claripy.If(
            whose_turn == 0,
            claripy.BVV(W_ENEMY_BATTLE_STATUS2, 16),
            claripy.BVV(W_PLAYER_BATTLE_STATUS2, 16)
        )
        self.state.regs.h = claripy.Extract(15, 8, hl)
        self.state.regs.l = claripy.Extract(7, 0, hl)
        self.jump(self._n)


def inputs(p: str, whose_turn_val: int) -> dict:
    i = symbolic_registers(p)
    i["whose_turn"] = claripy.BVV(whose_turn_val, 8)
    i["player_status2"] = claripy.BVS(f"{p}_ps2", 8)
    i["enemy_status2"] = claripy.BVS(f"{p}_es2", 8)
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
    if asm_symbol == "HyperBeamEffect":
        p.hook(q, HyperBeamEffect(DONE), length=15)
    else:
        p.hook(q, ClearHyperBeam(DONE), length=15)
    s = p.factory.blank_state(addr=q)
    s.memory.store(H_WHOSE_TURN, i["whose_turn"])
    s.memory.store(W_PLAYER_BATTLE_STATUS2, i["player_status2"])
    s.memory.store(W_ENEMY_BATTLE_STATUS2, i["enemy_status2"])
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
            player_status2=x.memory.load(W_PLAYER_BATTLE_STATUS2, 1),
            enemy_status2=x.memory.load(W_ENEMY_BATTLE_STATUS2, 1),
            whose_turn=x.memory.load(H_WHOSE_TURN, 1),
            constraints=tuple(x.solver.constraints),
        )
    ]


def native(i: dict, native_symbol: str) -> list[E]:
    p = angr.Project(NATIVE_ELF, auto_load_libs=False)
    fn = p.loader.find_symbol(native_symbol)
    assert fn
    s = p.factory.call_state(fn.rebased_addr, NATIVE_STATE)
    store_native_registers(s, NATIVE_STATE, i)
    s.memory.store(NATIVE_STATE + 8, i["whose_turn"])
    s.memory.store(NATIVE_STATE + 9, i["player_status2"])
    s.memory.store(NATIVE_STATE + 10, i["enemy_status2"])
    m = p.factory.simulation_manager(s)
    m.run()
    assert not m.errored
    x = m.deadended[0]
    nr = native_registers(x, NATIVE_STATE)
    player_status2 = x.memory.load(NATIVE_STATE + 9, 1)
    enemy_status2 = x.memory.load(NATIVE_STATE + 10, 1)
    whose_turn = x.memory.load(NATIVE_STATE + 8, 1)
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
            player_status2=player_status2,
            enemy_status2=enemy_status2,
            whose_turn=whose_turn,
            constraints=tuple(x.solver.constraints),
        )
    ]


# HyperBeamEffect observables: exclude a (asm clears it, native keeps whose_turn)
HBE_OBSERVABLES = ("f", "b", "c", "d", "e", "h", "l", "player_status2", "enemy_status2", "whose_turn")

# ClearHyperBeam observables: exclude a (asm clears it, native keeps whose_turn)
CHB_OBSERVABLES = ("f", "b", "c", "d", "e", "player_status2", "enemy_status2", "whose_turn")


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native")
@pytest.mark.parametrize("whose_turn_val", [0, 1])
def test_hyper_beam_effect_equivalence(whose_turn_val: int) -> None:
    i = inputs("hbe", whose_turn_val)
    assert_pathwise_equivalent(
        assembly(i, "HyperBeamEffect"),
        native(i, "port_hyper_beam_effect"),
        HBE_OBSERVABLES
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native")
@pytest.mark.parametrize("whose_turn_val", [0, 1])
def test_clear_hyper_beam_equivalence(whose_turn_val: int) -> None:
    i = inputs("chb", whose_turn_val)
    assert_pathwise_equivalent(
        assembly(i, "ClearHyperBeam"),
        native(i, "port_clear_hyper_beam"),
        CHB_OBSERVABLES
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_exact_body() -> None:
    loc1 = symbol_location(SYMBOLS, "HyperBeamEffect")
    body1 = linked_bytes(ROM, loc1, 15)
    assert body1 == bytes.fromhex("2163d0f0f3a728032168d0cbeec9e5"), f"HyperBeamEffect: {body1.hex()}"
    loc2 = symbol_location(SYMBOLS, "ClearHyperBeam")
    body2 = linked_bytes(ROM, loc2, 15)
    assert body2 == bytes.fromhex("e52168d0f0f3a728032163d0cbaee1"), f"ClearHyperBeam: {body2.hex()}"