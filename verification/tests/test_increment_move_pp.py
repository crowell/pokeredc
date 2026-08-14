from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
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
    collect_returns,
    linked_bytes,
    rom_window,
    symbol_location,
)
from verification.harness.sm83_shims import (
    Sm83LoadAHighImmediate,
    Sm83LoadAImmediate,
)


class AddNTimesInline(angr.SimProcedure):
    """Model ``call AddNTimes``: hl = hl + bc * a (a = 0 leaves hl unchanged),
    a = 0, b/c preserved."""

    def __init__(self, next_address: int, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        state = self.state
        a = state.regs.a
        bc = claripy.ZeroExt(8, state.regs.c) | (claripy.ZeroExt(8, state.regs.b) << 8)
        hl = claripy.ZeroExt(8, state.regs.l) | (claripy.ZeroExt(8, state.regs.h) << 8)
        new_hl = (hl + bc * claripy.ZeroExt(8, a)) & 0xFFFF
        state.regs.a = claripy.BVV(0, 8)
        state.regs.h = claripy.Extract(15, 8, new_hl)
        state.regs.l = claripy.Extract(7, 0, new_hl)
        self.jump(self._next_address)


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification" / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
GB_RETURN = 0xFFFF
NATIVE_STATE = 0x100000
# Local stack base: the enemy-turn battle-PP address (wEnemyMonPP + MOVE_INDEX)
# collides with the usual 0xD000 stack, so the assembly side uses 0xE000.
GB_STACK = 0xE000

H_WHOSE_TURN = 0xFFF3
W_BATTLE_MON_PP = 0xD02D
W_PARTY_MON1_PP = 0xD188
W_ENEMY_MON_PP = 0xCFFE
W_ENEMY_MON1_PP = 0xD8C1
W_PLAYER_MOVE_LIST_INDEX = 0xCC2E
W_PLAYER_MON_NUMBER = 0xCC2F
W_ENEMY_MOVE_LIST_INDEX = 0xCCE2
W_ENEMY_MON_PARTY_POS = 0xCFE8
PARTYMON_STRUCT_LENGTH = 0x2C

# Move index and party-mon number are fixed concrete so the PP addresses are
# concrete and `inc [hl]` can run natively without a symbolic store address.
# hWhoseTurn (the player/enemy selector) is also concrete; the proof is run
# once per turn so both branches are verified without a symbolic base address.
MOVE_INDEX = 2
WHICH = 0

PLAYER_BATTLE_PP_ADDR = W_BATTLE_MON_PP + MOVE_INDEX
PLAYER_PARTY_PP_ADDR = W_PARTY_MON1_PP + PARTYMON_STRUCT_LENGTH * WHICH + MOVE_INDEX
ENEMY_BATTLE_PP_ADDR = W_ENEMY_MON_PP + MOVE_INDEX
ENEMY_PARTY_PP_ADDR = W_ENEMY_MON1_PP + PARTYMON_STRUCT_LENGTH * WHICH + MOVE_INDEX


@lru_cache(maxsize=None)
def _pp_inputs() -> tuple[claripy.ast.BV, ...]:
    # Symbolic byte values shared between the asm and native endpoints so the
    # path comparator pairs the same initial PP variables.
    return (
        claripy.BVS("imp_pb_pp", 8),  # player battle PP byte
        claripy.BVS("imp_pp_pp", 8),  # player party PP byte
        claripy.BVS("imp_eb_pp", 8),  # enemy battle PP byte
        claripy.BVS("imp_ep_pp", 8),  # enemy party PP byte
    )


def _store_inputs(state: angr.SimState, whose: int) -> None:
    pb, pp, eb, ep = _pp_inputs()
    state.memory.store(H_WHOSE_TURN, claripy.BVV(whose, 8))
    state.memory.store(PLAYER_BATTLE_PP_ADDR, pb)
    state.memory.store(PLAYER_PARTY_PP_ADDR, pp)
    state.memory.store(ENEMY_BATTLE_PP_ADDR, eb)
    state.memory.store(ENEMY_PARTY_PP_ADDR, ep)
    # concrete move index / party-mon number -> concrete PP addresses
    state.memory.store(W_PLAYER_MOVE_LIST_INDEX, claripy.BVV(MOVE_INDEX, 8))
    state.memory.store(W_PLAYER_MON_NUMBER, claripy.BVV(WHICH, 8))
    state.memory.store(W_ENEMY_MOVE_LIST_INDEX, claripy.BVV(MOVE_INDEX, 8))
    state.memory.store(W_ENEMY_MON_PARTY_POS, claripy.BVV(WHICH, 8))


@dataclass(frozen=True)
class Endpoint:
    m_player_battle_pp: claripy.ast.BV
    m_player_party_pp: claripy.ast.BV
    m_enemy_battle_pp: claripy.ast.BV
    m_enemy_party_pp: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _assembly_endpoint(inputs: dict[str, claripy.ast.BV], whose: int) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "IncrementMovePP")
    project = angr.Project(
        rom_window(ROM, location.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": location.address,
        },
    )
    base = location.address
    # ldh a, [a8] (0xF0) loads from high RAM; absent from the z80 decoder.
    project.hook(base + 0x00, Sm83LoadAHighImmediate(0xF3, base + 0x02), length=2)
    # ld a, [a16] (0xFA) loads are shimmed (absent from the z80 decoder).
    project.hook(
        base + 0x09,
        Sm83LoadAImmediate(W_PLAYER_MOVE_LIST_INDEX, base + 0x0C),
        length=3,
    )
    project.hook(
        base + 0x14,
        Sm83LoadAImmediate(W_ENEMY_MOVE_LIST_INDEX, base + 0x17),
        length=3,
    )
    project.hook(base + 0x1F, Sm83LoadAHighImmediate(0xF3, base + 0x21), length=2)
    project.hook(
        base + 0x22,
        Sm83LoadAImmediate(W_PLAYER_MON_NUMBER, base + 0x25),
        length=3,
    )
    project.hook(
        base + 0x27,
        Sm83LoadAImmediate(W_ENEMY_MON_PARTY_POS, base + 0x2A),
        length=3,
    )
    project.hook(base + 0x2D, AddNTimesInline(base + 0x30), length=3)
    state = project.factory.blank_state(addr=base)
    _store_inputs(state, whose)
    set_assembly_registers(state, inputs)
    state.regs.sp = claripy.BVV(GB_STACK, 16)
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    return [
        Endpoint(
            m_player_battle_pp=end.memory.load(PLAYER_BATTLE_PP_ADDR, 1),
            m_player_party_pp=end.memory.load(PLAYER_PARTY_PP_ADDR, 1),
            m_enemy_battle_pp=end.memory.load(ENEMY_BATTLE_PP_ADDR, 1),
            m_enemy_party_pp=end.memory.load(ENEMY_PARTY_PP_ADDR, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in returned
    ]


def _native_endpoint(inputs: dict[str, claripy.ast.BV], whose: int) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_increment_move_pp")
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, claripy.BVV(0, 64)
    )
    store_native_registers(state, NATIVE_STATE, inputs)
    _store_inputs(state, whose)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            m_player_battle_pp=end.memory.load(PLAYER_BATTLE_PP_ADDR, 1),
            m_player_party_pp=end.memory.load(PLAYER_PARTY_PP_ADDR, 1),
            m_enemy_battle_pp=end.memory.load(ENEMY_BATTLE_PP_ADDR, 1),
            m_enemy_party_pp=end.memory.load(ENEMY_PARTY_PP_ADDR, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_increment_move_pp_symbolic_equivalence() -> None:
    inputs = symbolic_registers("imp")
    for whose in (0, 1):
        assembly = _assembly_endpoint(inputs, whose)
        native = _native_endpoint(inputs, whose)
        assert_pathwise_equivalent(
            assembly,
            native,
            (
                "m_player_battle_pp",
                "m_player_party_pp",
                "m_enemy_battle_pp",
                "m_enemy_party_pp",
            ),
        )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_increment_move_pp_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "IncrementMovePP")
    expected = bytes.fromhex(
        "f0f3a7212dd01188d1fa2ecc280921fecf11c1d8fae2cc06004f093462"
        "6b09f0f3a7fa2fcc2803fae8cf012c00cd873a34c9"
    )
    assert linked_bytes(ROM, location, len(expected)) == expected
