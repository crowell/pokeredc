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
    Sm83LoadAAtHlIncrement,
    Sm83LoadAImmediate,
)


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification" / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
GB_STACK = 0xD000
GB_RETURN = 0xFFFF
NATIVE_STATE = 0x100000

W_PLAYER_BATTLE_STATUS1 = 0xD062
W_PLAYER_BATTLE_STATUS2 = 0xD063
W_PLAYER_BATTLE_STATUS3 = 0xD064
W_BATTLE_MON_PP = 0xD02D
W_PARTY_MON1_PP = 0xD188
W_PLAYER_MON_NUMBER = 0xCC2F
W_PLAYER_MOVE_LIST_INDEX = 0xCC2E
PARTYMON_STRUCT_LENGTH = 0x2C
STRUGGLE = 0xA5

# The move index and party-mon number are fixed concrete so the PP addresses
# (wBattleMonPP + moveIndex, wPartyMon1PP + PARTYMON_STRUCT_LENGTH * which +
# moveIndex) are concrete and `dec [hl]` can run natively without a symbolic
# store address. The move id and the three battle-status bytes stay symbolic.
MOVE_INDEX = 2
WHICH = 0
DE_ADDR = 0xD100  # concrete address holding the used-move id

BATTLE_PP_ADDR = W_BATTLE_MON_PP + MOVE_INDEX
PARTY_PP_ADDR = W_PARTY_MON1_PP + PARTYMON_STRUCT_LENGTH * WHICH + MOVE_INDEX


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


@lru_cache(maxsize=None)
def _pp_inputs() -> tuple[claripy.ast.BV, ...]:
    # Symbolic inputs shared between the asm and native endpoints so path
    # constraints refer to the same claripy variables.
    return (
        claripy.BVS("dpp_move", 8),  # move id read from [de]
        claripy.BVS("dpp_status1", 8),  # wPlayerBattleStatus1
        claripy.BVS("dpp_status2", 8),  # wPlayerBattleStatus2
        claripy.BVS("dpp_status3", 8),  # wPlayerBattleStatus3
        claripy.BVS("dpp_battle_pp", 8),  # initial battle PP byte
        claripy.BVS("dpp_party_pp", 8),  # initial party PP byte
    )


def _store_inputs(state: angr.SimState) -> None:
    move, status1, status2, status3, battle_pp, party_pp = _pp_inputs()
    state.memory.store(DE_ADDR, move)
    state.memory.store(W_PLAYER_BATTLE_STATUS1, status1)
    state.memory.store(W_PLAYER_BATTLE_STATUS2, status2)
    state.memory.store(W_PLAYER_BATTLE_STATUS3, status3)
    state.memory.store(BATTLE_PP_ADDR, battle_pp)
    state.memory.store(PARTY_PP_ADDR, party_pp)
    # concrete move index / party-mon number -> concrete PP addresses
    state.memory.store(W_PLAYER_MOVE_LIST_INDEX, claripy.BVV(MOVE_INDEX, 8))
    state.memory.store(W_PLAYER_MON_NUMBER, claripy.BVV(WHICH, 8))


@dataclass(frozen=True)
class Endpoint:
    m_battle_pp: claripy.ast.BV
    m_party_pp: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _assembly_endpoint(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "DecrementPP")
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
    # ld a, [hli] (0x2A) reads wPlayerBattleStatus1 and advances hl.
    project.hook(base + 0x07, Sm83LoadAAtHlIncrement(base + 0x08), length=1)
    # ld a, [a16] (0xFA) loads are shimmed (absent from the z80 decoder).
    project.hook(
        base + 0x14,
        Sm83LoadAImmediate(W_PLAYER_BATTLE_STATUS3, base + 0x17),
        length=3,
    )
    project.hook(
        base + 0x1D,
        Sm83LoadAImmediate(W_PLAYER_MON_NUMBER, base + 0x20),
        length=3,
    )
    project.hook(base + 0x23, AddNTimesInline(base + 0x26), length=3)
    project.hook(
        base + 0x26,
        Sm83LoadAImmediate(W_PLAYER_MOVE_LIST_INDEX, base + 0x29),
        length=3,
    )
    state = project.factory.blank_state(addr=base)
    _store_inputs(state)
    set_assembly_registers(state, inputs)
    state.regs.sp = claripy.BVV(GB_STACK, 16)
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    return [
        Endpoint(
            m_battle_pp=end.memory.load(BATTLE_PP_ADDR, 1),
            m_party_pp=end.memory.load(PARTY_PP_ADDR, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in returned
    ]


def _native_endpoint(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_decrement_pp")
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, claripy.BVV(0, 64)
    )
    store_native_registers(state, NATIVE_STATE, inputs)
    _store_inputs(state)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            m_battle_pp=end.memory.load(BATTLE_PP_ADDR, 1),
            m_party_pp=end.memory.load(PARTY_PP_ADDR, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_decrement_pp_symbolic_equivalence() -> None:
    inputs = symbolic_registers("dpp")
    # `de` must be concrete so `ld a, [de]` reads a fixed address.
    inputs["d"] = claripy.BVV(DE_ADDR >> 8, 8)
    inputs["e"] = claripy.BVV(DE_ADDR & 0xFF, 8)
    assembly = _assembly_endpoint(inputs)
    native = _native_endpoint(inputs)
    assert_pathwise_equivalent(assembly, native, ("m_battle_pp", "m_party_pp"))


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_decrement_pp_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "DecrementPP")
    expected = bytes.fromhex(
        "1afea5c82162d02ae607c0cb76c0212dd0cd2640fa64d0cb5fc02188d1"
        "fa2fcc012c00cd873afa2ecc4f06000935c9"
    )
    assert linked_bytes(ROM, location, len(expected)) == expected
