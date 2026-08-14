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
    Sm83LoadAImmediate,
    Sm83StoreAImmediate,
    Sm83ResAtHl,
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

W_ENEMY_MON_PARTY_POS = 0xCFE8
W_ENEMY_MON1_STATUS = 0xD8A8
W_ENEMY_MON_STATUS = 0xCFE9
W_ENEMY_BATTLE_STATUS3 = 0xD069
PARTYMON_STRUCT_LENGTH = 0x2C

# Party position kept concrete so the roster status address (wEnemyMon1Status +
# PARTYMON_STRUCT_LENGTH * partyPos) is concrete and `ld [hl],a` runs natively.
PARTY_POS = 0
ROSTER_ADDR = W_ENEMY_MON1_STATUS + PARTYMON_STRUCT_LENGTH * PARTY_POS
ACTIVE_ADDR = W_ENEMY_MON_STATUS
BATTLE3_ADDR = W_ENEMY_BATTLE_STATUS3


@lru_cache(maxsize=None)
def _pp_inputs() -> tuple[claripy.ast.BV, ...]:
    # Symbolic byte inputs shared between the asm and native endpoints so the
    # path comparator pairs the same initial values.
    return (
        claripy.BVS("aic_roster", 8),  # enemy team roster status byte
        claripy.BVS("aic_active", 8),  # active enemy status byte
        claripy.BVS("aic_battle3", 8),  # wEnemyBattleStatus3 byte
    )


def _store_inputs(state: angr.SimState) -> None:
    roster, active, battle3 = _pp_inputs()
    state.memory.store(W_ENEMY_MON_PARTY_POS, claripy.BVV(PARTY_POS, 8))
    state.memory.store(ROSTER_ADDR, roster)
    state.memory.store(ACTIVE_ADDR, active)
    state.memory.store(BATTLE3_ADDR, battle3)


@dataclass(frozen=True)
class Endpoint:
    m_roster: claripy.ast.BV
    m_active: claripy.ast.BV
    m_battle3: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _assembly_endpoint(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "AICureStatus")
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
    # ld a, [a16] (0xFA) load is shimmed (absent from the z80 decoder).
    project.hook(base + 0x00, Sm83LoadAImmediate(W_ENEMY_MON_PARTY_POS, base + 0x03), length=3)
    # call AddNTimes is modeled as hl = hl + bc*a.
    project.hook(base + 0x09, AddNTimesInline(base + 0x0C), length=3)
    # ld [a16], a (0xEA) store is shimmed (absent from the z80 decoder).
    project.hook(base + 0x0E, Sm83StoreAImmediate(W_ENEMY_MON_STATUS, base + 0x11), length=3)
    # res BADLY_POISONED, [hl] (0xCB 0x86) is shimmed.
    project.hook(base + 0x14, Sm83ResAtHl(0, base + 0x16), length=2)
    state = project.factory.blank_state(addr=base)
    _store_inputs(state)
    set_assembly_registers(state, inputs)
    state.regs.sp = claripy.BVV(0xE000, 16)
    state.memory.store(0xE000, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    return [
        Endpoint(
            m_roster=end.memory.load(ROSTER_ADDR, 1),
            m_active=end.memory.load(ACTIVE_ADDR, 1),
            m_battle3=end.memory.load(BATTLE3_ADDR, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in returned
    ]


def _native_endpoint(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_ai_cure_status")
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
            m_roster=end.memory.load(ROSTER_ADDR, 1),
            m_active=end.memory.load(ACTIVE_ADDR, 1),
            m_battle3=end.memory.load(BATTLE3_ADDR, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_ai_cure_status_symbolic_equivalence() -> None:
    inputs = symbolic_registers("aic")
    assembly = _assembly_endpoint(inputs)
    native = _native_endpoint(inputs)
    assert_pathwise_equivalent(
        assembly,
        native,
        ("m_roster", "m_active", "m_battle3"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_ai_cure_status_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "AICureStatus")
    expected = bytes.fromhex(
        "fae8cf21a8d8012c00cd873aaf77eae9cf2169d0cb86c9"
    )
    assert linked_bytes(ROM, location, len(expected)) == expected
