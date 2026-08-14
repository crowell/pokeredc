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
    assembly_registers,
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
W_PARTY_MON1_MOVES = 0xD173
W_WHICH_POKEMON = 0xCF92
PARTYMON_STRUCT_LENGTH = 0x2C
NUM_MOVES = 4
HM_MOVE_IDS = (0x0F, 0x13, 0x39, 0x46, 0x94)


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


class IsInArraySim(angr.SimProcedure):
    """Inline ``call IsInArray``: set the z80 carry flag iff the move in `a` is
    one of the HM move ids. `a` (the move) is left unchanged so the caller
    returns it on a match."""

    def __init__(self, next_address: int, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        a = self.state.regs.a
        carry = claripy.Or(
            *[a == claripy.BVV(hm, 8) for hm in HM_MOVE_IDS]
        )
        f = self.state.regs.f
        carry_bit = claripy.If(carry, claripy.BVV(0x01, 8), claripy.BVV(0x00, 8))
        self.state.regs.f = (f & claripy.BVV(0xFE, 8)) | carry_bit
        self.jump(self._next_address)


@lru_cache(maxsize=None)
def _move_inputs() -> tuple[claripy.ast.BV, ...]:
    # Shared across the asm and native endpoints so path constraints refer to
    # the same claripy variables (otherwise the comparator mis-pairs paths).
    return tuple(claripy.BVS(f"khmm_move{i}", 8) for i in range(NUM_MOVES))


def _store_inputs(state: angr.SimState) -> None:
    # The mon index is fixed (concrete) so the move-list base
    # (wPartyMon1Moves + PARTYMON_STRUCT_LENGTH * which) is a concrete address;
    # a wrong PARTYMON_STRUCT_LENGTH would make asm and native read different
    # bases and fail. The four moves remain symbolic and shared between the
    # two endpoints.
    which = claripy.BVV(1, 8)
    moves = _move_inputs()
    state.memory.store(W_WHICH_POKEMON, which)
    base = W_PARTY_MON1_MOVES + PARTYMON_STRUCT_LENGTH * 1
    for i in range(NUM_MOVES):
        state.memory.store(base + i, moves[i])


@dataclass(frozen=True)
class Endpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _assembly_endpoint(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "KnowsHMMove")
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
    state = project.factory.blank_state(addr=location.address)
    base = location.address
    project.hook(
        base + 0x0E,
        Sm83LoadAImmediate(W_WHICH_POKEMON, base + 0x11),
        length=3,
    )
    project.hook(base + 0x11, AddNTimesInline(base + 0x14), length=3)
    project.hook(
        base + 0x16,
        Sm83LoadAAtHlIncrement(base + 0x17),
        length=1,
    )
    project.hook(base + 0x1F, IsInArraySim(base + 0x22), length=3)
    _store_inputs(state)
    set_assembly_registers(state, inputs)
    state.regs.sp = claripy.BVV(GB_STACK, 16)
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    return [
        Endpoint(
            **assembly_registers(end),
            constraints=tuple(end.solver.constraints),
        )
        for end in returned
    ]


def _native_endpoint(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_knows_hm_move")
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
            **native_registers(end, NATIVE_STATE),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_knows_hm_move_symbolic_equivalence() -> None:
    inputs = symbolic_registers("khmm")
    assembly = _assembly_endpoint(inputs)
    native = _native_endpoint(inputs)
    assert_pathwise_equivalent(assembly, native, ("a",))


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_knows_hm_move_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "KnowsHMMove")
    expected = bytes.fromhex(
        "2173d1012c001806219eda012100fa92cfcd873a06042ae5c5214557110100"
        "cdab3dc1e1d80520eea7c9"
    )
    assert linked_bytes(ROM, location, len(expected)) == expected
