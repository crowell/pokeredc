from __future__ import annotations

from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
    REGISTERS,
    assembly_registers,
    native_registers,
    set_assembly_registers,
    store_native_registers,
    symbolic_registers,
)
from verification.harness.rom import collect_returns, linked_bytes, rom_window, symbol_location
from verification.tests.test_place_move_users_name import (
    DESTINATION,
    DESTINATION_WINDOW,
    ENEMY_LITERAL,
    ENEMY_TEXT,
    H_WHOSE_TURN,
    NICKNAME,
    RETURN,
    STACK,
    W_BATTLE_MON_NICK,
    W_ENEMY_MON_NICK,
    Endpoint,
    IncDE,
    LdHFromB,
    LdLFromC,
    LoadDE,
    LoadWhoseTurn,
    PlaceStringSite,
    PopDE,
    PushDE,
    ContinuationBoundary,
    _memory,
    _setup,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000


class XorOne(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.regs.a ^ 1
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)
        )
        self.jump(self.state.addr + 1)


class AndA(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)
        )
        self.jump(self.state.addr + 1)


class BranchNZ(angr.SimProcedure):
    def __init__(self, taken: int, fallthrough: int) -> None:
        super().__init__()
        self.taken = taken
        self.fallthrough = fallthrough

    def run(self) -> None:  # type: ignore[override]
        condition = (self.state.regs.f & 0x40) == 0
        self.inhibit_autoret = True
        self.successors.add_successor(self.state.copy(), self.taken, condition, "Ijk_Boring")
        self.successors.add_successor(
            self.state.copy(), self.fallthrough, claripy.Not(condition), "Ijk_Boring"
        )


class JumpCommand(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__()
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.jump(self.target)


def _assembly(values: dict[str, claripy.ast.BV], whose_turn: int,
              saved_d: claripy.ast.BV, saved_e: claripy.ast.BV) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "PlaceMoveTargetsName")
    assert linked_bytes(ROM, location, 36) == bytes.fromhex(
        "f0f3ee011802f0f3d5a720051109d0180b11721acd5519606911dacfcd55196069d113c3"
    )
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    q = location.address
    project.hook(q, LoadWhoseTurn(), length=2)
    project.hook(q + 2, XorOne(), length=1)
    project.hook(q + 3, JumpCommand(q + 8), length=2)
    project.hook(q + 8, PushDE(), length=1)
    project.hook(q + 9, AndA(), length=1)
    project.hook(q + 10, BranchNZ(q + 17, q + 12), length=2)
    project.hook(q + 12, LoadDE(W_BATTLE_MON_NICK), length=3)
    project.hook(q + 15, JumpCommand(q + 28), length=2)
    project.hook(q + 17, LoadDE(ENEMY_TEXT), length=3)
    project.hook(q + 20, PlaceStringSite(ENEMY_TEXT, ENEMY_LITERAL), length=3)
    project.hook(q + 23, LdHFromB(), length=1)
    project.hook(q + 24, LdLFromC(), length=1)
    project.hook(q + 25, LoadDE(W_ENEMY_MON_NICK), length=3)
    project.hook(q + 28, PlaceStringSite(W_ENEMY_MON_NICK, NICKNAME), length=3)
    project.hook(q + 31, LdHFromB(), length=1)
    project.hook(q + 32, LdLFromC(), length=1)
    project.hook(q + 33, PopDE(), length=1)
    project.hook(q + 34, IncDE(), length=1)
    project.hook(q + 35, ContinuationBoundary(), length=3)
    state = project.factory.blank_state(addr=q)
    set_assembly_registers(state, values)
    state.regs.h = claripy.BVV(DESTINATION >> 8, 8)
    state.regs.l = claripy.BVV(DESTINATION & 0xFF, 8)
    state.regs.d = saved_d
    state.regs.e = saved_e
    state.regs.sp = STACK
    _setup(state, 0, values, whose_turn)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    ends = collect_returns(project, state, RETURN)
    return [Endpoint(**assembly_registers(end), memory=_memory(end, 0),
                     constraints=tuple(end.solver.constraints)) for end in ends]


def _native(values: dict[str, claripy.ast.BV], whose_turn: int,
            saved_d: claripy.ast.BV, saved_e: claripy.ast.BV) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_place_move_targets_name")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE,
                                       NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, saved_d)
    state.memory.store(NATIVE_STATE + 9, saved_e)
    _setup(state, NATIVE_MEMORY, values, whose_turn)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    end = manager.deadended[0]
    return [Endpoint(**native_registers(end, NATIVE_STATE),
                     memory=_memory(end, NATIVE_MEMORY),
                     constraints=tuple(end.solver.constraints))]


@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("whose_turn", (0, 1))
def test_place_move_targets_name_pathwise_equivalence(whose_turn: int) -> None:
    values = symbolic_registers("place_move_targets")
    for offset in range(DESTINATION_WINDOW):
        values[f"window{offset}"] = claripy.BVS(f"place_targets_window_{offset}", 8)
    saved_d = claripy.BVS("place_targets_saved_d", 8)
    saved_e = claripy.BVS("place_targets_saved_e", 8)
    values["d"] = saved_d
    values["e"] = saved_e
    values["h"] = claripy.BVV(DESTINATION >> 8, 8)
    values["l"] = claripy.BVV(DESTINATION & 0xFF, 8)
    assert_pathwise_equivalent(
        _assembly(values, whose_turn, saved_d, saved_e),
        _native(values, whose_turn, saved_d, saved_e),
        (*REGISTERS, "memory"),
    )
