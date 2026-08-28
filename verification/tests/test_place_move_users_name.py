from __future__ import annotations

from dataclasses import dataclass
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

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xEFFF
H_WHOSE_TURN = 0xFFF3
W_BATTLE_MON_NICK = 0xD009
W_ENEMY_MON_NICK = 0xCFDA
ENEMY_TEXT = 0x1A72
DESTINATION = 0xC400
DESTINATION_WINDOW = 20
NICKNAME = bytes((0x8F, 0x88, 0x84, 0x50))
ENEMY_LITERAL = bytes((0x84, 0xAD, 0xA4, 0xAC, 0xB8, 0x7F, 0x50))


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
    memory: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class LoadWhoseTurn(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(H_WHOSE_TURN, 1)
        self.jump(self.state.addr + 2)


class PushDE(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        sp = self.state.regs.sp - 2
        self.state.memory.store(sp, self.state.regs.e, endness="Iend_LE")
        self.state.memory.store(sp + 1, self.state.regs.d, endness="Iend_LE")
        self.state.regs.sp = sp
        self.jump(self.state.addr + 1)


class AndA(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x40, 8),
            claripy.BVV(0, 8),
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
        self.successors.add_successor(
            self.state.copy(), self.taken, condition, "Ijk_Boring"
        )
        self.successors.add_successor(
            self.state.copy(), self.fallthrough, claripy.Not(condition), "Ijk_Boring"
        )


class LoadDE(angr.SimProcedure):
    def __init__(self, value: int) -> None:
        super().__init__()
        self.value = value

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.d = claripy.BVV(self.value >> 8, 8)
        self.state.regs.e = claripy.BVV(self.value & 0xFF, 8)
        self.jump(self.state.addr + 3)


class JumpCommand(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__()
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.jump(self.target)


class PlaceStringSite(angr.SimProcedure):
    def __init__(self, source: int, string: bytes) -> None:
        super().__init__()
        self.source = source
        self.string = string

    def run(self) -> None:  # type: ignore[override]
        destination = (self.state.solver.eval(self.state.regs.h) << 8) | self.state.solver.eval(self.state.regs.l)
        for character in self.string[:-1]:
            self.state.memory.store(destination, claripy.BVV(character, 8))
            destination += 1
        self.state.regs.a = claripy.BVV(0x50, 8)
        self.state.regs.f = claripy.BVV(0x42, 8)
        self.state.regs.b = claripy.BVV(destination >> 8, 8)
        self.state.regs.c = claripy.BVV(destination & 0xFF, 8)
        self.state.regs.d = claripy.BVV((self.source + len(self.string) - 1) >> 8, 8)
        self.state.regs.e = claripy.BVV((self.source + len(self.string) - 1) & 0xFF, 8)
        self.jump(self.state.addr + 3)


class LdHFromB(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = self.state.regs.b
        self.jump(self.state.addr + 1)


class LdLFromC(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.l = self.state.regs.c
        self.jump(self.state.addr + 1)


class PopDE(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        sp = self.state.regs.sp
        self.state.regs.e = self.state.memory.load(sp, 1)
        self.state.regs.d = self.state.memory.load(sp + 1, 1)
        self.state.regs.sp = sp + 2
        self.jump(self.state.addr + 1)


class IncDE(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        value = claripy.Concat(self.state.regs.d, self.state.regs.e) + 1
        self.state.regs.d = value[15:8]
        self.state.regs.e = value[7:0]
        self.jump(self.state.addr + 1)


class ContinuationBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.jump(RETURN)


def _setup(state: angr.SimState, base: int,
           values: dict[str, claripy.ast.BV], whose_turn: int) -> None:
    state.memory.store(base + H_WHOSE_TURN, claripy.BVV(whose_turn, 8))
    for offset, value in enumerate(NICKNAME):
        state.memory.store(base + W_BATTLE_MON_NICK + offset, claripy.BVV(value, 8))
        state.memory.store(base + W_ENEMY_MON_NICK + offset, claripy.BVV(value, 8))
    for offset, value in enumerate(ENEMY_LITERAL):
        state.memory.store(base + ENEMY_TEXT + offset, claripy.BVV(value, 8))
    for offset in range(DESTINATION_WINDOW):
        state.memory.store(base + DESTINATION + offset, values[f"window{offset}"])


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        state.memory.load(base + H_WHOSE_TURN, 1),
        *(state.memory.load(base + DESTINATION + i, 1)
          for i in range(DESTINATION_WINDOW)),
        *(state.memory.load(base + W_BATTLE_MON_NICK + i, 1) for i in range(4)),
        *(state.memory.load(base + W_ENEMY_MON_NICK + i, 1) for i in range(4)),
        *(state.memory.load(base + ENEMY_TEXT + i, 1) for i in range(7)),
    )


def _assembly(values: dict[str, claripy.ast.BV], whose_turn: int,
              saved_d: claripy.ast.BV, saved_e: claripy.ast.BV) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "PlaceMoveUsersName")
    assert linked_bytes(ROM, location, 30) == bytes.fromhex(
        "f0f3d5a720051109d0180b11721acd5519606911dacfcd55196069d113c3"
    )
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    q = location.address
    project.hook(q, LoadWhoseTurn(), length=2)
    project.hook(q + 2, PushDE(), length=1)
    project.hook(q + 3, AndA(), length=1)
    project.hook(q + 4, BranchNZ(q + 11, q + 6), length=2)
    project.hook(q + 6, LoadDE(W_BATTLE_MON_NICK), length=3)
    project.hook(q + 9, JumpCommand(q + 22), length=2)
    project.hook(q + 11, LoadDE(ENEMY_TEXT), length=3)
    project.hook(q + 14, PlaceStringSite(ENEMY_TEXT, ENEMY_LITERAL), length=3)
    project.hook(q + 17, LdHFromB(), length=1)
    project.hook(q + 18, LdLFromC(), length=1)
    project.hook(q + 19, LoadDE(W_ENEMY_MON_NICK), length=3)
    project.hook(q + 22, PlaceStringSite(W_ENEMY_MON_NICK, NICKNAME), length=3)
    project.hook(q + 25, LdHFromB(), length=1)
    project.hook(q + 26, LdLFromC(), length=1)
    project.hook(q + 27, PopDE(), length=1)
    project.hook(q + 28, IncDE(), length=1)
    project.hook(q + 29, ContinuationBoundary(), length=3)
    state = project.factory.blank_state(addr=q)
    set_assembly_registers(state, values)
    state.regs.h = claripy.BVV(DESTINATION >> 8, 8)
    state.regs.l = claripy.BVV(DESTINATION & 0xFF, 8)
    state.regs.d = saved_d
    state.regs.e = saved_e
    state.regs.sp = STACK
    _setup(state, 0, values, whose_turn)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    endpoints = collect_returns(project, state, RETURN)
    return [Endpoint(**assembly_registers(end), memory=_memory(end, 0),
                     constraints=tuple(end.solver.constraints)) for end in endpoints]


def _native(values: dict[str, claripy.ast.BV], whose_turn: int,
            saved_d: claripy.ast.BV, saved_e: claripy.ast.BV) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_place_move_users_name")
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
def test_place_move_users_name_pathwise_equivalence(whose_turn: int) -> None:
    values = symbolic_registers("place_move_users")
    for offset in range(DESTINATION_WINDOW):
        values[f"window{offset}"] = claripy.BVS(f"place_move_window_{offset}", 8)
    saved_d = claripy.BVS("place_move_saved_d", 8)
    saved_e = claripy.BVS("place_move_saved_e", 8)
    values["d"] = saved_d
    values["e"] = saved_e
    values["h"] = claripy.BVV(DESTINATION >> 8, 8)
    values["l"] = claripy.BVV(DESTINATION & 0xFF, 8)
    assert_pathwise_equivalent(
        _assembly(values, whose_turn, saved_d, saved_e),
        _native(values, whose_turn, saved_d, saved_e),
        (*REGISTERS, "memory"),
    )
