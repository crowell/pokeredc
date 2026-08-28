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
)
from verification.harness.rom import collect_returns, rom_window, symbol_location

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
RETURN = 0xEFFF
STACK = 0xD000
SOURCE = 0xC500
DESTINATION = 0xC400
PLAYER_NAME = 0xD158
RIVAL_NAME = 0xD34A
BATTLE_NICK = 0xD009
ENEMY_NICK = 0xCFDA
WHOSE_TURN = 0xFFF3


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


class ReturnToken(angr.SimProcedure):
    def run(self) -> None:
        ret = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp = self.state.regs.sp + 2
        self.jump(ret)


class StoreHLIA(angr.SimProcedure):
    def run(self) -> None:
        hl = self.state.regs.hl
        self.state.memory.store(hl, self.state.regs.a)
        self.state.regs.hl = hl + 1
        self.jump(self.state.addr + 1)


class PrintLetterDelay(angr.SimProcedure):
    def run(self) -> None:
        self.state.regs.sp = self.state.regs.sp + 2
        self.jump(0x19E8)


class IncrementDE(angr.SimProcedure):
    def run(self) -> None:
        self.state.regs.de = self.state.regs.de + 1
        self.jump(0x19E9)


class LoadWhoseTurn(angr.SimProcedure):
    def run(self) -> None:
        self.state.regs.a = self.state.memory.load(WHOSE_TURN, 1)
        self.jump(self.state.addr + 2)


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        state.memory.load(base + DESTINATION, 16),
        state.memory.load(base + SOURCE, 1),
        state.memory.load(base + PLAYER_NAME, 3),
        state.memory.load(base + RIVAL_NAME, 3),
        state.memory.load(base + BATTLE_NICK, 3),
        state.memory.load(base + ENEMY_NICK, 3),
        state.memory.load(base + WHOSE_TURN, 1),
    )


def _assembly(values: dict[str, claripy.ast.BV], token: int, whose_turn: int = 0) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "PlaceString")
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
    project.hook(0x195E, ReturnToken(), length=1)
    project.hook(0x19E4, StoreHLIA(), length=1)
    project.hook(0x38D3, PrintLetterDelay(), length=3)
    project.hook(0x19E8, IncrementDE(), length=1)
    project.hook(0x1A2F, LoadWhoseTurn(), length=2)
    project.hook(0x1A35, LoadWhoseTurn(), length=2)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    state.memory.store(DESTINATION, values["destination_byte"])
    for offset in range(1, 16):
        state.memory.store(DESTINATION + offset, claripy.BVV(0, 8))
    state.memory.store(SOURCE, claripy.BVV(token, 8))
    state.memory.store(SOURCE + 1, claripy.BVV(0x50, 8))
    for address, values_for_name in (
        (PLAYER_NAME, (0x41, 0x42, 0x50)),
        (RIVAL_NAME, (0x43, 0x44, 0x50)),
        (BATTLE_NICK, (0x45, 0x46, 0x50)),
        (ENEMY_NICK, (0x47, 0x48, 0x50)),
    ):
        for offset, value in enumerate(values_for_name):
            state.memory.store(address + offset, claripy.BVV(value, 8))
    state.memory.store(WHOSE_TURN, claripy.BVV(whose_turn, 8))
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    return [
        Endpoint(**assembly_registers(end), memory=_memory(end, 0), constraints=tuple(end.solver.constraints))
        for end in collect_returns(project, state, RETURN)
    ]


def _native(values: dict[str, claripy.ast.BV], token: int, whose_turn: int = 0) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_place_string")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_MEMORY + DESTINATION, values["destination_byte"])
    for offset in range(1, 16):
        state.memory.store(NATIVE_MEMORY + DESTINATION + offset, claripy.BVV(0, 8))
    state.memory.store(NATIVE_MEMORY + SOURCE, claripy.BVV(token, 8))
    state.memory.store(NATIVE_MEMORY + SOURCE + 1, claripy.BVV(0x50, 8))
    for address, values_for_name in (
        (PLAYER_NAME, (0x41, 0x42, 0x50)),
        (RIVAL_NAME, (0x43, 0x44, 0x50)),
        (BATTLE_NICK, (0x45, 0x46, 0x50)),
        (ENEMY_NICK, (0x47, 0x48, 0x50)),
    ):
        for offset, value in enumerate(values_for_name):
            state.memory.store(NATIVE_MEMORY + address + offset, claripy.BVV(value, 8))
    state.memory.store(NATIVE_MEMORY + WHOSE_TURN, claripy.BVV(whose_turn, 8))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    end = manager.deadended[0]
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=_memory(end, NATIVE_MEMORY),
            constraints=tuple(end.solver.constraints),
        )
    ]


@pytest.mark.parametrize("token", (0x00, 0x52, 0x53, 0x54, 0x56, 0x57, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F))
@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_place_string_terminal_tokens_pathwise_equivalence(token: int) -> None:
    values = {register: claripy.BVV(0, 8) for register in REGISTERS}
    values["h"] = claripy.BVV(DESTINATION >> 8, 8)
    values["l"] = claripy.BVV(DESTINATION & 0xFF, 8)
    values["d"] = claripy.BVV(SOURCE >> 8, 8)
    values["e"] = claripy.BVV(SOURCE & 0xFF, 8)
    values["destination_byte"] = claripy.BVS("place_string_terminal_destination", 8)
    assert_pathwise_equivalent(_assembly(values, token), _native(values, token), (*REGISTERS, "memory"))


@pytest.mark.parametrize("token,whose_turn", ((0x59, 0), (0x59, 1), (0x5A, 0), (0x5A, 1)))
@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_place_string_battle_name_tokens_pathwise_equivalence(token: int, whose_turn: int) -> None:
    values = {register: claripy.BVV(0, 8) for register in REGISTERS}
    values["h"] = claripy.BVV(DESTINATION >> 8, 8)
    values["l"] = claripy.BVV(DESTINATION & 0xFF, 8)
    values["d"] = claripy.BVV(SOURCE >> 8, 8)
    values["e"] = claripy.BVV(SOURCE & 0xFF, 8)
    values["destination_byte"] = claripy.BVS("place_string_battle_name_destination", 8)
    assert_pathwise_equivalent(
        _assembly(values, token, whose_turn),
        _native(values, token, whose_turn),
        (*REGISTERS, "memory"),
    )
