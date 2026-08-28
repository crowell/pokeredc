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
SOURCE = 0xC500
DESTINATION = 0xC400
STRING = bytes((0x41, 0x42, 0x43, 0x50))
WINDOW = 6


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


class PlaceStringSite(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        source = SOURCE
        destination = DESTINATION
        for character in STRING[:-1]:
            self.state.memory.store(destination, claripy.BVV(character, 8))
            destination += 1
        self.state.regs.a = claripy.BVV(0x50, 8)
        self.state.regs.f = claripy.BVV(0x42, 8)
        self.state.regs.b = claripy.BVV(destination >> 8, 8)
        self.state.regs.c = claripy.BVV(destination & 0xFF, 8)
        self.state.regs.d = claripy.BVV((source + len(STRING) - 1) >> 8, 8)
        self.state.regs.e = claripy.BVV((source + len(STRING) - 1) & 0xFF, 8)
        self.state.regs.h = claripy.BVV(DESTINATION >> 8, 8)
        self.state.regs.l = claripy.BVV(DESTINATION & 0xFF, 8)
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
        de = claripy.Concat(self.state.regs.d, self.state.regs.e) + 1
        self.state.regs.d = de[15:8]
        self.state.regs.e = de[7:0]
        self.jump(self.state.addr + 1)


class ContinuationBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.jump(RETURN)


def _setup(state: angr.SimState, base: int,
           values: dict[str, claripy.ast.BV], saved_d: claripy.ast.BV,
           saved_e: claripy.ast.BV) -> None:
    for offset in range(WINDOW):
        state.memory.store(base + DESTINATION + offset,
                           values[f"window{offset}"])
    for offset, character in enumerate(STRING):
        state.memory.store(base + SOURCE + offset, claripy.BVV(character, 8))
    state.memory.store(base + STACK, saved_e, endness="Iend_LE")
    state.memory.store(base + STACK + 1, saved_d, endness="Iend_LE")


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(*(state.memory.load(base + DESTINATION + i, 1)
                            for i in range(WINDOW)))


def _assembly(values: dict[str, claripy.ast.BV], saved_d: claripy.ast.BV,
              saved_e: claripy.ast.BV) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "PlaceCommandCharacter")
    assert linked_bytes(ROM, location, 10) == bytes.fromhex("cd55196069d113c35619")
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    q = location.address
    project.hook(q, PlaceStringSite(), length=3)
    project.hook(q + 3, LdHFromB(), length=1)
    project.hook(q + 4, LdLFromC(), length=1)
    project.hook(q + 5, PopDE(), length=1)
    project.hook(q + 6, IncDE(), length=1)
    project.hook(q + 7, ContinuationBoundary(), length=3)
    state = project.factory.blank_state(addr=q)
    set_assembly_registers(state, values)
    state.regs.h = claripy.BVV(DESTINATION >> 8, 8)
    state.regs.l = claripy.BVV(DESTINATION & 0xFF, 8)
    state.regs.d = claripy.BVV(SOURCE >> 8, 8)
    state.regs.e = claripy.BVV(SOURCE & 0xFF, 8)
    state.regs.sp = STACK
    _setup(state, 0, values, saved_d, saved_e)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    endpoints = collect_returns(project, state, RETURN)
    return [Endpoint(**assembly_registers(end), memory=_memory(end, 0),
                     constraints=tuple(end.solver.constraints)) for end in endpoints]


def _native(values: dict[str, claripy.ast.BV], saved_d: claripy.ast.BV,
            saved_e: claripy.ast.BV) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_place_command_character")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE,
                                       NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, saved_d)
    state.memory.store(NATIVE_STATE + 9, saved_e)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    _setup(state, NATIVE_MEMORY, values, saved_d, saved_e)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    end = manager.deadended[0]
    return [Endpoint(**native_registers(end, NATIVE_STATE),
                     memory=_memory(end, NATIVE_MEMORY),
                     constraints=tuple(end.solver.constraints))]


@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_place_command_character_pathwise_equivalence() -> None:
    values = symbolic_registers("place_command_character")
    for offset in range(WINDOW):
        values[f"window{offset}"] = claripy.BVS(
            f"place_command_window_{offset}", 8)
    values["h"] = claripy.BVV(DESTINATION >> 8, 8)
    values["l"] = claripy.BVV(DESTINATION & 0xFF, 8)
    values["d"] = claripy.BVV(SOURCE >> 8, 8)
    values["e"] = claripy.BVV(SOURCE & 0xFF, 8)
    saved_d = claripy.BVS("place_command_saved_d", 8)
    saved_e = claripy.BVS("place_command_saved_e", 8)
    assert_pathwise_equivalent(
        _assembly(values, saved_d, saved_e),
        _native(values, saved_d, saved_e),
        (*REGISTERS, "memory"),
    )
