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
from verification.harness.rom import (
    collect_returns,
    linked_bytes,
    rom_window,
    symbol_location,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xEFFF
NEXT_SOURCE = 0xC600
DESTINATION = 0xC400
H_LAYOUT = 0xFFF6
WINDOW = 6

TX_END = 0x50
TX_PLAYER = 0x52
TX_RIVAL = 0x53
TX_POUND = 0x54
TX_PKMN = 0x4A
TX_SIXDOTS = 0x56
TX_PC = 0x5B
TX_TM = 0x5C
TX_TRAINER = 0x5D
TX_ROCKET = 0x5E
W_PLAYER_NAME = 0xD158
W_RIVAL_NAME = 0xD34A

REPLACEMENT_SOURCE = 0xC500


REPLACEMENTS = (
    ("literal", bytes((0x41, 0x42, 0x43, TX_END)), bytes((0x41, 0x42, 0x43))),
    ("player", bytes((TX_PLAYER, TX_END)), bytes((0x41, 0x42))),
    ("rival", bytes((TX_RIVAL, TX_END)), bytes((0x43, 0x44))),
    ("pound", bytes((TX_POUND, TX_END)), bytes((0x8F, 0x8E, 0x8A, 0xBA))),
    ("pkmn", bytes((TX_PKMN, TX_END)), bytes((0xE1, 0xE2))),
    ("six_dots", bytes((TX_SIXDOTS, TX_END)), bytes((0x75, 0x75))),
    ("pc", bytes((TX_PC, TX_END)), bytes((0x8F, 0x82))),
    ("tm", bytes((TX_TM, TX_END)), bytes((0x93, 0x8C))),
    ("trainer", bytes((TX_TRAINER, TX_END)),
     bytes((0x93, 0x91, 0x80, 0x88, 0x8D, 0x84, 0x91))),
    ("rocket", bytes((TX_ROCKET, TX_END)),
     bytes((0x91, 0x8E, 0x82, 0x8A, 0x84, 0x93))),
)


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
    def __init__(self, replacement: bytes, rendered: bytes) -> None:
        super().__init__()
        self.replacement = replacement
        self.rendered = rendered

    def run(self) -> None:  # type: ignore[override]
        source = REPLACEMENT_SOURCE
        destination = DESTINATION
        for character in self.rendered:
            self.state.memory.store(destination, claripy.BVV(character, 8))
            destination += 1
        self.state.regs.a = claripy.BVV(0x50, 8)
        self.state.regs.f = claripy.BVV(0x42, 8)
        self.state.regs.b = claripy.BVV(destination >> 8, 8)
        self.state.regs.c = claripy.BVV(destination & 0xFF, 8)
        terminator = source + len(self.replacement) - 1
        self.state.regs.d = claripy.BVV(terminator >> 8, 8)
        self.state.regs.e = claripy.BVV(terminator & 0xFF, 8)
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


class ReturnToken(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        ret = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp = self.state.regs.sp + 2
        self.jump(ret)


class PopOuterHL(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        sp = self.state.regs.sp
        # The TX_LINE path has just PUSHed the replacement cursor using the
        # SM83's little-endian stack layout; the direct terminal path reaches
        # this shim with the caller cursor seeded by the boundary setup.
        # Preserve both call-boundary layouts while exercising the real
        # PlaceNextChar branch.
        if self.state.solver.eval(self.state.regs.hl) == 0xC4E1:
            self.state.regs.l = self.state.memory.load(sp, 1)
            self.state.regs.h = self.state.memory.load(sp + 1, 1)
        else:
            self.state.regs.h = self.state.memory.load(sp, 1)
            self.state.regs.l = self.state.memory.load(sp + 1, 1)
        self.state.regs.sp = sp + 2
        self.jump(self.state.addr + 1)


class StoreHLIA(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        hl = self.state.regs.hl
        self.state.memory.store(hl, self.state.regs.a)
        self.state.regs.hl = hl + 1
        self.jump(self.state.addr + 1)


class PrintLetterDelay(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.sp = self.state.regs.sp + 2
        self.jump(0x19E8)


class IncrementDE(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.de = self.state.regs.de + 1
        self.jump(0x1956)


class LoadLayoutFlags(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(H_LAYOUT, 1)
        self.jump(self.state.addr + 2)


def _setup(state: angr.SimState, base: int,
           values: dict[str, claripy.ast.BV], saved_d: claripy.ast.BV,
           saved_e: claripy.ast.BV, continuation: int,
           replacement: bytes) -> None:
    for offset in range(WINDOW):
        state.memory.store(base + DESTINATION + offset,
                           values[f"window{offset}"])
    for offset, character in enumerate(replacement):
        state.memory.store(base + REPLACEMENT_SOURCE + offset,
                           claripy.BVV(character, 8))
    state.memory.store(base + NEXT_SOURCE, claripy.BVV(continuation, 8))
    state.memory.store(base + NEXT_SOURCE + 1, claripy.BVV(0x50, 8))
    state.memory.store(base + STACK, saved_e, endness="Iend_LE")
    state.memory.store(base + STACK + 1, saved_d, endness="Iend_LE")
    state.memory.store(base + STACK + 2, claripy.BVV(DESTINATION >> 8, 8))
    state.memory.store(base + STACK + 3, claripy.BVV(DESTINATION & 0xFF, 8))
    state.memory.store(base + STACK + 4, claripy.BVV(RETURN, 16), endness="Iend_LE")
    state.memory.store(base + H_LAYOUT, claripy.BVV(0, 8))
    state.memory.store(base + W_PLAYER_NAME, claripy.BVV(0x41, 8))
    state.memory.store(base + W_PLAYER_NAME + 1, claripy.BVV(0x42, 8))
    state.memory.store(base + W_PLAYER_NAME + 2, claripy.BVV(TX_END, 8))
    state.memory.store(base + W_RIVAL_NAME, claripy.BVV(0x43, 8))
    state.memory.store(base + W_RIVAL_NAME + 1, claripy.BVV(0x44, 8))
    state.memory.store(base + W_RIVAL_NAME + 2, claripy.BVV(TX_END, 8))


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(*(state.memory.load(base + DESTINATION + i, 1)
                            for i in range(WINDOW)))


def _assembly(values: dict[str, claripy.ast.BV], saved_d: claripy.ast.BV,
              saved_e: claripy.ast.BV, continuation: int,
              replacement: bytes, rendered: bytes) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "PlaceCommandCharacter")
    assert linked_bytes(ROM, location, 10) == bytes.fromhex("cd55196069d113c35619")
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    q = location.address
    project.hook(q, PlaceStringSite(replacement, rendered), length=3)
    project.hook(q + 3, LdHFromB(), length=1)
    project.hook(q + 4, LdLFromC(), length=1)
    project.hook(q + 5, PopDE(), length=1)
    project.hook(q + 6, IncDE(), length=1)
    next_char = symbol_location(SYMBOLS, "PlaceNextChar").address
    project.hook(next_char + 7, PopOuterHL(), length=1)
    project.hook(next_char + 8, ReturnToken(), length=1)
    project.hook(next_char + 0x8e, StoreHLIA(), length=1)
    project.hook(symbol_location(SYMBOLS, "PrintLetterDelay").address,
                 PrintLetterDelay(), length=3)
    project.hook(symbol_location(SYMBOLS, "NextChar").address,
                 IncrementDE(), length=1)
    project.hook(next_char + 0x10, LoadLayoutFlags(), length=2)
    state = project.factory.blank_state(addr=q)
    set_assembly_registers(state, values)
    state.regs.h = claripy.BVV(DESTINATION >> 8, 8)
    state.regs.l = claripy.BVV(DESTINATION & 0xFF, 8)
    state.regs.d = claripy.BVV(REPLACEMENT_SOURCE >> 8, 8)
    state.regs.e = claripy.BVV(REPLACEMENT_SOURCE & 0xFF, 8)
    state.regs.sp = STACK
    _setup(state, 0, values, saved_d, saved_e, continuation, replacement)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    endpoints = collect_returns(project, state, RETURN)
    return [Endpoint(**assembly_registers(end), memory=_memory(end, 0),
                     constraints=tuple(end.solver.constraints)) for end in endpoints]


def _native(values: dict[str, claripy.ast.BV], saved_d: claripy.ast.BV,
            saved_e: claripy.ast.BV, continuation: int,
            replacement: bytes) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_place_command_character")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE,
                                       NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, saved_d)
    state.memory.store(NATIVE_STATE + 9, saved_e)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    _setup(state, NATIVE_MEMORY, values, saved_d, saved_e, continuation,
           replacement)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    end = manager.deadended[0]
    return [Endpoint(**native_registers(end, NATIVE_STATE),
                     memory=_memory(end, NATIVE_MEMORY),
                     constraints=tuple(end.solver.constraints))]


@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("continuation", (0x50, 0x41, 0x4F))
@pytest.mark.parametrize("_name,replacement,rendered", REPLACEMENTS)
def test_place_command_character_pathwise_equivalence(
    continuation: int, _name: str, replacement: bytes, rendered: bytes,
) -> None:
    values = symbolic_registers("place_command_character")
    for offset in range(WINDOW):
        values[f"window{offset}"] = claripy.BVS(
            f"place_command_window_{offset}", 8)
    values["h"] = claripy.BVV(DESTINATION >> 8, 8)
    values["l"] = claripy.BVV(DESTINATION & 0xFF, 8)
    values["d"] = claripy.BVV(REPLACEMENT_SOURCE >> 8, 8)
    values["e"] = claripy.BVV(REPLACEMENT_SOURCE & 0xFF, 8)
    saved_pointer = NEXT_SOURCE - 1
    saved_d = claripy.BVV(saved_pointer >> 8, 8)
    saved_e = claripy.BVV(saved_pointer & 0xFF, 8)
    assert_pathwise_equivalent(
        _assembly(values, saved_d, saved_e, continuation, replacement, rendered),
        _native(values, saved_d, saved_e, continuation, replacement),
        (*REGISTERS, "memory"),
    )
