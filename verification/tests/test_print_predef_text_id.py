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
from verification.harness.rom import linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import (
    Sm83LoadAHighImmediate,
    Sm83StoreAAtHlIncrement,
    Sm83StoreAHighImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0x7FFF
W_TEXT_PREDEF_FLAG = 0xCF11
W_CUR_MAP_TEXT_PTR = 0xD36C
W_SPRITE_INDEX = 0xCF13
H_TEXT_ID = 0xFF8C
H_FRAME_COUNTER = 0xFFD5
H_LOADED_ROM_BANK = 0xFFB8
H_SAVED_MAP_TEXT_PTR = 0xFFEC
R_ROMB = 0x2000
TEXT_PREDEFS = 0x3F22
EXPECTED = bytes.fromhex(
    "e08c21223fcd0f3f2111cfcbc6cd2029216cd3f0ec22f0ed77c9"
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
    text_predef: claripy.ast.BV
    text_id: claripy.ast.BV
    map_pointer: claripy.ast.BV
    saved_pointer: claripy.ast.BV
    frame_counter: claripy.ast.BV
    sprite_index: claripy.ast.BV
    loaded_bank: claripy.ast.BV
    romb: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class SetMapBoundary(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        low = self.state.memory.load(W_CUR_MAP_TEXT_PTR, 1)
        high = self.state.memory.load(W_CUR_MAP_TEXT_PTR + 1, 1)
        self.state.memory.store(H_SAVED_MAP_TEXT_PTR, low)
        self.state.memory.store(H_SAVED_MAP_TEXT_PTR + 1, high)
        self.state.memory.store(W_CUR_MAP_TEXT_PTR, self.state.regs.l)
        self.state.memory.store(W_CUR_MAP_TEXT_PTR + 1, self.state.regs.h)
        self.state.regs.a = self.state.regs.h
        self.jump(self.continuation)


class DisplayBoundary(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        old_bank = self.state.memory.load(H_LOADED_ROM_BANK, 1)
        old_f = self.state.regs.f
        self.state.memory.store(W_TEXT_PREDEF_FLAG, claripy.BVV(0, 8))
        self.state.memory.store(H_FRAME_COUNTER, claripy.BVV(30, 8))
        pointer = claripy.BVV(TEXT_PREDEFS, 16)
        self.state.regs.h = pointer[15:8]
        self.state.regs.l = pointer[7:0]
        self.state.regs.d = claripy.BVV(0, 8)
        self.state.regs.a = self.state.memory.load(H_TEXT_ID, 1)
        self.state.memory.store(W_SPRITE_INDEX, self.state.regs.a)
        self.state.regs.b = old_bank
        self.state.regs.c = old_f
        self.state.regs.f = claripy.BVV(0, 8)
        self.jump(self.continuation)


def _endpoint(state: angr.SimState, *, native: bool, base: int) -> Endpoint:
    registers = native_registers(state, NATIVE_STATE) if native else assembly_registers(state)
    return Endpoint(
        **registers,
        text_predef=state.memory.load(base + W_TEXT_PREDEF_FLAG, 1),
        text_id=state.memory.load(base + H_TEXT_ID, 1),
        map_pointer=state.memory.load(base + W_CUR_MAP_TEXT_PTR, 2),
        saved_pointer=state.memory.load(base + H_SAVED_MAP_TEXT_PTR, 2),
        frame_counter=state.memory.load(base + H_FRAME_COUNTER, 1),
        sprite_index=state.memory.load(base + W_SPRITE_INDEX, 1),
        loaded_bank=state.memory.load(base + H_LOADED_ROM_BANK, 1),
        romb=state.memory.load(base + R_ROMB, 1),
        constraints=tuple(state.solver.constraints),
    )


def _values() -> dict[str, claripy.ast.BV]:
    return {
        "a": claripy.BVV(0x0B, 8), "f": claripy.BVV(0, 8),
        "b": claripy.BVV(0x45, 8), "c": claripy.BVV(0x67, 8),
        "d": claripy.BVV(0x89, 8), "e": claripy.BVV(0xAB, 8),
        "h": claripy.BVV(0xCD, 8), "l": claripy.BVV(0xEF, 8),
    }


def _setup(state: angr.SimState, base: int) -> None:
    state.memory.store(base + W_CUR_MAP_TEXT_PTR, claripy.BVV(0x78, 8))
    state.memory.store(base + W_CUR_MAP_TEXT_PTR + 1, claripy.BVV(0x56, 8))
    state.memory.store(base + H_LOADED_ROM_BANK, claripy.BVV(7, 8))
    state.memory.store(base + R_ROMB, claripy.BVV(5, 8))


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "PrintPredefTextID")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    base = location.address
    project.hook(base, Sm83StoreAHighImmediate(H_TEXT_ID, base + 2), length=2)
    project.hook(base + 5, SetMapBoundary(base + 8), length=3)
    project.hook(base + 0x0D, DisplayBoundary(base + 0x10), length=3)
    project.hook(base + 0x13, Sm83LoadAHighImmediate(H_SAVED_MAP_TEXT_PTR, base + 0x15), length=2)
    project.hook(base + 0x15, Sm83StoreAAtHlIncrement(base + 0x16), length=1)
    project.hook(base + 0x16, Sm83LoadAHighImmediate(H_SAVED_MAP_TEXT_PTR + 1, base + 0x18), length=2)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _setup(state, 0)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=lambda candidate: candidate.addr == RETURN)
    assert not manager.errored and manager.found
    return [_endpoint(end, native=False, base=0) for end in manager.found]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_print_predef_text_id")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, claripy.BVV(7, 8))
    state.memory.store(NATIVE_STATE + 9, claripy.BVV(5, 8))
    _setup(state, NATIVE_MEMORY)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and manager.deadended
    return [_endpoint(end, native=True, base=NATIVE_MEMORY) for end in manager.deadended]


@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_print_predef_text_id_pathwise_equivalence() -> None:
    assert_pathwise_equivalent(
        _assembly(_values()), _native(_values()),
        (*REGISTERS, "text_predef", "text_id", "map_pointer", "saved_pointer",
         "frame_counter", "sprite_index", "loaded_bank", "romb"),
    )
