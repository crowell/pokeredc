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
from verification.harness.rom import collect_returns, rom_window, symbol_location

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
RETURN = 0xEFFF
SOURCE = 0xC500
DESTINATION = 0xC400
SAVED_CURSOR = 0xC410
TX_END = 0x50


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


class StoreHLIA(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        hl = self.state.regs.hl
        self.state.memory.store(hl, self.state.regs.a)
        self.state.regs.hl = hl + 1
        self.jump(self.state.addr + 1)


class PrintLetterDelay(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        # Skip the call's return address and resume at NextChar.
        self.state.regs.sp = self.state.regs.sp + 2
        self.jump(symbol_location(SYMBOLS, "NextChar").address)


class IncrementDE(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.de = self.state.regs.de + 1
        self.jump(symbol_location(SYMBOLS, "PlaceNextChar").address)


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["destination_byte"] = claripy.BVS(f"{prefix}_destination_byte", 8)
    return values


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        state.memory.load(base + DESTINATION, 1),
        state.memory.load(base + SOURCE, 1),
        state.memory.load(base + SOURCE + 1, 1),
    )


def _assembly(values: dict[str, claripy.ast.BV], character: int) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "PlaceNextChar")
    next_char = symbol_location(SYMBOLS, "NextChar")
    print_delay = symbol_location(SYMBOLS, "PrintLetterDelay")
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
    project.hook(print_delay.address, PrintLetterDelay(), length=3)
    project.hook(next_char.address, IncrementDE(), length=1)
    project.hook(0x19E4, StoreHLIA(), length=1)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.regs.sp = 0xD000
    state.memory.store(0xD000, claripy.BVV(SAVED_CURSOR, 16), endness="Iend_LE")
    state.memory.store(0xD002, claripy.BVV(RETURN, 16), endness="Iend_LE")
    state.memory.store(DESTINATION, values["destination_byte"])
    state.memory.store(SOURCE, claripy.BVV(character, 8))
    state.memory.store(SOURCE + 1, claripy.BVV(TX_END, 8))
    ends = collect_returns(project, state, RETURN)
    return [
        Endpoint(
            **assembly_registers(end),
            memory=_memory(end, 0),
            constraints=tuple(end.solver.constraints),
        )
        for end in ends
    ]


def _native(values: dict[str, claripy.ast.BV], character: int) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_place_next_char")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_MEMORY + DESTINATION, values["destination_byte"])
    state.memory.store(NATIVE_MEMORY + SOURCE, claripy.BVV(character, 8))
    state.memory.store(NATIVE_MEMORY + SOURCE + 1, claripy.BVV(TX_END, 8))
    # The native ABI carries the caller's saved HL after the register block.
    state.memory.store(NATIVE_STATE + 8, claripy.BVV(SAVED_CURSOR >> 8, 8))
    state.memory.store(NATIVE_STATE + 9, claripy.BVV(SAVED_CURSOR & 0xFF, 8))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=_memory(end, NATIVE_MEMORY),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("character", (0x41, TX_END))
def test_place_next_char_pathwise_equivalence(character: int) -> None:
    values = _inputs(f"place_next_char_{character:02x}")
    values["h"] = claripy.BVV(DESTINATION >> 8, 8)
    values["l"] = claripy.BVV(DESTINATION & 0xFF, 8)
    values["d"] = claripy.BVV(SOURCE >> 8, 8)
    values["e"] = claripy.BVV(SOURCE & 0xFF, 8)
    assert_pathwise_equivalent(
        _assembly(values, character),
        _native(values, character),
        (*REGISTERS, "memory"),
    )
