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
from verification.harness.rom import rom_window, sm83_flags_to_z80, symbol_location

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF
SOURCE = 0xC500
DESTINATION = 0xC400
CHARACTER = 0x41
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


class CharacterSummary(angr.SimProcedure):
    def run(self) -> None:
        destination = DESTINATION + 1
        source = SOURCE + 1
        self.state.regs.a = claripy.BVV(TX_END, 8)
        self.state.regs.b = claripy.BVV(destination >> 8, 8)
        self.state.regs.c = claripy.BVV(destination & 0xFF, 8)
        self.state.regs.d = claripy.BVV(source >> 8, 8)
        self.state.regs.e = claripy.BVV(source & 0xFF, 8)
        self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0xC0, 8))
        self.state.memory.store(DESTINATION, claripy.BVV(CHARACTER, 8))
        self.jump(DONE)


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["destination_byte"] = claripy.BVS(f"{prefix}_destination_byte", 8)
    return values


def _memory_endpoint(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        state.memory.load(base + DESTINATION, 1),
        state.memory.load(base + SOURCE, 1),
        state.memory.load(base + SOURCE + 1, 1),
    )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
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
    project.hook(location.address, CharacterSummary(), length=1)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.memory.store(DESTINATION, values["destination_byte"])
    state.memory.store(SOURCE, claripy.BVV(CHARACTER, 8))
    state.memory.store(SOURCE + 1, claripy.BVV(TX_END, 8))
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored
    return [
        Endpoint(**assembly_registers(end), memory=_memory_endpoint(end, 0), constraints=tuple(end.solver.constraints))
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_place_string")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_MEMORY + DESTINATION, values["destination_byte"])
    state.memory.store(NATIVE_MEMORY + SOURCE, claripy.BVV(CHARACTER, 8))
    state.memory.store(NATIVE_MEMORY + SOURCE + 1, claripy.BVV(TX_END, 8))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(**native_registers(end, NATIVE_STATE), memory=_memory_endpoint(end, NATIVE_MEMORY), constraints=tuple(end.solver.constraints))
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_place_string_character_pathwise_equivalence() -> None:
    values = _inputs("place_string_character")
    values["h"] = claripy.BVV(DESTINATION >> 8, 8)
    values["l"] = claripy.BVV(DESTINATION & 0xFF, 8)
    values["d"] = claripy.BVV(SOURCE >> 8, 8)
    values["e"] = claripy.BVV(SOURCE & 0xFF, 8)
    assert_pathwise_equivalent(_assembly(values), _native(values), (*REGISTERS, "memory"))
