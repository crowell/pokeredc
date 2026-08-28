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
from verification.harness.rom import collect_returns, rom_window, sm83_flags_to_z80, symbol_location

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
TILEMAP = 0xC3A0
REGION_LENGTH = 0x200


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
    region: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class ScrollTextUpOneLine(angr.SimProcedure):
    def run(self) -> None:
        entry_c = self.state.regs.c
        for i in range(60):
            self.state.memory.store(TILEMAP + 13 * 20 + i, self.state.memory.load(TILEMAP + 14 * 20 + i, 1))
        for i in range(18):
            self.state.memory.store(TILEMAP + 16 * 20 + 1 + i, claripy.BVV(0x7F, 8))
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0xC0, 8))
        self.state.regs.b = claripy.BVV(0, 8)
        self.state.regs.c = entry_c
        self.state.regs.d = claripy.BVV(0xC4, 8)
        self.state.regs.e = claripy.BVV(0xE0, 8)
        self.state.regs.h = claripy.BVV(0xC4, 8)
        self.state.regs.l = claripy.BVV(0xF3, 8)
        ret = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp = self.state.regs.sp + 2
        self.jump(ret)


class ReturnPlaceString(angr.SimProcedure):
    def run(self) -> None:
        ret = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp = self.state.regs.sp + 2
        self.jump(ret)


def _region(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(*(state.memory.load(base + TILEMAP + i, 1) for i in range(REGION_LENGTH)))


def _setup(state: angr.SimState, base: int) -> None:
    state.memory.store(base + DESTINATION, claripy.BVV(0xAA, 8))
    for i in range(REGION_LENGTH):
        if i != DESTINATION - TILEMAP:
            state.memory.store(base + TILEMAP + i, claripy.BVV((i * 13) & 0xFF, 8))
    state.memory.store(base + SOURCE, claripy.BVV(0x4C, 8))
    state.memory.store(base + SOURCE + 1, claripy.BVV(0x50, 8))


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "PlaceString")
    project = angr.Project(rom_window(ROM, location.bank), auto_load_libs=False, rebase_granularity=0x100,
                           main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                                      "base_addr": 0, "entry_point": location.address})
    project.hook(0x1B18, ScrollTextUpOneLine(), length=0x22)
    project.hook(0x195E, ReturnPlaceString(), length=1)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    _setup(state, 0)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    return [Endpoint(**assembly_registers(end), region=_region(end, 0), constraints=tuple(end.solver.constraints))
            for end in collect_returns(project, state, RETURN)]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_place_string")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, NATIVE_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    end = manager.deadended[0]
    return [Endpoint(**native_registers(end, NATIVE_STATE), region=_region(end, NATIVE_MEMORY),
                     constraints=tuple(end.solver.constraints))]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_place_string_scroll_pathwise_equivalence() -> None:
    values = {register: claripy.BVV(0, 8) for register in REGISTERS}
    values["h"] = claripy.BVV(DESTINATION >> 8, 8)
    values["l"] = claripy.BVV(DESTINATION & 0xFF, 8)
    values["d"] = claripy.BVV(SOURCE >> 8, 8)
    values["e"] = claripy.BVV(SOURCE & 0xFF, 8)
    assert_pathwise_equivalent(_assembly(values), _native(values), (*REGISTERS, "region"))
