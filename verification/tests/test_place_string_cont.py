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
from verification.harness.rom import collect_returns, rom_window, sm83_flags_to_z80, symbol_location
from verification.harness.sm83_shims import Sm83StoreAImmediate


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xEFFF
SOURCE = 0xC500
DESTINATION = 0xC400
TILEMAP = 0xC3A0
REGION_LENGTH = 0x200
ARROW_SLOT = 0xC4F2
W_LINKSTATE = 0xD12B


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


class ReturnPlaceString(angr.SimProcedure):
    def run(self) -> None:
        ret = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp = self.state.regs.sp + 2
        self.jump(ret)


class PrintLetterDelay(angr.SimProcedure):
    def run(self) -> None:
        self.jump(self.state.addr + 3)


class IncrementDE(angr.SimProcedure):
    def run(self) -> None:
        self.state.regs.de = self.state.regs.de + 1
        self.jump(self.state.addr + 1)


class PushDE(angr.SimProcedure):
    def run(self) -> None:
        sp = self.state.solver.eval(self.state.regs.sp)
        self.state.memory.store(sp - 1, self.state.regs.d)
        self.state.memory.store(sp - 2, self.state.regs.e)
        self.state.regs.sp = claripy.BVV(sp - 2, 16)
        self.jump(self.state.addr + 1)


class PopDE(angr.SimProcedure):
    def run(self) -> None:
        sp = self.state.solver.eval(self.state.regs.sp)
        self.state.regs.e = self.state.memory.load(sp, 1)
        self.state.regs.d = self.state.memory.load(sp + 1, 1)
        self.state.regs.sp = claripy.BVV(sp + 2, 16)
        self.jump(self.state.addr + 1)


class ProtectedDelay3(angr.SimProcedure):
    def run(self) -> None:
        # Complete proved port_delay3 transition, followed by the
        # ProtectedDelay3 BC restore.
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0xC0, 8))
        self.jump(self.state.addr + 3)


class ManualTextScroll(angr.SimProcedure):
    def run(self) -> None:
        # Non-link, terminating A/B observation of the proved callee.
        self.state.regs.a = claripy.BVV(0x90, 8)
        self.jump(self.state.addr + 3)


class ScrollTextUpOneLine(angr.SimProcedure):
    def run(self) -> None:
        entry_c = self.state.regs.c
        for i in range(60):
            self.state.memory.store(
                TILEMAP + 13 * 20 + i,
                self.state.memory.load(TILEMAP + 14 * 20 + i, 1),
            )
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
        self.jump(self.state.addr + 3)


def _region(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(*(state.memory.load(base + TILEMAP + i, 1) for i in range(REGION_LENGTH)))


def _setup(state: angr.SimState, base: int, values: dict[str, claripy.ast.BV]) -> None:
    state.memory.store(base + DESTINATION, claripy.BVV(0xAA, 8))
    for i in range(REGION_LENGTH):
        if i != DESTINATION - TILEMAP:
            state.memory.store(base + TILEMAP + i, claripy.BVV((i * 13) & 0xFF, 8))
    state.memory.store(base + SOURCE, claripy.BVV(0x4B, 8))
    state.memory.store(base + SOURCE + 1, claripy.BVV(0x50, 8))
    state.memory.store(base + ARROW_SLOT, values.get("arrow", claripy.BVV(0, 8)))
    state.memory.store(base + W_LINKSTATE, claripy.BVV(0, 8))


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
    project.hook(0x195E, ReturnPlaceString(), length=1)
    project.hook(0x19E8, IncrementDE(), length=1)
    project.hook(0x38D3, PrintLetterDelay(), length=3)
    project.hook(0x1AFA, Sm83StoreAImmediate(ARROW_SLOT, 0x1AFD), length=3)
    project.hook(0x1AFD, ProtectedDelay3(), length=3)
    project.hook(0x1B00, PushDE(), length=1)
    project.hook(0x1B01, ManualTextScroll(), length=3)
    project.hook(0x1B04, PopDE(), length=1)
    project.hook(0x1B07, Sm83StoreAImmediate(ARROW_SLOT, 0x1B0A), length=3)
    project.hook(0x1B0A, PushDE(), length=1)
    project.hook(0x1B0B, ScrollTextUpOneLine(), length=3)
    project.hook(0x1B0E, ScrollTextUpOneLine(), length=3)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    _setup(state, 0, values)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    returned = collect_returns(project, state, RETURN)
    return [
        Endpoint(**assembly_registers(end), region=_region(end, 0), constraints=tuple(end.solver.constraints))
        for end in returned
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_place_string")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, NATIVE_MEMORY, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    end = manager.deadended[0]
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            region=_region(end, NATIVE_MEMORY),
            constraints=tuple(end.solver.constraints),
        )
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run red")
def test_place_string_cont_pathwise_equivalence() -> None:
    values = symbolic_registers("place_string_cont")
    values["h"] = claripy.BVV(DESTINATION >> 8, 8)
    values["l"] = claripy.BVV(DESTINATION & 0xFF, 8)
    values["d"] = claripy.BVV(SOURCE >> 8, 8)
    values["e"] = claripy.BVV(SOURCE & 0xFF, 8)
    assert_pathwise_equivalent(_assembly(values), _native(values), (*REGISTERS, "region"))
