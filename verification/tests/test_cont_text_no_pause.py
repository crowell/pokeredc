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
REGION = 0xC4A4
REGION_LENGTH = 80
TEXT_CURSOR = 0xC4E1


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


class ScrollSite(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        for offset in range(60):
            value = self.state.memory.load(REGION + 20 + offset, 1)
            self.state.memory.store(REGION + offset, value)
        for offset in range(18):
            self.state.memory.store(REGION + 61 + offset, claripy.BVV(0x7F, 8))
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x42, 8)
        self.state.regs.b = claripy.BVV(0, 8)
        self.state.regs.d = claripy.BVV(0xC4, 8)
        self.state.regs.e = claripy.BVV(0xE0, 8)
        self.state.regs.h = claripy.BVV(0xC4, 8)
        self.state.regs.l = claripy.BVV(0xF3, 8)
        self.jump(self.state.addr + 3)


class LoadHL(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = claripy.BVV(TEXT_CURSOR >> 8, 8)
        self.state.regs.l = claripy.BVV(TEXT_CURSOR & 0xFF, 8)
        self.jump(self.state.addr + 3)


class PopDE(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        sp = self.state.regs.sp
        self.state.regs.e = self.state.memory.load(sp, 1)
        self.state.regs.d = self.state.memory.load(sp + 1, 1)
        self.state.regs.sp = sp + 2
        self.jump(self.state.addr + 1)


class PushDE(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        sp = self.state.regs.sp - 2
        self.state.memory.store(sp, self.state.regs.e, endness="Iend_LE")
        self.state.memory.store(sp + 1, self.state.regs.d, endness="Iend_LE")
        self.state.regs.sp = sp
        self.jump(self.state.addr + 1)


class ContinuationBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.jump(RETURN)


def _setup(state: angr.SimState, base: int,
           values: dict[str, claripy.ast.BV], saved_d: claripy.ast.BV,
           saved_e: claripy.ast.BV) -> None:
    for offset in range(REGION_LENGTH):
        state.memory.store(base + REGION + offset, values[f"region{offset}"])
    state.memory.store(base + STACK, saved_e, endness="Iend_LE")
    state.memory.store(base + STACK + 1, saved_d, endness="Iend_LE")


def _region(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(*(state.memory.load(base + REGION + i, 1)
                            for i in range(REGION_LENGTH)))


def _assembly(values: dict[str, claripy.ast.BV], saved_d: claripy.ast.BV,
              saved_e: claripy.ast.BV) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "_ContTextNoPause")
    assert linked_bytes(ROM, location, 14) == bytes.fromhex("d5cd181bcd181b21e1c4d1c3e819")
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    q = location.address
    project.hook(q, PushDE(), length=1)
    project.hook(q + 1, ScrollSite(), length=3)
    project.hook(q + 4, ScrollSite(), length=3)
    project.hook(q + 7, LoadHL(), length=3)
    project.hook(q + 10, PopDE(), length=1)
    project.hook(q + 11, ContinuationBoundary(), length=3)
    state = project.factory.blank_state(addr=q)
    set_assembly_registers(state, values)
    state.regs.sp = STACK
    # Model the initial push de by placing the saved pointer at SP.
    state.memory.store(STACK, saved_e, endness="Iend_LE")
    state.memory.store(STACK + 1, saved_d, endness="Iend_LE")
    _setup(state, 0, values, saved_d, saved_e)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    endpoints = collect_returns(project, state, RETURN)
    return [Endpoint(**assembly_registers(end), region=_region(end, 0),
                     constraints=tuple(end.solver.constraints)) for end in endpoints]


def _native(values: dict[str, claripy.ast.BV], saved_d: claripy.ast.BV,
            saved_e: claripy.ast.BV) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_cont_text_no_pause")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE,
                                       NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, saved_d)
    state.memory.store(NATIVE_STATE + 9, saved_e)
    _setup(state, NATIVE_MEMORY, values, saved_d, saved_e)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    end = manager.deadended[0]
    return [Endpoint(**native_registers(end, NATIVE_STATE),
                     region=_region(end, NATIVE_MEMORY),
                     constraints=tuple(end.solver.constraints))]


@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_cont_text_no_pause_pathwise_equivalence() -> None:
    values = symbolic_registers("cont_text_no_pause")
    for offset in range(REGION_LENGTH):
        values[f"region{offset}"] = claripy.BVS(
            f"cont_text_region_{offset}", 8)
    saved_d = claripy.BVS("cont_text_saved_d", 8)
    saved_e = claripy.BVS("cont_text_saved_e", 8)
    values["d"] = saved_d
    values["e"] = saved_e
    assert_pathwise_equivalent(
        _assembly(values, saved_d, saved_e),
        _native(values, saved_d, saved_e),
        (*REGISTERS, "region"),
    )
