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
STACK = 0xD000
RETURN = 0xEFFF
CURSOR = 0xC4F0
TEXT_ID_ERROR_MINUS_ONE = 0x19F3


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
    constraints: tuple[claripy.ast.Bool, ...]


class CopyBCFromHL(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.b = self.state.regs.h
        self.state.regs.c = self.state.regs.l
        self.jump(self.state.addr + 2)


class PopHL(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        sp = self.state.regs.sp
        self.state.regs.l = self.state.memory.load(sp, 1)
        self.state.regs.h = self.state.memory.load(sp + 1, 1)
        self.state.regs.sp = sp + 2
        self.jump(self.state.addr + 1)


class LoadDE(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.d = claripy.BVV(0x19, 8)
        self.state.regs.e = claripy.BVV(0xF4, 8)
        self.jump(self.state.addr + 3)


class DecDE(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.e = self.state.regs.e - 1
        self.state.regs.d = self.state.regs.d - claripy.If(
            self.state.regs.e == 0xFF, claripy.BVV(1, 8), claripy.BVV(0, 8)
        )
        self.jump(self.state.addr + 1)


class ReturnBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.jump(RETURN)


def _assembly(values: dict[str, claripy.ast.BV], saved_h: claripy.ast.BV,
              saved_l: claripy.ast.BV) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "NullChar")
    assert linked_bytes(ROM, location, 8) == bytes.fromhex("444de111f4191bc9")
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    q = location.address
    project.hook(q, CopyBCFromHL(), length=2)
    project.hook(q + 2, PopHL(), length=1)
    project.hook(q + 3, LoadDE(), length=3)
    project.hook(q + 6, DecDE(), length=1)
    project.hook(q + 7, ReturnBoundary(), length=1)
    state = project.factory.blank_state(addr=q)
    set_assembly_registers(state, values)
    state.regs.h = claripy.BVV(CURSOR >> 8, 8)
    state.regs.l = claripy.BVV(CURSOR & 0xFF, 8)
    state.regs.sp = STACK
    state.memory.store(STACK, saved_l, endness="Iend_LE")
    state.memory.store(STACK + 1, saved_h, endness="Iend_LE")
    endpoints = collect_returns(project, state, RETURN)
    return [Endpoint(**assembly_registers(end),
                     constraints=tuple(end.solver.constraints)) for end in endpoints]


def _native(values: dict[str, claripy.ast.BV], saved_h: claripy.ast.BV,
            saved_l: claripy.ast.BV) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_null_char")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, saved_h)
    state.memory.store(NATIVE_STATE + 9, saved_l)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    end = manager.deadended[0]
    return [Endpoint(**native_registers(end, NATIVE_STATE),
                     constraints=tuple(end.solver.constraints))]


@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_null_char_pathwise_equivalence() -> None:
    values = symbolic_registers("null_char")
    saved_h = claripy.BVS("null_char_saved_h", 8)
    saved_l = claripy.BVS("null_char_saved_l", 8)
    values["h"] = claripy.BVV(CURSOR >> 8, 8)
    values["l"] = claripy.BVV(CURSOR & 0xFF, 8)
    assert_pathwise_equivalent(
        _assembly(values, saved_h, saved_l),
        _native(values, saved_h, saved_l),
        (*REGISTERS,),
    )
