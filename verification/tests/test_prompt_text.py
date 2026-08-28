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
    sm83_flags_to_z80,
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
W_LINK_STATE = 0xD12B
ARROW_SLOT = 0xC4F2
DONE_TEXT_PREV = 0x1AB2


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


class LoadLinkState(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(W_LINK_STATE, 1)
        self.jump(self.state.addr + 3)


class CompareFour(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        value = self.state.regs.a
        self.state.regs.f = claripy.If(
            value == 4,
            claripy.BVV(0x40, 8),
            claripy.BVV(0x02, 8),
        )
        self.jump(self.state.addr + 2)


class BranchZ(angr.SimProcedure):
    def __init__(self, taken: int, fallthrough: int) -> None:
        super().__init__()
        self.taken = taken
        self.fallthrough = fallthrough

    def run(self) -> None:  # type: ignore[override]
        condition = (self.state.regs.f & 0x40) != 0
        self.inhibit_autoret = True
        self.successors.add_successor(
            self.state.copy(), self.taken, condition, "Ijk_Boring"
        )
        self.successors.add_successor(
            self.state.copy(), self.fallthrough, claripy.Not(condition), "Ijk_Boring"
        )


class LoadArrow(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0xEE, 8)
        self.jump(self.state.addr + 2)


class StoreArrow(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(ARROW_SLOT, self.state.regs.a)
        self.jump(self.state.addr + 3)


class Delay3Boundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        # Delay3's final DEC C leaves Z|N set after the three DelayFrames.
        self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0xC0, 8))
        self.jump(self.state.addr + 3)


class ManualBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        link = self.state.memory.load(W_LINK_STATE, 1)
        battle = link == 4
        self.state.regs.a = claripy.If(battle, claripy.BVV(4, 8), claripy.BVV(0x90, 8))
        self.state.regs.f = claripy.If(
            battle,
            sm83_flags_to_z80(claripy.BVV(0xC0, 8)),
            sm83_flags_to_z80(claripy.BVV(0xC0, 8)),
        )
        self.state.regs.c = claripy.If(battle, claripy.BVV(65, 8), self.state.regs.c)
        self.jump(self.state.addr + 3)


class LoadSpace(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0x7F, 8)
        self.jump(self.state.addr + 2)


class DoneBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        sp = self.state.regs.sp
        self.state.regs.l = self.state.memory.load(sp, 1)
        self.state.regs.h = self.state.memory.load(sp + 1, 1)
        self.state.regs.d = claripy.BVV(DONE_TEXT_PREV >> 8, 8)
        self.state.regs.e = claripy.BVV(DONE_TEXT_PREV & 0xFF, 8)
        self.inhibit_autoret = True
        self.jump(RETURN)


def _setup(state: angr.SimState, base: int,
           values: dict[str, claripy.ast.BV], link_state: claripy.ast.BV,
           saved_h: claripy.ast.BV, saved_l: claripy.ast.BV) -> None:
    state.memory.store(base + W_LINK_STATE, link_state)
    state.memory.store(base + ARROW_SLOT, values["arrow"])
    state.memory.store(base + STACK, saved_l, endness="Iend_LE")
    state.memory.store(base + STACK + 1, saved_h, endness="Iend_LE")


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        state.memory.load(base + W_LINK_STATE, 1),
        state.memory.load(base + ARROW_SLOT, 1),
    )


def _assembly(values: dict[str, claripy.ast.BV], link_state: claripy.ast.BV,
              saved_h: claripy.ast.BV, saved_l: claripy.ast.BV) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "PromptText")
    assert linked_bytes(ROM, location, 24) == bytes.fromhex(
        "fa2bd1fe04caa21a3eeeeaf2c4cd3a1bcd98383e7feaf2c4"
    )
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    q = location.address
    project.hook(q, LoadLinkState(), length=3)
    project.hook(q + 3, CompareFour(), length=2)
    project.hook(q + 5, BranchZ(q + 13, q + 8), length=3)
    project.hook(q + 8, LoadArrow(), length=2)
    project.hook(q + 10, StoreArrow(), length=3)
    project.hook(q + 13, Delay3Boundary(), length=3)
    project.hook(q + 16, ManualBoundary(), length=3)
    project.hook(q + 19, LoadSpace(), length=2)
    project.hook(q + 21, StoreArrow(), length=3)
    project.hook(q + 24, DoneBoundary(), length=1)
    state = project.factory.blank_state(addr=q)
    set_assembly_registers(state, values)
    state.regs.sp = STACK
    _setup(state, 0, values, link_state, saved_h, saved_l)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    endpoints = collect_returns(project, state, RETURN)
    return [Endpoint(**assembly_registers(end), memory=_memory(end, 0),
                     constraints=tuple(end.solver.constraints)) for end in endpoints]


def _native(values: dict[str, claripy.ast.BV], link_state: claripy.ast.BV,
            saved_h: claripy.ast.BV, saved_l: claripy.ast.BV) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_prompt_text")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE,
                                       NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, saved_h)
    state.memory.store(NATIVE_STATE + 9, saved_l)
    _setup(state, NATIVE_MEMORY, values, link_state, saved_h, saved_l)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [Endpoint(**native_registers(end, NATIVE_STATE),
                     memory=_memory(end, NATIVE_MEMORY),
                     constraints=tuple(end.solver.constraints))
            for end in manager.deadended]


@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("link_value", (0x04, 0x05))
def test_prompt_text_pathwise_equivalence(link_value: int) -> None:
    values = symbolic_registers("prompt_text")
    values["arrow"] = claripy.BVS("prompt_text_arrow", 8)
    link_state = claripy.BVV(link_value, 8)
    saved_h = claripy.BVS("prompt_text_saved_h", 8)
    saved_l = claripy.BVS("prompt_text_saved_l", 8)
    assert_pathwise_equivalent(
        _assembly(values, link_state, saved_h, saved_l),
        _native(values, link_state, saved_h, saved_l),
        (*REGISTERS, "memory"),
    )
