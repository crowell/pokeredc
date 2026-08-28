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
from verification.harness.rom import collect_returns, linked_bytes, rom_window, sm83_flags_to_z80, symbol_location

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
CLEAR_CURSOR = 0xC469
CLEAR_LENGTH = 138  # seven 18-byte rows at a 20-byte screen stride
TEXT_PAGE_CURSOR = 0xC47D


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
        self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0xC0, 8))
        self.jump(self.state.addr + 3)


class ManualBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        link = self.state.memory.load(W_LINK_STATE, 1)
        battle = link == 4
        self.state.regs.a = claripy.If(battle, claripy.BVV(4, 8), claripy.BVV(0x90, 8))
        self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0xC0, 8))
        self.state.regs.c = claripy.If(battle, claripy.BVV(65, 8), self.state.regs.c)
        self.jump(self.state.addr + 3)


class LoadHL(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = claripy.BVV(TEXT_PAGE_CURSOR >> 8, 8)
        self.state.regs.l = claripy.BVV(TEXT_PAGE_CURSOR & 0xFF, 8)
        self.jump(self.state.addr + 3)


class ClearBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        for row in range(7):
            for column in range(18):
                self.state.memory.store(
                    CLEAR_CURSOR + row * 20 + column, claripy.BVV(0x7F, 8)
                )
        self.state.regs.a = claripy.BVV(0x7F, 8)
        self.state.regs.f = claripy.BVV(0xC0, 8)
        self.state.regs.b = claripy.BVV(0, 8)
        self.state.regs.c = claripy.BVV(18, 8)
        self.state.regs.d = claripy.BVV(0, 8)
        self.state.regs.e = claripy.BVV(20, 8)
        self.state.regs.h = claripy.BVV(0xC4, 8)
        self.state.regs.l = claripy.BVV(0xE7, 8)
        self.jump(self.state.addr + 3)


class LoadC20(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.c = claripy.BVV(20, 8)
        self.jump(self.state.addr + 2)


class Delay20Boundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x42, 8)
        self.state.regs.c = claripy.BVV(0, 8)
        self.jump(self.state.addr + 3)


class PushDE(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        sp = self.state.regs.sp - 2
        self.state.memory.store(sp, self.state.regs.e, endness="Iend_LE")
        self.state.memory.store(sp + 1, self.state.regs.d, endness="Iend_LE")
        self.state.regs.sp = sp
        self.jump(self.state.addr + 1)


class PopDE(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        sp = self.state.regs.sp
        self.state.regs.e = self.state.memory.load(sp, 1)
        self.state.regs.d = self.state.memory.load(sp + 1, 1)
        self.state.regs.sp = sp + 2
        self.jump(self.state.addr + 1)


class PopHL(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        sp = self.state.regs.sp
        self.state.regs.l = self.state.memory.load(sp, 1)
        self.state.regs.h = self.state.memory.load(sp + 1, 1)
        self.state.regs.sp = sp + 2
        self.jump(self.state.addr + 1)


class PushHL(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        sp = self.state.regs.sp - 2
        self.state.memory.store(sp, self.state.regs.l, endness="Iend_LE")
        self.state.memory.store(sp + 1, self.state.regs.h, endness="Iend_LE")
        self.state.regs.sp = sp
        self.jump(self.state.addr + 1)


class ContinuationBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.jump(RETURN)


def _setup(state: angr.SimState, base: int,
           values: dict[str, claripy.ast.BV], link_state: claripy.ast.BV,
           saved_d: claripy.ast.BV, saved_e: claripy.ast.BV) -> None:
    state.memory.store(base + W_LINK_STATE, link_state)
    state.memory.store(base + ARROW_SLOT, values["arrow"])
    for offset in range(CLEAR_LENGTH):
        state.memory.store(base + CLEAR_CURSOR + offset, values[f"clear{offset}"])
    state.memory.store(base + STACK, claripy.BVV(0x12, 8), endness="Iend_LE")
    state.memory.store(base + STACK + 1, claripy.BVV(0x34, 8), endness="Iend_LE")


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        state.memory.load(base + W_LINK_STATE, 1),
        state.memory.load(base + ARROW_SLOT, 1),
        *(state.memory.load(base + CLEAR_CURSOR + i, 1)
          for i in range(CLEAR_LENGTH)),
    )


def _assembly(values: dict[str, claripy.ast.BV], link_state: claripy.ast.BV,
              saved_d: claripy.ast.BV, saved_e: claripy.ast.BV) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "PageChar")
    assert linked_bytes(ROM, location, 35) == bytes.fromhex(
        "d53eeeeaf2c4cd3a1bcd98382169c4011207cdc4180e14cd3937d1e1217dc4e5c3e819"
    )
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    q = location.address
    project.hook(q, PushDE(), length=1)
    project.hook(q + 1, LoadArrow(), length=2)
    project.hook(q + 3, StoreArrow(), length=3)
    project.hook(q + 6, Delay3Boundary(), length=3)
    project.hook(q + 9, ManualBoundary(), length=3)
    project.hook(q + 12, LoadHL(), length=3)
    project.hook(q + 18, ClearBoundary(), length=3)
    project.hook(q + 21, LoadC20(), length=2)
    project.hook(q + 23, Delay20Boundary(), length=3)
    project.hook(q + 26, PopDE(), length=1)
    project.hook(q + 27, PopHL(), length=1)
    project.hook(q + 28, LoadHL(), length=3)
    project.hook(q + 31, PushHL(), length=1)
    project.hook(q + 32, ContinuationBoundary(), length=3)
    state = project.factory.blank_state(addr=q)
    set_assembly_registers(state, values)
    state.regs.sp = STACK
    _setup(state, 0, values, link_state, saved_d, saved_e)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    endpoints = collect_returns(project, state, RETURN)
    return [Endpoint(**assembly_registers(end), memory=_memory(end, 0),
                     constraints=tuple(end.solver.constraints)) for end in endpoints]


def _native(values: dict[str, claripy.ast.BV], link_state: claripy.ast.BV,
            saved_d: claripy.ast.BV, saved_e: claripy.ast.BV) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_page_char")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE,
                                       NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, saved_d)
    state.memory.store(NATIVE_STATE + 9, saved_e)
    _setup(state, NATIVE_MEMORY, values, link_state, saved_d, saved_e)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    end = manager.deadended[0]
    return [Endpoint(**native_registers(end, NATIVE_STATE),
                     memory=_memory(end, NATIVE_MEMORY),
                     constraints=tuple(end.solver.constraints))]


@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("link_value", (0x04, 0x05))
def test_page_char_pathwise_equivalence(link_value: int) -> None:
    values = symbolic_registers("page_char")
    values["arrow"] = claripy.BVS("page_char_arrow", 8)
    for offset in range(CLEAR_LENGTH):
        values[f"clear{offset}"] = claripy.BVS(f"page_char_clear_{offset}", 8)
    saved_d = claripy.BVS("page_char_saved_d", 8)
    saved_e = claripy.BVS("page_char_saved_e", 8)
    values["d"] = saved_d
    values["e"] = saved_e
    link_state = claripy.BVV(link_value, 8)
    assert_pathwise_equivalent(
        _assembly(values, link_state, saved_d, saved_e),
        _native(values, link_state, saved_d, saved_e),
        (*REGISTERS, "memory"),
    )
