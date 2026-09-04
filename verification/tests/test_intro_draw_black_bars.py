"""Proof for IntroDrawBlackBars."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
    assembly_registers,
    native_registers,
    set_assembly_registers,
    store_native_registers,
    symbolic_registers,
)
from verification.harness.rom import collect_returns, linked_bytes, rom_window, symbol_location

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF
EXPECTED = bytes.fromhex(
    "cdf05721a0c30e50cd075821b8c40e50cd075821009c0e80cd0758"
    "21c09d0e80c30758"
)
WRITES = ((0xC3A0, 0x50), (0xC4B8, 0x50), (0x9C00, 0x80), (0x9DC0, 0x80))


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
    writes: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class IntroClearScreen(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        for address in range(0x9C00, 0x9E40):
            self.state.memory.store(address, 0, 1)
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x40, 8)
        self.state.regs.b = claripy.BVV(0, 8)
        self.state.regs.c = claripy.BVV(0, 8)
        self.state.regs.h = claripy.BVV(0x9E, 8)
        self.state.regs.l = claripy.BVV(0x40, 8)
        self.jump(self.addr + 3)


class IntroPlaceBlackTiles(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        hl = (int(self.state.solver.eval(self.state.regs.h)) << 8) | int(
            self.state.solver.eval(self.state.regs.l)
        )
        count = int(self.state.solver.eval(self.state.regs.c))
        for offset in range(count):
            self.state.memory.store((hl + offset) & 0xFFFF, 1, 1)
        final = (hl + count) & 0xFFFF
        self.state.regs.a = claripy.BVV(1, 8)
        self.state.regs.f = claripy.BVV(0x42, 8)
        self.state.regs.c = claripy.BVV(0, 8)
        self.state.regs.h = claripy.BVV(final >> 8, 8)
        self.state.regs.l = claripy.BVV(final & 0xFF, 8)
        self.jump(self.addr + 3)


class IntroPlaceBlackTilesReturn(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        hl = (int(self.state.solver.eval(self.state.regs.h)) << 8) | int(
            self.state.solver.eval(self.state.regs.l)
        )
        count = int(self.state.solver.eval(self.state.regs.c))
        for offset in range(count):
            self.state.memory.store((hl + offset) & 0xFFFF, 1, 1)
        final = (hl + count) & 0xFFFF
        self.state.regs.a = claripy.BVV(1, 8)
        self.state.regs.c = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x42, 8)
        self.state.regs.h = claripy.BVV(final >> 8, 8)
        self.state.regs.l = claripy.BVV(final & 0xFF, 8)
        self.jump(DONE)


def _writes(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        *[
            state.memory.load(base + address + offset, 1)
            for address, count in WRITES
            for offset in range(count)
        ]
    )


def _assembly(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    loc = symbol_location(SYMBOLS, "IntroDrawBlackBars")
    base = loc.address
    project = angr.Project(
        rom_window(ROM, loc.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": base,
        },
    )
    project.hook(base, IntroClearScreen(), length=3)
    project.hook(base + 0x08, IntroPlaceBlackTiles(), length=3)
    project.hook(base + 0x10, IntroPlaceBlackTiles(), length=3)
    project.hook(base + 0x18, IntroPlaceBlackTiles(), length=3)
    project.hook(base + 0x20, IntroPlaceBlackTilesReturn(), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, inputs)
    end = collect_returns(project, state, DONE)[0]
    return [
        Endpoint(
            **assembly_registers(end),
            writes=_writes(end, 0),
            constraints=tuple(end.solver.constraints),
        )
    ]


def _native(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_intro_draw_black_bars")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, inputs)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            writes=_writes(end, NATIVE_MEMORY),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_intro_draw_black_bars_pathwise_equivalence() -> None:
    inputs = symbolic_registers("intro_draw_black_bars")
    assert_pathwise_equivalent(
        _assembly(inputs),
        _native(inputs),
        ("a", "f", "b", "c", "d", "e", "h", "l", "writes"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_intro_draw_black_bars_exact_linked_body() -> None:
    loc = symbol_location(SYMBOLS, "IntroDrawBlackBars")
    assert linked_bytes(ROM, loc, len(EXPECTED)) == EXPECTED
