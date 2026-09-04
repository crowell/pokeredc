"""Proof for PlayIntro's orchestration and cleanup path."""

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
H_JOY_HELD = 0xFFB4
H_AUTO_BG_TRANSFER_ENABLED = 0xFFBA
H_SCX = 0xFFAE
EXPECTED = bytes.fromhex("afe0b43ce0bacd8a58cd9d56cdd820afe0aee0bacd8200cdaf20c9")


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
    joy_held: claripy.ast.BV
    auto_transfer: claripy.ast.BV
    scx: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class Setup(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(1, 8)
        self.state.regs.f = claripy.BVV(0, 8)
        self.state.memory.store(H_JOY_HELD, 0, 1)
        self.state.memory.store(H_AUTO_BG_TRANSFER_ENABLED, 1, 1)
        self.jump(self.addr + 6)


class CleanupSetup(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x40, 8)
        self.state.memory.store(H_SCX, 0, 1)
        self.state.memory.store(H_AUTO_BG_TRANSFER_ENABLED, 0, 1)
        self.jump(self.addr + 5)


class CallBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(self.addr + 3)


class ClearSprites(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x40, 8)
        self.state.regs.b = claripy.BVV(0, 8)
        self.state.regs.h = claripy.BVV(0xC3, 8)
        self.state.regs.l = claripy.BVV(0xA0, 8)
        self.jump(self.addr + 3)


class Return(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(DONE)

class DelayFrame(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x50, 8)
        self.jump(self.addr + 3)


def _assembly(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    loc = symbol_location(SYMBOLS, "PlayIntro")
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
    project.hook(base, Setup(), length=6)
    project.hook(base + 0x06, CallBoundary(), length=3)
    project.hook(base + 0x09, CallBoundary(), length=3)
    project.hook(base + 0x0C, CallBoundary(), length=3)
    project.hook(base + 0x0F, CleanupSetup(), length=5)
    project.hook(base + 0x14, ClearSprites(), length=3)
    project.hook(base + 0x17, DelayFrame(), length=3)
    project.hook(base + 0x1A, Return(), length=1)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, inputs)
    returned = collect_returns(project, state, DONE)
    return [
        Endpoint(
            **assembly_registers(end),
            joy_held=end.memory.load(H_JOY_HELD, 1),
            auto_transfer=end.memory.load(H_AUTO_BG_TRANSFER_ENABLED, 1),
            scx=end.memory.load(H_SCX, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in returned
    ]


def _native(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_play_intro")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, inputs)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            joy_held=end.memory.load(NATIVE_MEMORY + H_JOY_HELD, 1),
            auto_transfer=end.memory.load(NATIVE_MEMORY + H_AUTO_BG_TRANSFER_ENABLED, 1),
            scx=end.memory.load(NATIVE_MEMORY + H_SCX, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_play_intro_pathwise_equivalence() -> None:
    inputs = symbolic_registers("play_intro")
    assert_pathwise_equivalent(
        _assembly(inputs),
        _native(inputs),
        ("a", "f", "b", "c", "d", "e", "h", "l", "joy_held", "auto_transfer", "scx"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_play_intro_exact_linked_body() -> None:
    loc = symbol_location(SYMBOLS, "PlayIntro")
    assert linked_bytes(ROM, loc, len(EXPECTED)) == EXPECTED
