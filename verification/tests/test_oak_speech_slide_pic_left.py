"""Proof for OakSpeechSlidePicLeft through the common-loop entry."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.rom import (
    collect_returns,
    linked_bytes,
    rom_window,
    symbol_location,
)

from verification.harness.registers import (
    assembly_registers,
    native_registers,
    set_assembly_registers,
    store_native_registers,
    symbolic_registers,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
NAME_BUFFER = 0xCD6D
NAME_DEST = 0xD158
NAME_BYTES = claripy.BVS("oak_slide_left_name", 88)
TEXT_BOX_TOP_LEFT = 0xC3A0
DONE = 0xEFFF
EXPECTED = bytes.fromhex(
    "d521a0c3010b0ccdc4180e0acd3937d1216dcd010b00cdb500cdd73d"
    "21fcc3117d063eff1807"
)


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
    screen: claripy.ast.BV
    name: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class ClearScreenArea(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        for row in range(12):
            for column in range(11):
                self.state.memory.store(
                    TEXT_BOX_TOP_LEFT + row * 20 + column, 0x7F, 1
                )
        self.state.regs.a = claripy.BVV(0x7F, 8)
        self.state.regs.b = claripy.BVV(0, 8)
        self.state.regs.c = claripy.BVV(0x0B, 8)
        self.state.regs.d = claripy.BVV(0, 8)
        self.state.regs.e = claripy.BVV(20, 8)
        self.state.regs.h = claripy.BVV(0xC4, 8)
        self.state.regs.l = claripy.BVV(0x90, 8)
        self.state.regs.f = claripy.BVV(0x42, 8)
        self.jump(self.addr + 3)


class DelayFrames(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.c = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x42, 8)
        self.jump(self.addr + 3)


class CopyData(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        source = self.state.regs.hl
        destination = self.state.regs.de
        for index in range(11):
            self.state.memory.store(
                destination + index, self.state.memory.load(source + index, 1)
            )
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.b = claripy.BVV(0, 8)
        self.state.regs.c = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x40, 8)
        self.state.regs.h = claripy.BVV(0xCD, 8)
        self.state.regs.l = claripy.BVV(0x78, 8)
        self.state.regs.d = claripy.BVV((NAME_DEST + 11) >> 8, 8)
        self.state.regs.e = claripy.BVV((NAME_DEST + 11) & 0xFF, 8)
        self.jump(self.addr + 3)


class JumpTo(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(DONE)

def _screen(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        *[
            state.memory.load(TEXT_BOX_TOP_LEFT + row * 20 + column + base, 1)
            for row in range(12)
            for column in range(11)
        ]
    )


def _name(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(*[state.memory.load(base + NAME_DEST + i, 1) for i in range(11)])


def _assembly(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    loc = symbol_location(SYMBOLS, "OakSpeechSlidePicLeft")
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
    project.hook(base + 0x07, ClearScreenArea(), length=3)
    project.hook(base + 0x0C, DelayFrames(), length=3)
    project.hook(base + 0x16, CopyData(), length=3)
    project.hook(base + 0x19, DelayFrames(), length=3)
    project.hook(base + 0x24, JumpTo(), length=2)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, inputs)
    state.regs.d = claripy.BVV(NAME_DEST >> 8, 8)
    state.regs.e = claripy.BVV(NAME_DEST & 0xFF, 8)
    state.memory.store(NAME_BUFFER, NAME_BYTES)
    state.regs.sp = claripy.BVV(0xD000, 16)
    returned = collect_returns(project, state, DONE)
    return [
        Endpoint(
            **assembly_registers(end),
            screen=_screen(end, 0),
            name=_name(end, 0),
            constraints=tuple(end.solver.constraints),
        )
        for end in returned
    ]


def _native(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_oak_speech_slide_pic_left")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 4, claripy.BVV(NAME_DEST >> 8, 8))
    state.memory.store(NATIVE_STATE + 5, claripy.BVV(NAME_DEST & 0xFF, 8))
    state.memory.store(NATIVE_MEMORY + NAME_BUFFER, NAME_BYTES)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            screen=_screen(end, NATIVE_MEMORY),
            name=_name(end, NATIVE_MEMORY),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_oak_speech_slide_pic_left_pathwise_equivalence() -> None:
    inputs = symbolic_registers("oak_slide_left")
    assert_pathwise_equivalent(
        _assembly(inputs),
        _native(inputs),
        ("a", "f", "b", "c", "d", "e", "h", "l", "screen", "name"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_oak_speech_slide_pic_left_exact_linked_body() -> None:
    loc = symbol_location(SYMBOLS, "OakSpeechSlidePicLeft")
    assert linked_bytes(ROM, loc, len(EXPECTED)) == EXPECTED
