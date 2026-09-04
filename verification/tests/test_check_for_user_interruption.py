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
from verification.harness.rom import linked_bytes, rom_window, symbol_location

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
DONE = 0xEFFF
H_VBLANK_OCCURRED = 0xFFD6
H_JOYPRESSED = 0xFFB3
H_JOYHELD = 0xFFB4
H_JOY5 = 0xFFB5
H_JOY6 = 0xFFB6
H_JOY7 = 0xFFB7
H_FRAMECOUNTER = 0xFFD5
PAD_UP_SELECT_B = 0x46
PAD_START_A = 0x09
EXPECTED = bytes.fromhex(
    "cdaf20c5cd3138c1f0b4fe46280bf0b5e6092005"
    "0d20e9a7c9"
    "37c9"
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
    memory: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class DelayFrameSummary(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        state = self.state
        state.memory.store(H_VBLANK_OCCURRED, claripy.BVV(0, 8))
        state.regs.a = claripy.BVV(0, 8)
        state.regs.f = claripy.BVV(0xA0, 8)
        self.jump(self.next_address)


class JoypadLowSensitivitySummary(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        state = self.state
        joy7 = state.memory.load(H_JOY7, 1)
        joy6 = state.memory.load(H_JOY6, 1)
        pressed = state.memory.load(H_JOYPRESSED, 1)
        held = state.memory.load(H_JOYHELD, 1)
        frame_counter = state.memory.load(H_FRAMECOUNTER, 1)
        joy5 = claripy.If(joy7 == 0, pressed, held)
        state.memory.store(H_JOY5, joy5)
        state.memory.store(
            H_FRAMECOUNTER,
            claripy.If(pressed != 0, claripy.BVV(30, 8), frame_counter),
        )
        state.memory.store(
            H_JOY5,
            claripy.If(
                pressed != 0,
                joy5,
                claripy.If(
                    frame_counter != 0,
                    claripy.BVV(0, 8),
                    claripy.If(
                        ((held & 0x03) != 0) & (joy6 == 0),
                        claripy.BVV(0, 8),
                        joy5,
                    ),
                ),
            ),
        )
        state.memory.store(
            H_FRAMECOUNTER,
            claripy.If(
                pressed != 0,
                claripy.BVV(30, 8),
                claripy.If(frame_counter != 0, frame_counter, claripy.BVV(5, 8)),
            ),
        )
        self.jump(self.next_address)

class ReturnSummary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(DONE)


class Boundary(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.jump(self.next_address)

class LoadMemoryA(angr.SimProcedure):
    def __init__(self, address: int, next_address: int) -> None:
        super().__init__()
        self.address = address
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self.address, 1)
        self.jump(self.next_address)

def _inputs(mode: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers("check_for_user_interruption")
    values["vblank"] = claripy.BVS("check_interrupt_vblank", 8)
    modes = {
        "held": (0x00, PAD_UP_SELECT_B, 0x00, 0x01, 0x01),
        "button": (0x01, 0x00, 0x00, 0x01, 0x00),
        "timeout": (0x00, 0x00, 0x00, 0x01, 0x01),
    }
    pressed, held, joy5, joy6, joy7 = modes[mode]
    values["joy_pressed"] = claripy.BVV(pressed, 8)
    values["joy_held"] = claripy.BVV(held, 8)
    values["joy5"] = claripy.BVV(joy5, 8)
    values["joy6"] = claripy.BVV(joy6, 8)
    values["joy7"] = claripy.BVV(joy7, 8)
    values["frame"] = claripy.BVV(0, 8)
    return values


def _setup(state: angr.SimState, base: int, values: dict[str, claripy.ast.BV]) -> None:
    state.memory.store(base + H_VBLANK_OCCURRED, values["vblank"])
    state.memory.store(base + H_JOYPRESSED, values["joy_pressed"])
    state.memory.store(base + H_JOYHELD, values["joy_held"])
    state.memory.store(base + H_JOY5, values["joy5"])
    state.memory.store(base + H_JOY6, values["joy6"])
    state.memory.store(base + H_JOY7, values["joy7"])
    state.memory.store(base + H_FRAMECOUNTER, values["frame"])


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        *(state.memory.load(base + address, 1) for address in (
            H_VBLANK_OCCURRED,
            H_JOYPRESSED,
            H_JOYHELD,
            H_JOY5,
            H_JOY6,
            H_JOY7,
            H_FRAMECOUNTER,
        ))
    )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "CheckForUserInterruption")
    continuation = symbol_location(SYMBOLS, "CheckForUserInterruption.input")
    assert continuation.address > location.address
    assert linked_bytes(ROM, location, continuation.address - location.address) + linked_bytes(
        ROM, continuation, symbol_location(SYMBOLS, "LoadDestinationWarpPosition").address - continuation.address
    ) == EXPECTED
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
    base = location.address
    delay = symbol_location(SYMBOLS, "DelayFrame")
    joypad = symbol_location(SYMBOLS, "JoypadLowSensitivity")
    assert delay.bank == joypad.bank == location.bank == 0
    project.hook(base + 0x00, DelayFrameSummary(base + 0x03), length=3)
    project.hook(base + 0x03, Boundary(base + 0x04), length=1)
    project.hook(base + 0x04, JoypadLowSensitivitySummary(base + 0x07), length=3)
    project.hook(base + 0x07, Boundary(base + 0x08), length=1)
    project.hook(base + 0x08, LoadMemoryA(H_JOYHELD, base + 0x0A), length=2)
    project.hook(base + 0x0E, LoadMemoryA(H_JOY5, base + 0x10), length=2)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.solver.add(values["c"] >= 1, values["c"] <= 2)
    _setup(state, 0, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(DONE, 16), endness="Iend_LE")
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=256)
    assert not manager.errored
    return [
        Endpoint(
            **assembly_registers(end),
            memory=_memory(end, 0),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_check_for_user_interruption")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.solver.add(values["c"] >= 1, values["c"] <= 2)
    _setup(state, NATIVE_MEMORY, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=_memory(end, NATIVE_MEMORY),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("mode", ("held", "button", "timeout"))
def test_check_for_user_interruption_pathwise_equivalence(mode: str) -> None:
    values = _inputs(mode)
    assert_pathwise_equivalent(_assembly(values), _native(values), (*REGISTERS, "memory"))
