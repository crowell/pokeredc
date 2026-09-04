"""Proof for the OakSpeech setup prefix through PrepareOakSpeech."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import assembly_registers, native_registers, set_assembly_registers, store_native_registers, symbolic_registers
from verification.harness.rom import collect_returns, linked_bytes, rom_window, sm83_flags_to_z80, symbol_location

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF
W_OPTIONS_INITIALIZED = 0xD08A
DEBUG_NEW_GAME_PLAYER_NAME = 0x45AA
DEBUG_NEW_GAME_RIVAL_NAME = 0x45B1
EXPECTED = bytes.fromhex("3effcdb1233e024f3eefcda123cd0f19cda036cdca60")
PLAYER_NAME = bytes.fromhex("8d888d93848d50928e8d98")
RIVAL_NAME = bytes.fromhex("928e8d9850fa5fdaea91cf")


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


class CallBoundary(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.jump(self._next_address)


class PrepareOakSpeech(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        state = self.state
        state.regs.a = claripy.BVV(RIVAL_NAME[-1], 8)
        state.regs.f = sm83_flags_to_z80(claripy.BVV(0x80, 8))
        state.regs.b = claripy.BVV(0, 8)
        state.regs.c = claripy.BVV(0, 8)
        state.regs.h = claripy.BVV(0x45, 8)
        state.regs.l = claripy.BVV(0xBC, 8)
        state.regs.d = claripy.BVV(0xD3, 8)
        state.regs.e = claripy.BVV(0x55, 8)
        self.jump(return_from_call(state))


def return_from_call(state: angr.SimState) -> int:
    stack = state.solver.eval(state.regs.sp)
    target = state.solver.eval(state.memory.load(stack, 2, endness="Iend_LE"))
    state.regs.sp = claripy.BVV((stack + 2) & 0xFFFF, 16)
    return target


def _assembly(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    loc = symbol_location(SYMBOLS, "OakSpeech")
    base = loc.address
    project = angr.Project(rom_window(ROM, loc.bank), auto_load_libs=False, rebase_granularity=0x100, main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0, "entry_point": base})
    project.hook(base + 0x02, CallBoundary(base + 0x05), length=3)
    project.hook(base + 0x0A, CallBoundary(base + 0x0D), length=3)
    project.hook(base + 0x0D, CallBoundary(base + 0x10), length=3)
    project.hook(base + 0x10, CallBoundary(base + 0x13), length=3)
    project.hook(base + 0x13, PrepareOakSpeech(), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, inputs)
    state.regs.sp = 0xD000
    state.memory.store(0xD000, claripy.BVV(DONE, 16), endness="Iend_LE")
    return [Endpoint(**assembly_registers(end), constraints=tuple(end.solver.constraints)) for end in collect_returns(project, state, DONE)]


def _native(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_oak_speech")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_MEMORY + W_OPTIONS_INITIALIZED, claripy.BVV(1, 8))
    state.memory.store(NATIVE_MEMORY + DEBUG_NEW_GAME_PLAYER_NAME, PLAYER_NAME)
    state.memory.store(NATIVE_MEMORY + DEBUG_NEW_GAME_RIVAL_NAME, RIVAL_NAME)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [Endpoint(**native_registers(end, NATIVE_STATE), constraints=tuple(end.solver.constraints)) for end in manager.deadended]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_oak_speech_setup_prefix_pathwise_equivalence() -> None:
    inputs = symbolic_registers("oak_speech")
    assert_pathwise_equivalent(_assembly(inputs), _native(inputs), ("a", "f", "b", "c", "d", "e", "h", "l"))


def test_oak_speech_exact_linked_prefix() -> None:
    loc = symbol_location(SYMBOLS, "OakSpeech")
    assert linked_bytes(ROM, loc, len(EXPECTED)) == EXPECTED
