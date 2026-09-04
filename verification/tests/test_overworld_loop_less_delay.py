"""Proof for OverworldLoopLessDelay through LoadGBPal."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS, assembly_registers, native_registers, set_assembly_registers, store_native_registers, symbolic_registers
from verification.harness.rom import linked_bytes, rom_window, sm83_flags_to_z80, symbol_location

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
W_MAP_PAL_OFFSET = 0xD35D
FADE_PAL4 = 0x2116
R_BGP = 0xFF47
R_OBP0 = 0xFF48
R_OBP1 = 0xFF49
EXPECTED = bytes.fromhex("cdaf20cdba20")


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
    palette: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class DelayFrameBoundary(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__()
        self._target = target

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x50, 8)
        self.jump(self._target)


class LoadGBPalBoundary(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__()
        self._target = target

    def run(self) -> None:  # type: ignore[override]
        state = self.state
        offset = state.memory.load(W_MAP_PAL_OFFSET, 1)
        state.regs.a = state.memory.load(FADE_PAL4 + 2, 1)
        state.regs.b = offset
        state.regs.h = claripy.BVV(0x21, 8)
        state.regs.l = claripy.BVV(0x19, 8)
        state.regs.f = sm83_flags_to_z80(claripy.BVV(0x40, 8))
        state.memory.store(R_BGP, state.memory.load(FADE_PAL4, 1))
        state.memory.store(R_OBP0, state.memory.load(FADE_PAL4 + 1, 1))
        state.memory.store(R_OBP1, state.memory.load(FADE_PAL4 + 2, 1))
        self.jump(self._target)


def _assembly(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "OverworldLoopLessDelay")
    delay_frame = symbol_location(SYMBOLS, "DelayFrame")
    load_gb_pal = symbol_location(SYMBOLS, "LoadGBPal")
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
    project.hook(delay_frame.address, DelayFrameBoundary(location.address + 0x03), length=1)
    project.hook(load_gb_pal.address, LoadGBPalBoundary(location.address + 0x06), length=1)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    state.memory.store(W_MAP_PAL_OFFSET, claripy.BVV(0, 8))
    state.memory.store(FADE_PAL4, claripy.BVV(0xE4, 8))
    state.memory.store(FADE_PAL4 + 1, claripy.BVV(0xD0, 8))
    state.memory.store(FADE_PAL4 + 2, claripy.BVV(0xE0, 8))
    manager = project.factory.simulation_manager(state)
    manager.explore(find=lambda candidate: candidate.addr == location.address + 0x06)
    assert not manager.errored
    return [
        Endpoint(
            **assembly_registers(end),
            palette=claripy.Concat(end.memory.load(R_BGP, 1), end.memory.load(R_OBP0, 1), end.memory.load(R_OBP1, 1)),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_overworld_loop_less_delay")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_MEMORY + W_MAP_PAL_OFFSET, claripy.BVV(0, 8))
    state.memory.store(NATIVE_MEMORY + FADE_PAL4, claripy.BVV(0xE4, 8))
    state.memory.store(NATIVE_MEMORY + FADE_PAL4 + 1, claripy.BVV(0xD0, 8))
    state.memory.store(NATIVE_MEMORY + FADE_PAL4 + 2, claripy.BVV(0xE0, 8))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            palette=claripy.Concat(end.memory.load(NATIVE_MEMORY + R_BGP, 1), end.memory.load(NATIVE_MEMORY + R_OBP0, 1), end.memory.load(NATIVE_MEMORY + R_OBP1, 1)),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_overworld_loop_less_delay_pathwise_equivalence() -> None:
    inputs = symbolic_registers("overworld_loop_less_delay")
    assert_pathwise_equivalent(_assembly(inputs), _native(inputs), (*REGISTERS, "palette"))


def test_overworld_loop_less_delay_exact_prefix() -> None:
    location = symbol_location(SYMBOLS, "OverworldLoopLessDelay")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
