from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS, assembly_registers, native_registers, set_assembly_registers, store_native_registers, symbolic_registers
from verification.harness.rom import rom_window, symbol_location

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
DONE = 0xEFFF
ANIMATION_BLINK_MON = 0x536F

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

class LoadBlinkPointer(angr.SimProcedure):
    def run(self) -> None:
        self.inhibit_autoret = True
        state = self.state.copy()
        state.regs.h = claripy.BVV(ANIMATION_BLINK_MON >> 8, 8)
        state.regs.l = claripy.BVV(ANIMATION_BLINK_MON & 0xFF, 8)
        self.successors.add_successor(state, self.addr + 3, claripy.BoolV(True), "Ijk_Boring")

class ContinuationBoundary(angr.SimProcedure):
    def run(self) -> None:
        self.inhibit_autoret = True
        self.successors.add_successor(self.state.copy(), DONE, claripy.BoolV(True), "Ijk_Boring")

def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "AnimationBlinkEnemyMon")
    continuation = symbol_location(SYMBOLS, "CallWithTurnFlipped")
    project = angr.Project(rom_window(ROM, location.bank), auto_load_libs=False, rebase_granularity=0x100, main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0, "entry_point": location.address})
    project.hook(location.address, LoadBlinkPointer(), length=3)
    project.hook(location.address + 3, ContinuationBoundary(), length=3)
    project.hook(continuation.address, ContinuationBoundary(), length=1)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored
    return [Endpoint(**assembly_registers(end), constraints=tuple(end.solver.constraints)) for end in manager.found]

def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_animation_blink_enemy_mon")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [Endpoint(**native_registers(end, NATIVE_STATE), constraints=tuple(end.solver.constraints)) for end in manager.deadended]

@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_animation_blink_enemy_mon_entry_pathwise_equivalence() -> None:
    values = symbolic_registers("animation_blink_enemy_mon")
    assert_pathwise_equivalent(_assembly(values), _native(values), REGISTERS)
