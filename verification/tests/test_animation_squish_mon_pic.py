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
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF
DIRECTION = 0xD09F

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
    direction: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]

class LoadDirection(angr.SimProcedure):
    def run(self) -> None:
        self.inhibit_autoret = True
        state = self.state.copy()
        state.regs.a = state.memory.load(DIRECTION, 1)
        self.successors.add_successor(state, self.addr + 3, claripy.BoolV(True), "Ijk_Boring")

class CompareZero(angr.SimProcedure):
    def run(self) -> None:
        self.inhibit_autoret = True
        state = self.state.copy()
        state.regs.f = claripy.BVV(0x02, 8) | claripy.If(state.regs.a == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        self.successors.add_successor(state, self.addr + 2, claripy.BoolV(True), "Ijk_Boring")

class ContinuationBoundary(angr.SimProcedure):
    def run(self) -> None:
        self.inhibit_autoret = True
        self.successors.add_successor(self.state.copy(), DONE, claripy.BoolV(True), "Ijk_Boring")

def _endpoint(state: angr.SimState, base: int, assembly: bool) -> Endpoint:
    return Endpoint(**(assembly_registers(state) if assembly else native_registers(state, NATIVE_STATE)), direction=state.memory.load(base + DIRECTION, 1), constraints=tuple(state.solver.constraints))

def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "_AnimationSquishMonPic")
    left = symbol_location(SYMBOLS, "AnimCopyRowLeft")
    right = symbol_location(SYMBOLS, "AnimCopyRowRight")
    project = angr.Project(rom_window(ROM, location.bank), auto_load_libs=False, rebase_granularity=0x100, main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":location.address})
    project.hook(location.address + 6, LoadDirection(), length=3)
    project.hook(location.address + 9, CompareZero(), length=2)
    project.hook(left.address, ContinuationBoundary(), length=1)
    project.hook(right.address, ContinuationBoundary(), length=1)
    state = project.factory.blank_state(addr=location.address); set_assembly_registers(state, values); state.memory.store(DIRECTION, values["direction"])
    manager = project.factory.simulation_manager(state); manager.explore(find=DONE); assert not manager.errored
    return [_endpoint(end, 0, True) for end in manager.found]

def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False); function = project.loader.find_symbol("port_animation_squish_mon_pic"); assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY); store_native_registers(state, NATIVE_STATE, values); state.memory.store(NATIVE_MEMORY + DIRECTION, values["direction"])
    manager = project.factory.simulation_manager(state); manager.run(); assert not manager.errored
    return [_endpoint(end, NATIVE_MEMORY, False) for end in manager.deadended]

@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_animation_squish_mon_pic_entry_pathwise_equivalence() -> None:
    values = symbolic_registers("animation_squish_mon_pic")
    values["direction"] = claripy.BVS("squish_direction", 8)
    assert_pathwise_equivalent(_assembly(values), _native(values), (*REGISTERS, "direction"))
