from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS, assembly_registers, native_registers, set_assembly_registers, store_native_registers, symbolic_registers
from verification.harness.rom import linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import Sm83DecRegister

ROOT = Path(__file__).resolve().parents[2]
VERIFY = ROOT / "verification"
NATIVE_ELF = VERIFY / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
LOOP_BOUNDARY = 0xEFFE
RETURN_BOUNDARY = 0xEFFF
NATIVE_STATE = 0x100000


class LoadIncrement(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__(); self._next_address = next_address
    def run(self) -> None:  # type: ignore[override]
        if self.state.globals.get("reset_stats_entered", False):
            self.jump(LOOP_BOUNDARY); return
        self.state.globals["reset_stats_entered"] = True
        self.state.regs.a = self.state.globals["fetched"]
        self.state.regs.hl = self.state.regs.hl + 1
        self.jump(self._next_address)


class StoreValue(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__(); self._next_address = next_address
    def run(self) -> None:  # type: ignore[override]
        self.state.globals["written"] = self.state.regs.a
        self.jump(self._next_address)


class ReturnBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(RETURN_BOUNDARY)


class LoopBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(LOOP_BOUNDARY)


@dataclass(frozen=True)
class Endpoint:
    a: claripy.ast.BV; f: claripy.ast.BV; b: claripy.ast.BV; c: claripy.ast.BV
    d: claripy.ast.BV; e: claripy.ast.BV; h: claripy.ast.BV; l: claripy.ast.BV
    written: claripy.ast.BV; continuation: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _assembly(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "ResetStats"); loop = location.address + 2
    project = angr.Project(rom_window(ROM, location.bank), auto_load_libs=False, rebase_granularity=0x100,
        main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":loop})
    project.hook(loop, LoadIncrement(loop + 1), length=1)
    project.hook(loop + 1, StoreValue(loop + 2), length=1)
    project.hook(loop + 3, Sm83DecRegister("b", loop + 4), length=1)
    project.hook(loop + 6, ReturnBoundary(), length=1)
    state = project.factory.blank_state(addr=loop); set_assembly_registers(state, inputs)
    state.globals["fetched"] = inputs["fetched"]; state.globals["written"] = inputs["written"]
    manager = project.factory.simulation_manager(state); manager.stashes["found"] = []
    while manager.active:
        manager.move(from_stash="active",to_stash="found",filter_func=lambda s:s.addr in {LOOP_BOUNDARY,RETURN_BOUNDARY})
        if manager.active: manager.step()
    assert not manager.errored
    return [Endpoint(**assembly_registers(end),written=end.globals["written"],continuation=claripy.BVV(1 if end.addr==LOOP_BOUNDARY else 0,8),constraints=tuple(end.solver.constraints)) for end in manager.found]


def _native(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project=angr.Project(NATIVE_ELF,auto_load_libs=False); function=project.loader.find_symbol("port_reset_stats_step"); assert function
    state=project.factory.call_state(function.rebased_addr,NATIVE_STATE,claripy.ZeroExt(56,inputs["fetched"])); store_native_registers(state,NATIVE_STATE,inputs)
    state.memory.store(NATIVE_STATE+8,inputs["written"]); manager=project.factory.simulation_manager(state); manager.run(); assert not manager.errored
    return [Endpoint(**native_registers(end,NATIVE_STATE),written=end.memory.load(NATIVE_STATE+8,1),continuation=claripy.If(end.regs.rax[7:0]==0,claripy.BVV(1,8),claripy.BVV(0,8)),constraints=tuple(end.solver.constraints)) for end in manager.deadended]


def _begin_assembly(inputs: dict[str, claripy.ast.BV]) -> Endpoint:
    location=symbol_location(SYMBOLS,"ResetStats"); project=angr.Project(rom_window(ROM,location.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":location.address})
    project.hook(location.address+2,LoopBoundary(),length=1); state=project.factory.blank_state(addr=location.address); set_assembly_registers(state,inputs)
    manager=project.factory.simulation_manager(state); manager.explore(find=LOOP_BOUNDARY); assert not manager.errored and len(manager.found)==1; end=manager.found[0]
    return Endpoint(**assembly_registers(end),written=inputs["written"],continuation=claripy.BVV(1,8),constraints=tuple(end.solver.constraints))


def _begin_native(inputs: dict[str, claripy.ast.BV]) -> Endpoint:
    project=angr.Project(NATIVE_ELF,auto_load_libs=False); function=project.loader.find_symbol("port_reset_stats_begin"); assert function
    state=project.factory.call_state(function.rebased_addr,NATIVE_STATE); store_native_registers(state,NATIVE_STATE,inputs); manager=project.factory.simulation_manager(state); manager.run(); assert not manager.errored and len(manager.deadended)==1; end=manager.deadended[0]
    return Endpoint(**native_registers(end,NATIVE_STATE),written=inputs["written"],continuation=claripy.BVV(1,8),constraints=tuple(end.solver.constraints))


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_reset_stats_step_inductive_equivalence() -> None:
    inputs=symbolic_registers("reset_stats_step"); inputs["fetched"]=claripy.BVS("reset_stats_fetched",8); inputs["written"]=claripy.BVS("reset_stats_written",8)
    assert_pathwise_equivalent(_assembly(inputs),_native(inputs),(*REGISTERS,"written","continuation"))


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_reset_stats_begin_symbolic_equivalence() -> None:
    inputs=symbolic_registers("reset_stats_begin"); inputs["written"]=claripy.BVS("reset_stats_begin_written",8)
    assert_pathwise_equivalent([_begin_assembly(inputs)],[_begin_native(inputs)],(*REGISTERS,"continuation"))


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_reset_stats_exact_linked_body() -> None:
    location=symbol_location(SYMBOLS,"ResetStats"); assert linked_bytes(ROM,location,9)==bytes.fromhex("06082a12130520fac9")
