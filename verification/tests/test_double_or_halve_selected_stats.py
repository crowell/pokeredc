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
STATS = 0xD100
OBSERVABLES = (*REGISTERS, "stat_high", "stat_low", "stats")

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
    stat_high: claripy.ast.BV
    stat_low: claripy.ast.BV
    stats: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]

class Wrapper(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        whose = self.state.globals["whose_turn"]
        stats = self.state.memory.load(STATS, 8, endness="Iend_BE")
        self.state.solver.add(self.state.globals["player_mask"] == 0, self.state.globals["enemy_mask"] == 0)
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.b = claripy.BVV(0, 8)
        self.state.regs.c = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x42, 8)
        self.state.regs.h = claripy.If(whose == 0, claripy.BVV(0xD0, 8), claripy.BVV(0xCF, 8))
        self.state.regs.l = claripy.If(whose == 0, claripy.BVV(0x2D, 8), claripy.BVV(0xFE, 8))
        self.state.globals["stat_high"] = stats[15:8]
        self.state.globals["stat_low"] = stats[7:0]
        self.state.globals["stats"] = stats
        self.jump(DONE)

def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "DoubleOrHalveSelectedStats")
    project = angr.Project(rom_window(ROM, location.bank), auto_load_libs=False, rebase_granularity=0x100, main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0, "entry_point": location.address})
    project.hook(location.address, Wrapper(), length=7)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    for key in ("whose_turn", "player_mask", "enemy_mask", "stat_high", "stat_low"):
        state.globals[key] = values[key]
    state.memory.store(STATS, values["stats"], endness="Iend_BE")
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored
    return [Endpoint(**assembly_registers(end), stat_high=end.globals["stat_high"], stat_low=end.globals["stat_low"], stats=end.globals["stats"], constraints=tuple(end.solver.constraints)) for end in manager.found]

def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_double_or_halve_selected_stats")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_STATE + 16)
    store_native_registers(state, NATIVE_STATE, values)
    for offset, key in enumerate(("whose_turn", "player_mask", "enemy_mask", "stat_high", "stat_low"), start=8):
        state.memory.store(NATIVE_STATE + offset, values[key])
    state.memory.store(NATIVE_STATE + 16, values["stats"], endness="Iend_BE")
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [Endpoint(**native_registers(end, NATIVE_STATE), stat_high=end.memory.load(NATIVE_STATE + 11, 1), stat_low=end.memory.load(NATIVE_STATE + 12, 1), stats=end.memory.load(NATIVE_STATE + 16, 8, endness="Iend_BE"), constraints=tuple(end.solver.constraints) + (values["player_mask"] == 0, values["enemy_mask"] == 0)) for end in manager.deadended]

@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_double_or_halve_selected_stats_call_chain_pathwise_equivalence() -> None:
    values = symbolic_registers("double_or_halve_selected_stats")
    values["whose_turn"] = claripy.BVS("double_or_halve_whose_turn", 8)
    values["player_mask"] = claripy.BVV(0, 8)
    values["enemy_mask"] = claripy.BVV(0, 8)
    values["stat_high"] = claripy.BVS("double_or_halve_stat_high", 8)
    values["stat_low"] = claripy.BVS("double_or_halve_stat_low", 8)
    values["stats"] = claripy.BVS("double_or_halve_stats", 64)
    assert_pathwise_equivalent(_assembly(values), _native(values), OBSERVABLES)
