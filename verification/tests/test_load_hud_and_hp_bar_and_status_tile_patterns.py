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
LCD_CONTROL = 0xFF40

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

class Setup(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        old = self.state.memory.load(LCD_CONTROL, 1)
        result = old + old
        self.state.regs.a = result
        self.state.regs.f = claripy.If(result == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        self.state.regs.f |= claripy.If((old & 0x0F).UGT(7), claripy.BVV(0x10, 8), claripy.BVV(0, 8))
        self.state.regs.f |= claripy.If(old.UGT(0x7F), claripy.BVV(0x01, 8), claripy.BVV(0, 8))
        self.jump(DONE)

def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "LoadHudAndHpBarAndStatusTilePatterns")
    project = angr.Project(rom_window(ROM, location.bank), auto_load_libs=False, rebase_granularity=0x100, main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0, "entry_point": location.address})
    project.hook(location.address, Setup(), length=7)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.memory.store(LCD_CONTROL, values["lcd_control"])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored
    return [Endpoint(**assembly_registers(end), constraints=tuple(end.solver.constraints)) for end in manager.found]

def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_load_hud_and_hp_bar_and_status_tile_patterns")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, values["lcd_control"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [Endpoint(**native_registers(end, NATIVE_STATE), constraints=tuple(end.solver.constraints)) for end in manager.deadended]

@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_load_hud_and_hp_bar_and_status_tile_patterns_pathwise_equivalence() -> None:
    values = symbolic_registers("load_hud_patterns")
    values["lcd_control"] = claripy.BVS("load_hud_patterns_lcd", 8)
    assert_pathwise_equivalent(_assembly(values), _native(values), REGISTERS)
