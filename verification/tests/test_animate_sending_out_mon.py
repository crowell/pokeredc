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
PREDEF_HL = 0xCC4F
IS_IN_BATTLE = 0xD057

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
        low = self.state.memory.load(PREDEF_HL, 1)
        high = self.state.memory.load(PREDEF_HL + 1, 1)
        battle = self.state.memory.load(IS_IN_BATTLE, 1)
        self.state.regs.h = high
        self.state.regs.l = low
        self.state.regs.b = claripy.BVV(0x4C, 8)
        self.state.regs.a = battle
        self.state.regs.f = claripy.BVV(0x10, 8) | claripy.If(battle == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        self.jump(DONE)

def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "AnimateSendingOutMon")
    project = angr.Project(rom_window(ROM, location.bank), auto_load_libs=False, rebase_granularity=0x100, main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0, "entry_point": location.address})
    project.hook(location.address, Setup(), length=0x12)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    for address, key in ((PREDEF_HL,"predef_hl_low"),(PREDEF_HL+1,"predef_hl_high"),(IS_IN_BATTLE,"is_in_battle")):
        state.memory.store(address, values[key])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored
    return [Endpoint(**assembly_registers(end), constraints=tuple(end.solver.constraints)) for end in manager.found]

def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_animate_sending_out_mon")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    for offset, key in enumerate(("predef_hl_low","predef_hl_high","start_tile_id","is_in_battle"), start=8):
        state.memory.store(NATIVE_STATE + offset, values[key])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [Endpoint(**native_registers(end, NATIVE_STATE), constraints=tuple(end.solver.constraints)) for end in manager.deadended]

@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_animate_sending_out_mon_setup_pathwise_equivalence() -> None:
    values = symbolic_registers("sending_out")
    for key in ("predef_hl_low","predef_hl_high","start_tile_id","is_in_battle"):
        values[key] = claripy.BVS(f"sending_out_{key}", 8)
    assert_pathwise_equivalent(_assembly(values), _native(values), REGISTERS)
