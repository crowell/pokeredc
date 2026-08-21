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
        whose = self.state.memory.load(0xFFF3, 1)
        enemy = self.state.memory.load(0xCCDD, 1)
        player = self.state.memory.load(0xCCDC, 1)
        flags = self.state.memory.load(0xD733, 1)
        test_move = self.state.memory.load(0xCCD9, 1)
        self.state.regs.d = claripy.BVV(0xCF, 8)
        self.state.regs.e = claripy.If(whose == 0, claripy.BVV(0xD2, 8), claripy.BVV(0xCC, 8))
        self.state.regs.a = claripy.If(whose != 0, enemy, claripy.If((flags & 1) != 0, test_move, player))
        self.state.regs.f = claripy.If(whose != 0, claripy.BVV(0x10, 8), (self.state.regs.f & 1) | claripy.BVV(0x10, 8) | claripy.If((flags & 1) == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)))
        self.jump(DONE)

def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "GetCurrentMove")
    project = angr.Project(rom_window(ROM, location.bank), auto_load_libs=False, rebase_granularity=0x100, main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0, "entry_point": location.address})
    project.hook(location.address, Setup(), length=0x1E)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    for address, key in ((0xFFF3,"whose_turn"),(0xCCDD,"enemy_selected_move"),(0xCCDC,"player_selected_move"),(0xD733,"status_flags7"),(0xCCD9,"test_battle_selected_move")):
        state.memory.store(address, values[key])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored
    return [Endpoint(**assembly_registers(end), constraints=tuple(end.solver.constraints)) for end in manager.found]

def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_get_current_move")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    for offset, key in enumerate(("whose_turn","enemy_selected_move","player_selected_move","status_flags7","test_battle_selected_move"), start=8):
        state.memory.store(NATIVE_STATE + offset, values[key])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [Endpoint(**native_registers(end, NATIVE_STATE), constraints=tuple(end.solver.constraints)) for end in manager.deadended]

@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_get_current_move_setup_pathwise_equivalence() -> None:
    values = symbolic_registers("get_current_move")
    for key in ("whose_turn","enemy_selected_move","player_selected_move","status_flags7","test_battle_selected_move"):
        values[key] = claripy.BVS(f"get_current_move_{key}", 8)
    assert_pathwise_equivalent(_assembly(values), _native(values), REGISTERS)
