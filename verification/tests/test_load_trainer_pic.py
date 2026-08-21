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
POINTER = 0xD033
LINK_STATE = 0xD12B

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
        low = self.state.memory.load(POINTER, 1)
        high = self.state.memory.load(POINTER + 1, 1)
        link = self.state.memory.load(LINK_STATE, 1)
        self.state.regs.e = low
        self.state.regs.d = high
        self.state.regs.a = claripy.If(link == 0, claripy.BVV(0x13, 8), claripy.BVV(4, 8))
        self.state.regs.f = claripy.BVV(0x10, 8) | claripy.If(link == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        self.jump(DONE)

def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "_LoadTrainerPic")
    project = angr.Project(rom_window(ROM, location.bank), auto_load_libs=False, rebase_granularity=0x100, main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0, "entry_point": location.address})
    project.hook(location.address, Setup(), length=0x12)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.memory.store(POINTER, values["trainer_pointer_low"])
    state.memory.store(POINTER + 1, values["trainer_pointer_high"])
    state.memory.store(LINK_STATE, values["link_state"])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored
    return [Endpoint(**assembly_registers(end), constraints=tuple(end.solver.constraints)) for end in manager.found]

def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_load_trainer_pic")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    for offset, key in enumerate(("trainer_pointer_low", "trainer_pointer_high", "link_state"), start=8):
        state.memory.store(NATIVE_STATE + offset, values[key])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [Endpoint(**native_registers(end, NATIVE_STATE), constraints=tuple(end.solver.constraints)) for end in manager.deadended]

@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_load_trainer_pic_pathwise_equivalence() -> None:
    values = symbolic_registers("load_trainer_pic")
    values["trainer_pointer_low"] = claripy.BVS("load_trainer_pic_low", 8)
    values["trainer_pointer_high"] = claripy.BVS("load_trainer_pic_high", 8)
    values["link_state"] = claripy.BVS("load_trainer_pic_link_state", 8)
    assert_pathwise_equivalent(_assembly(values), _native(values), REGISTERS)
