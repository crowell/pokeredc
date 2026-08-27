from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr, claripy, pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS, assembly_registers, native_registers, set_assembly_registers, store_native_registers
from verification.harness.rom import linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import Sm83CpImmediate, Sm83LoadAAtHlIncrement, Sm83LoadAHighImmediate, Sm83LoadAImmediate, Sm83StoreAHighImmediate

ROOT = Path(__file__).resolve().parents[2]; ELF = ROOT / "verification/build/ports.elf"; ROM = ROOT / "pokered.gbc"; SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000; NATIVE_MEMORY = 0x200000; RETURN = 0xEFFF
W_MAP = 0xD35E; W_TOWN = 0xD70B; W_LIST = 0xD5CE; POINTERS = 0x48F5; STATES = 0x4AEA

@dataclass(frozen=True)
class Endpoint:
    a: claripy.ast.BV; f: claripy.ast.BV; b: claripy.ast.BV; c: claripy.ast.BV; d: claripy.ast.BV; e: claripy.ast.BV; h: claripy.ast.BV; l: claripy.ast.BV
    town: claripy.ast.BV; listing: claripy.ast.BV; constraints: tuple[claripy.ast.Bool, ...]

class Jump(angr.SimProcedure):
    def __init__(self, target: int) -> None: super().__init__(); self.target = target
    def run(self) -> None: self.jump(self.target)

class FlagAction(angr.SimProcedure):
    def __init__(self, target: int) -> None: super().__init__(); self.target = target
    def run(self) -> None: self.state.memory.store(W_TOWN, claripy.BVV(1, 8)); self.jump(self.target)

class Divide(angr.SimProcedure):
    def __init__(self, target: int) -> None: super().__init__(); self.target = target
    def run(self) -> None: self.state.memory.store(0xFF98, claripy.BVV(0, 8)); self.jump(self.target)

class MoveAToRegister(angr.SimProcedure):
    def __init__(self, register: str, target: int) -> None: super().__init__(); self.register = register; self.target = target
    def run(self) -> None: setattr(self.state.regs, self.register, self.state.regs.a); self.jump(self.target)

class LoadRegisterToA(angr.SimProcedure):
    def __init__(self, register: str, target: int) -> None: super().__init__(); self.register = register; self.target = target
    def run(self) -> None: self.state.regs.a = getattr(self.state.regs, self.register); self.jump(self.target)

class SubRegister(angr.SimProcedure):
    def __init__(self, register: str, target: int) -> None: super().__init__(); self.register = register; self.target = target
    def run(self) -> None: self.state.regs.a = self.state.regs.a - getattr(self.state.regs, self.register); self.jump(self.target)

def _setup(state: angr.SimState, base: int) -> None:
    state.memory.store(base + W_MAP, claripy.BVV(0, 8)); state.memory.store(base + POINTERS, claripy.BVV(STATES, 16), endness="Iend_LE")
    state.memory.store(base + STATES, claripy.BVV(0xff, 8)); state.memory.store(base + W_TOWN, claripy.BVV(0, 8))
    for offset in range(33): state.memory.store(base + W_LIST + offset, claripy.BVV(0, 8))

def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    loc = symbol_location(SYMBOLS, "MarkTownVisitedAndLoadToggleableObjects"); end = symbol_location(SYMBOLS, "InitializeToggleableObjectsFlags")
    body = linked_bytes(ROM, loc, end.address - loc.address); assert len(body) == 98
    project = angr.Project(rom_window(ROM, loc.bank), auto_load_libs=False, rebase_granularity=0x100, main_opts={"backend":"blob", "arch":ArchPcode("z80:LE:16:default"), "base_addr":0, "entry_point":loc.address})
    project.hook(loc.address + 0x00, Sm83LoadAImmediate(W_MAP, loc.address + 3), length=3)
    project.hook(loc.address + 0x03, Sm83CpImmediate(0x0c, loc.address + 5), length=2)
    project.hook(loc.address + 0x05, Jump(loc.address + 7), length=2)
    project.hook(loc.address + 0x0f, FlagAction(loc.address + 0x12), length=3)
    project.hook(loc.address + 0x15, Sm83LoadAImmediate(W_MAP, loc.address + 0x18), length=3)
    project.hook(loc.address + 0x1d, Sm83LoadAAtHlIncrement(loc.address + 0x1e), length=1)
    project.hook(loc.address + 0x24, LoadRegisterToA("l", loc.address + 0x25), length=1)
    project.hook(loc.address + 0x25, SubRegister("e", loc.address + 0x26), length=1)
    project.hook(loc.address + 0x26, Jump(loc.address + 0x29), length=2)
    project.hook(loc.address + 0x29, MoveAToRegister("l", loc.address + 0x2a), length=1)
    project.hook(loc.address + 0x2a, LoadRegisterToA("h", loc.address + 0x2b), length=1)
    project.hook(loc.address + 0x2b, SubRegister("d", loc.address + 0x2c), length=1)
    project.hook(loc.address + 0x2c, MoveAToRegister("h", loc.address + 0x2d), length=1)
    project.hook(loc.address + 0x2d, LoadRegisterToA("h", loc.address + 0x2e), length=1)
    for offset, high in ((0x2e, 0x95), (0x31, 0x96), (0x34, 0x97), (0x36, 0x98), (0x3a, 0x99)):
        project.hook(loc.address + offset, Sm83StoreAHighImmediate(high, loc.address + offset + 2), length=2)
    project.hook(loc.address + 0x3e, Divide(loc.address + 0x41), length=3)
    project.hook(loc.address + 0x41, Sm83LoadAImmediate(W_MAP, loc.address + 0x44), length=3)
    project.hook(loc.address + 0x45, Sm83LoadAHighImmediate(0x98, loc.address + 0x47), length=2)
    project.hook(loc.address + 0x4c, Sm83LoadAAtHlIncrement(loc.address + 0x4d), length=1)
    project.hook(loc.address + 0x4d, Sm83CpImmediate(0xff, loc.address + 0x4f), length=2)
    project.hook(loc.address + 0x4f, Jump(loc.address + 0x5e), length=2)
    project.hook(loc.address + 0x61, Jump(RETURN), length=1)
    state = project.factory.blank_state(addr=loc.address); set_assembly_registers(state, values); _setup(state, 0); state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state); manager.explore(find=RETURN, num_find=2); assert not manager.errored and manager.found
    return [Endpoint(**assembly_registers(x), town=x.memory.load(W_TOWN, 1), listing=x.memory.load(W_LIST, 33), constraints=tuple(x.solver.constraints)) for x in manager.found]

def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False); function = project.loader.find_symbol("port_mark_town_visited_and_load_toggleable_objects"); assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY); store_native_registers(state, NATIVE_STATE, values); _setup(state, NATIVE_MEMORY); manager = project.factory.simulation_manager(state); manager.run(); assert not manager.errored and len(manager.deadended) == 1
    return [Endpoint(**native_registers(x, NATIVE_STATE), town=x.memory.load(NATIVE_MEMORY + W_TOWN, 1), listing=x.memory.load(NATIVE_MEMORY + W_LIST, 33), constraints=tuple(x.solver.constraints)) for x in manager.deadended]

@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(), reason="build artifacts missing")
def test_mark_town_visited_and_load_toggleable_objects_pathwise_equivalence() -> None:
    values = {register: claripy.BVV(0, 8) for register in REGISTERS}
    assert_pathwise_equivalent(_assembly(values), _native(values), (*REGISTERS, "town", "listing"))
