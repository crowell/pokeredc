from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr, claripy, pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS, assembly_registers, native_registers, set_assembly_registers, store_native_registers
from verification.harness.rom import linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import Sm83AndRegister, Sm83CpImmediate, Sm83LoadAAtHlIncrement, Sm83LoadAImmediate, Sm83StoreAImmediate, Sm83AddHlRegisterPair

ROOT = Path(__file__).resolve().parents[2]; ELF = ROOT / "verification/build/ports.elf"; ROM = ROOT / "pokered.gbc"; SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000; NATIVE_MEMORY = 0x200000; RETURN = 0xEFFF
W_MAP = 0xD35E; W_GRASS_RATE = 0xD887; W_GRASS = 0xD888; W_WATER_RATE = 0xD8A4; W_WATER = 0xD8A5; POINTERS = 0x4EEB; SOURCE = 0x9000; COUNT = 20

@dataclass(frozen=True)
class Endpoint:
    a: claripy.ast.BV; f: claripy.ast.BV; b: claripy.ast.BV; c: claripy.ast.BV; d: claripy.ast.BV; e: claripy.ast.BV; h: claripy.ast.BV; l: claripy.ast.BV
    grass_rate: claripy.ast.BV; water_rate: claripy.ast.BV; grass: claripy.ast.BV; water: claripy.ast.BV; constraints: tuple[claripy.ast.Bool, ...]

class Jump(angr.SimProcedure):
    def __init__(self, target: int) -> None: super().__init__(); self.target = target
    def run(self) -> None: self.jump(self.target)

class MoveAToC(angr.SimProcedure):
    def __init__(self, target: int) -> None: super().__init__(); self.target = target
    def run(self) -> None: self.state.regs.c = self.state.regs.a; self.jump(self.target)

class SetRegister(angr.SimProcedure):
    def __init__(self, register: str, value: int, target: int) -> None: super().__init__(); self.register = register; self.value = value; self.target = target
    def run(self) -> None: setattr(self.state.regs, self.register, claripy.BVV(self.value, 8)); self.jump(self.target)

class PushPair(angr.SimProcedure):
    def __init__(self, pair: str, target: int) -> None: super().__init__(); self.pair = pair; self.target = target
    def run(self) -> None: self.state.globals["saved_" + self.pair] = getattr(self.state.regs, self.pair); self.jump(self.target)

class PopPair(angr.SimProcedure):
    def __init__(self, pair: str, target: int) -> None: super().__init__(); self.pair = pair; self.target = target
    def run(self) -> None: setattr(self.state.regs, self.pair, self.state.globals["saved_" + self.pair]); self.jump(self.target)

class LookupWild(angr.SimProcedure):
    def __init__(self, target: int) -> None: super().__init__(); self.target = target
    def run(self) -> None:
        self.state.regs.hl = SOURCE + 1; self.state.regs.a = self.state.memory.load(SOURCE, 1); self.jump(self.target)

class BranchZ(angr.SimProcedure):
    def __init__(self, taken: int, fallthrough: int) -> None: super().__init__(); self.taken = taken; self.fallthrough = fallthrough
    def run(self) -> None:
        self.inhibit_autoret = True; z = (self.state.regs.f & 0x40) != 0
        self.successors.add_successor(self.state.copy(), self.taken, z, "Ijk_Boring"); self.successors.add_successor(self.state.copy(), self.fallthrough, claripy.Not(z), "Ijk_Boring")

class LoadHAtHL(angr.SimProcedure):
    def __init__(self, target: int) -> None: super().__init__(); self.target = target
    def run(self) -> None: self.state.regs.h = self.state.memory.load(self.state.regs.hl, 1); self.jump(self.target)

class LoadLFromA(angr.SimProcedure):
    def __init__(self, target: int) -> None: super().__init__(); self.target = target
    def run(self) -> None: self.state.regs.l = self.state.regs.a; self.jump(self.target)

class SetPair(angr.SimProcedure):
    def __init__(self, pair: str, value: int, target: int) -> None: super().__init__(); self.pair = pair; self.value = value; self.target = target
    def run(self) -> None: setattr(self.state.regs, self.pair, claripy.BVV(self.value, 16)); self.jump(self.target)

class CopyDataSummary(angr.SimProcedure):
    def __init__(self, target: int) -> None: super().__init__(); self.target = target
    def run(self) -> None:
        hl = self.state.regs.hl; de = self.state.regs.de
        for _ in range(COUNT): self.state.memory.store(de, self.state.memory.load(hl, 1)); hl += 1; de += 1
        self.state.regs.hl = hl; self.state.regs.de = de; self.state.regs.bc = 0; self.state.regs.a = 0; self.state.regs.f = 0x40; self.jump(self.target)

def _setup(state: angr.SimState, base: int, grass_rate: int, water_rate: int) -> None:
    state.memory.store(base + W_MAP, claripy.BVV(0, 8)); state.memory.store(base + POINTERS, claripy.BVV(SOURCE & 0xff, 8)); state.memory.store(base + POINTERS + 1, claripy.BVV(SOURCE >> 8, 8))
    state.memory.store(base + SOURCE, claripy.BVV(grass_rate, 8))
    if grass_rate:
        for i in range(COUNT): state.memory.store(base + SOURCE + 1 + i, claripy.BVV(0x20 + i, 8))
        state.memory.store(base + SOURCE + 1 + COUNT, claripy.BVV(water_rate, 8))
        for i in range(COUNT): state.memory.store(base + SOURCE + 2 + COUNT + i, claripy.BVV(0x60 + i, 8))
    else:
        state.memory.store(base + SOURCE + 1, claripy.BVV(water_rate, 8))
        for i in range(COUNT): state.memory.store(base + SOURCE + 2 + i, claripy.BVV(0x60 + i, 8))
    for i in range(COUNT): state.memory.store(base + W_GRASS + i, claripy.BVV(0, 8)); state.memory.store(base + W_WATER + i, claripy.BVV(0, 8))
    state.memory.store(base + W_GRASS_RATE, claripy.BVV(0, 8)); state.memory.store(base + W_WATER_RATE, claripy.BVV(0, 8))

def _endpoint(state: angr.SimState, base: int, native: bool, memory_base: int) -> Endpoint:
    fields = native_registers(state, base) if native else assembly_registers(state)
    return Endpoint(**fields, grass_rate=state.memory.load(memory_base + W_GRASS_RATE, 1), water_rate=state.memory.load(memory_base + W_WATER_RATE, 1), grass=state.memory.load(memory_base + W_GRASS, COUNT), water=state.memory.load(memory_base + W_WATER, COUNT), constraints=tuple(state.solver.constraints))

def _assembly(values: dict[str, claripy.ast.BV], grass_rate: int, water_rate: int) -> list[Endpoint]:
    loc = symbol_location(SYMBOLS, "LoadWildData"); end = symbol_location(SYMBOLS, "WildDataPointers"); body = linked_bytes(ROM, loc, end.address - loc.address); assert len(body) == 51
    p = angr.Project(rom_window(ROM, loc.bank), auto_load_libs=False, rebase_granularity=0x100, main_opts={"backend":"blob", "arch":ArchPcode("z80:LE:16:default"), "base_addr":0, "entry_point":loc.address})
    p.hook(loc.address + 0, SetPair("hl", POINTERS, loc.address + 3), length=3); p.hook(loc.address + 3, Sm83LoadAImmediate(W_MAP, loc.address + 6), length=3); p.hook(loc.address + 6, MoveAToC(loc.address + 7), length=1); p.hook(loc.address + 7, SetRegister("b", 0, loc.address + 9), length=2); p.hook(loc.address + 9, LookupWild(loc.address + 0x0f), length=6); p.hook(loc.address + 0x0f, Sm83StoreAImmediate(W_GRASS_RATE, loc.address + 0x12), length=3); p.hook(loc.address + 0x12, Sm83AndRegister("a", loc.address + 0x13), length=1); p.hook(loc.address + 0x13, BranchZ(loc.address + 0x24, loc.address + 0x15), length=2); p.hook(loc.address + 0x15, PushPair("hl", loc.address + 0x16), length=1); p.hook(loc.address + 0x16, SetPair("de", W_GRASS, loc.address + 0x19), length=3); p.hook(loc.address + 0x19, SetPair("bc", COUNT, loc.address + 0x1c), length=3); p.hook(loc.address + 0x1c, CopyDataSummary(loc.address + 0x1f), length=3); p.hook(loc.address + 0x1f, PopPair("hl", loc.address + 0x20), length=1); p.hook(loc.address + 0x20, SetPair("bc", COUNT, loc.address + 0x23), length=3); p.hook(loc.address + 0x23, Sm83AddHlRegisterPair("bc", loc.address + 0x24), length=1); p.hook(loc.address + 0x24, Sm83LoadAAtHlIncrement(loc.address + 0x25), length=1); p.hook(loc.address + 0x25, Sm83StoreAImmediate(W_WATER_RATE, loc.address + 0x28), length=3); p.hook(loc.address + 0x28, Sm83AndRegister("a", loc.address + 0x29), length=1); p.hook(loc.address + 0x29, BranchZ(RETURN, loc.address + 0x2a), length=1); p.hook(loc.address + 0x2a, SetPair("de", W_WATER, loc.address + 0x2d), length=3); p.hook(loc.address + 0x2d, SetPair("bc", COUNT, loc.address + 0x30), length=3); p.hook(loc.address + 0x30, CopyDataSummary(RETURN), length=3); p.hook(loc.address + 0x32, Jump(RETURN), length=1)
    s = p.factory.blank_state(addr=loc.address); set_assembly_registers(s, values); _setup(s, 0, grass_rate, water_rate); s.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY); m = p.factory.simulation_manager(s); m.explore(find=RETURN); assert not m.errored and m.found; return [_endpoint(x, 0, False, 0) for x in m.found]

def _native(values: dict[str, claripy.ast.BV], grass_rate: int, water_rate: int) -> list[Endpoint]:
    p = angr.Project(ELF, auto_load_libs=False); fn = p.loader.find_symbol("port_load_wild_data"); assert fn is not None; s = p.factory.call_state(fn.rebased_addr, NATIVE_STATE, NATIVE_MEMORY); store_native_registers(s, NATIVE_STATE, values); _setup(s, NATIVE_MEMORY, grass_rate, water_rate); m = p.factory.simulation_manager(s); m.run(); assert not m.errored and len(m.deadended) == 1; return [_endpoint(m.deadended[0], NATIVE_STATE, True, NATIVE_MEMORY)]

@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(), reason="build artifacts missing")
@pytest.mark.parametrize("grass_rate,water_rate", ((0, 0), (5, 0), (0, 7), (5, 7)))
def test_load_wild_data_pathwise_equivalence(grass_rate: int, water_rate: int) -> None:
    values = {register: claripy.BVV(0, 8) for register in REGISTERS}; assert_pathwise_equivalent(_assembly(values, grass_rate, water_rate), _native(values, grass_rate, water_rate), (*REGISTERS, "grass_rate", "water_rate", "grass", "water"))
