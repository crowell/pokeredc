from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr, claripy, pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS, assembly_registers, native_registers, set_assembly_registers, store_native_registers
from verification.harness.rom import linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import Sm83AndImmediate, Sm83CpImmediate, Sm83CpRegister, Sm83LoadAAtHlIncrement, Sm83LoadAHighImmediate, Sm83LoadAImmediate, Sm83StoreAHighImmediate, Sm83StoreAImmediate

ROOT = Path(__file__).resolve().parents[2]; ELF = ROOT / "verification/build/ports.elf"; ROM = ROOT / "pokered.gbc"; SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000; NATIVE_MEMORY = 0x200000; RETURN = 0xEFFF
W_PREDEF_HL = 0xCC4F; W_PREDEF_DE = 0xCC51; W_PREDEF_BC = 0xCC53; W_TILESET = 0xD367; W_PREVIOUS = 0xFF8B; W_DEST = 0xD42F; W_Y = 0xD361; W_X = 0xD362; W_YB = 0xD363; W_XB = 0xD364; W_BANK = 0xD52B; H_ANIM = 0xFFD7; H_COUNTER = 0xFFD8; W_CURRENT = 0xD35F; TILESETS = 0x47BE; DUNGEONS = 0x47B2; SOURCE = 0x9000

@dataclass(frozen=True)
class Endpoint:
    a: claripy.ast.BV; f: claripy.ast.BV; b: claripy.ast.BV; c: claripy.ast.BV; d: claripy.ast.BV; e: claripy.ast.BV; h: claripy.ast.BV; l: claripy.ast.BV
    header: claripy.ast.BV; anim: claripy.ast.BV; counter: claripy.ast.BV; blocks: claripy.ast.BV; current: claripy.ast.BV; constraints: tuple[claripy.ast.Bool, ...]

class Jump(angr.SimProcedure):
    def __init__(self, target: int) -> None: super().__init__(); self.target = target
    def run(self) -> None: self.jump(self.target)

class MoveAToB(angr.SimProcedure):
    def __init__(self, target: int) -> None: super().__init__(); self.target = target
    def run(self) -> None: self.state.regs.b = self.state.regs.a; self.jump(self.target)

class BranchFlag(angr.SimProcedure):
    def __init__(self, bit: int, taken: int, fallthrough: int) -> None: super().__init__(); self.bit = bit; self.taken = taken; self.fallthrough = fallthrough
    def run(self) -> None:
        self.inhibit_autoret = True; condition = (self.state.regs.f & (1 << self.bit)) != 0
        self.successors.add_successor(self.state.copy(), self.taken, condition, "Ijk_Boring"); self.successors.add_successor(self.state.copy(), self.fallthrough, claripy.Not(condition), "Ijk_Boring")

class PushPair(angr.SimProcedure):
    def __init__(self, pair: str, target: int) -> None: super().__init__(); self.pair = pair; self.target = target
    def run(self) -> None: self.state.globals["saved_" + self.pair] = getattr(self.state.regs, self.pair); self.jump(self.target)

class PopPair(angr.SimProcedure):
    def __init__(self, pair: str, target: int) -> None: super().__init__(); self.pair = pair; self.target = target
    def run(self) -> None: setattr(self.state.regs, self.pair, self.state.globals["saved_" + self.pair]); self.jump(self.target)

class GetPredef(angr.SimProcedure):
    def __init__(self, target: int) -> None: super().__init__(); self.target = target
    def run(self) -> None:
        self.state.regs.h = self.state.memory.load(W_PREDEF_HL, 1); self.state.regs.l = self.state.memory.load(W_PREDEF_HL + 1, 1); self.state.regs.d = self.state.memory.load(W_PREDEF_DE, 1); self.state.regs.e = self.state.memory.load(W_PREDEF_DE + 1, 1); self.state.regs.b = self.state.memory.load(W_PREDEF_BC, 1); self.state.regs.c = self.state.memory.load(W_PREDEF_BC + 1, 1); self.jump(self.target)

class CopyHeader(angr.SimProcedure):
    def __init__(self, target: int) -> None: super().__init__(); self.target = target
    def run(self) -> None:
        source = self.state.regs.hl; dest = self.state.regs.de
        for i in range(11): self.state.memory.store(dest + i, self.state.memory.load(source + i, 1))
        self.state.regs.hl = source + 11; self.state.regs.de = dest + 11; self.state.regs.c = 0; self.state.regs.a = self.state.memory.load(source + 11, 1); self.state.memory.store(H_ANIM, self.state.regs.a); self.state.regs.a = 0; self.state.regs.f = 0x40; self.state.memory.store(H_COUNTER, self.state.regs.a); self.jump(self.target)

class SearchDungeon(angr.SimProcedure):
    def __init__(self, target: int) -> None: super().__init__(); self.target = target
    def run(self) -> None:
        needle = self.state.regs.a; self.state.regs.c = needle; count = 0; address = DUNGEONS
        while True:
            value = self.state.memory.load(address, 1); concrete = int(self.state.solver.eval(value))
            if concrete == 0xff: self.state.regs.a = value; self.state.regs.b = count; self.state.regs.f = 0x20; break
            if concrete == int(self.state.solver.eval(needle)): self.state.regs.a = value; self.state.regs.b = count; self.state.regs.c = needle; self.state.regs.f = 0x01; break
            count += 1; address += 1
        self.jump(self.target)

class LoadDestination(angr.SimProcedure):
    def __init__(self, target: int) -> None: super().__init__(); self.target = target
    def run(self) -> None:
        source = self.state.regs.hl + self.state.regs.a * 4
        for i in range(4): self.state.memory.store(W_CURRENT + i, self.state.memory.load(source + i, 1))
        self.state.regs.hl = source + 4; self.state.regs.de = W_CURRENT + 4; self.state.regs.bc = 0; self.state.regs.a = self.state.memory.load(source + 3, 1); self.state.regs.f = 0x40; self.jump(self.target)

def _setup(state: angr.SimState, base: int, tileset: int, previous: int, destination: int) -> None:
    table = linked_bytes(ROM, symbol_location(SYMBOLS, "Tilesets"), 23 * 12); dungeon = linked_bytes(ROM, symbol_location(SYMBOLS, "DungeonTilesets"), 12)
    for i, value in enumerate(table): state.memory.store(base + TILESETS + i, claripy.BVV(value, 8))
    for i, value in enumerate(dungeon): state.memory.store(base + DUNGEONS + i, claripy.BVV(value, 8))
    state.memory.store(base + W_TILESET, claripy.BVV(tileset, 8)); state.memory.store(base + W_PREVIOUS, claripy.BVV(previous, 8)); state.memory.store(base + W_DEST, claripy.BVV(destination, 8)); state.memory.store(base + W_Y, claripy.BVV(5, 8)); state.memory.store(base + W_X, claripy.BVV(8, 8))
    for address, value in ((W_PREDEF_HL, SOURCE), (W_PREDEF_DE, 0x9100), (W_PREDEF_BC, 0x1234)):
        state.memory.store(base + address, claripy.BVV(value >> 8, 8)); state.memory.store(base + address + 1, claripy.BVV(value & 0xff, 8))
    for i, value in enumerate((0x11, 0x22, 0x33, 0x44)): state.memory.store(base + SOURCE + destination * 4 + i, claripy.BVV(value, 8))
    for i in range(12): state.memory.store(base + W_BANK + i, claripy.BVV(0, 8))
    for i in range(4): state.memory.store(base + W_CURRENT + i, claripy.BVV(0, 8))
    state.memory.store(base + W_YB, claripy.BVV(0, 8)); state.memory.store(base + W_XB, claripy.BVV(0, 8))

def _endpoint(state: angr.SimState, reg_base: int, memory_base: int, native: bool) -> Endpoint:
    fields = native_registers(state, reg_base) if native else assembly_registers(state)
    return Endpoint(**fields, header=state.memory.load(memory_base + W_BANK, 11), anim=state.memory.load(memory_base + H_ANIM, 1), counter=state.memory.load(memory_base + H_COUNTER, 1), blocks=state.memory.load(memory_base + W_YB, 2), current=state.memory.load(memory_base + W_CURRENT, 4), constraints=tuple(state.solver.constraints))

def _assembly(values: dict[str, claripy.ast.BV], tileset: int, previous: int, destination: int) -> list[Endpoint]:
    loc = symbol_location(SYMBOLS, "LoadTilesetHeader"); end = symbol_location(SYMBOLS, "DungeonTilesets"); body = linked_bytes(ROM, loc, end.address - loc.address); assert len(body) == 94
    p = angr.Project(rom_window(ROM, loc.bank), auto_load_libs=False, rebase_granularity=0x100, main_opts={"backend":"blob", "arch":ArchPcode("z80:LE:16:default"), "base_addr":0, "entry_point":loc.address})
    p.hook(loc.address + 0, GetPredef(loc.address + 3), length=3); p.hook(loc.address + 3, PushPair("hl", loc.address + 4), length=1); p.hook(loc.address + 6, Sm83LoadAImmediate(W_TILESET, loc.address + 9), length=3); p.hook(loc.address + 0x1b, CopyHeader(loc.address + 0x27), length=2); p.hook(loc.address + 0x27, PopPair("hl", loc.address + 0x28), length=1); p.hook(loc.address + 0x28, Sm83LoadAImmediate(W_TILESET, loc.address + 0x2b), length=3); p.hook(loc.address + 0x2b, PushPair("hl", loc.address + 0x2c), length=1); p.hook(loc.address + 0x2c, PushPair("de", loc.address + 0x2d), length=1); p.hook(loc.address + 0x33, SearchDungeon(loc.address + 0x36), length=3); p.hook(loc.address + 0x36, PopPair("de", loc.address + 0x37), length=1); p.hook(loc.address + 0x37, PopPair("hl", loc.address + 0x38), length=1); p.hook(loc.address + 0x38, BranchFlag(0, loc.address + 0x43, loc.address + 0x3a), length=2); p.hook(loc.address + 0x3a, Sm83LoadAImmediate(W_TILESET, loc.address + 0x3d), length=3); p.hook(loc.address + 0x3d, MoveAToB(loc.address + 0x3e), length=1); p.hook(loc.address + 0x3e, Sm83LoadAHighImmediate(W_PREVIOUS & 0xff, loc.address + 0x40), length=2); p.hook(loc.address + 0x40, Sm83CpRegister("b", loc.address + 0x41), length=1); p.hook(loc.address + 0x41, BranchFlag(6, loc.address + 0x5d, loc.address + 0x43), length=2); p.hook(loc.address + 0x43, Sm83LoadAImmediate(W_DEST, loc.address + 0x46), length=3); p.hook(loc.address + 0x46, Sm83CpImmediate(0xff, loc.address + 0x48), length=2); p.hook(loc.address + 0x48, BranchFlag(6, loc.address + 0x5d, loc.address + 0x4a), length=2); p.hook(loc.address + 0x4a, LoadDestination(loc.address + 0x4d), length=3); p.hook(loc.address + 0x4d, Sm83LoadAImmediate(W_Y, loc.address + 0x50), length=3); p.hook(loc.address + 0x50, Sm83AndImmediate(1, loc.address + 0x52), length=2); p.hook(loc.address + 0x52, Sm83StoreAImmediate(W_YB, loc.address + 0x55), length=3); p.hook(loc.address + 0x55, Sm83LoadAImmediate(W_X, loc.address + 0x58), length=3); p.hook(loc.address + 0x58, Sm83AndImmediate(1, loc.address + 0x5a), length=2); p.hook(loc.address + 0x5a, Sm83StoreAImmediate(W_XB, loc.address + 0x5d), length=3); p.hook(loc.address + 0x5d, Jump(RETURN), length=1)
    s = p.factory.blank_state(addr=loc.address); set_assembly_registers(s, values); _setup(s, 0, tileset, previous, destination); s.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY); m = p.factory.simulation_manager(s); m.explore(find=RETURN); assert not m.errored and m.found; return [_endpoint(x, 0, 0, False) for x in m.found]

def _native(values: dict[str, claripy.ast.BV], tileset: int, previous: int, destination: int) -> list[Endpoint]:
    p = angr.Project(ELF, auto_load_libs=False); fn = p.loader.find_symbol("port_load_tileset_header"); assert fn is not None; s = p.factory.call_state(fn.rebased_addr, NATIVE_STATE, NATIVE_MEMORY); store_native_registers(s, NATIVE_STATE, values); _setup(s, NATIVE_MEMORY, tileset, previous, destination); m = p.factory.simulation_manager(s); m.run(); assert not m.errored and len(m.deadended) == 1; return [_endpoint(m.deadended[0], NATIVE_STATE, NATIVE_MEMORY, True)]

@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(), reason="build artifacts missing")
@pytest.mark.parametrize("tileset,previous,destination", ((0, 0, 0xff), (0, 1, 0xff), (1, 1, 0xff), (1, 1, 0)))
def test_load_tileset_header_pathwise_equivalence(tileset: int, previous: int, destination: int) -> None:
    values = {register: claripy.BVV(0, 8) for register in REGISTERS}; assert_pathwise_equivalent(_assembly(values, tileset, previous, destination), _native(values, tileset, previous, destination), (*REGISTERS, "header", "anim", "counter", "blocks", "current"))
