from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr, claripy, pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS, assembly_registers, native_registers, set_assembly_registers, store_native_registers
from verification.harness.rom import linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import Sm83LoadAHighImmediate, Sm83LoadAImmediate, Sm83StoreAHighImmediate, Sm83StoreAImmediate

ROOT = Path(__file__).resolve().parents[2]; ELF = ROOT / "verification/build/ports.elf"; ROM = ROOT / "pokered.gbc"; SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000; NATIVE_MEMORY = 0x200000; RETURN = 0xEFFF
W_MAP = 0xD35E; W_TILESET = 0xD367; W_UNUSED_TILESET = 0xD119; H_PREVIOUS = 0xFF8B; H_LOADED = 0xFFB8; ROMB = 0x2000; TOWN_VISITED = 0xD70B; TOGGLE_PTRS = 0x48F5; TOGGLE_LIST = 0xD5CE; SOURCE = 0x9000
MAP_POINTERS = 0x01AE; HEADER = 0x9100; OBJECTS = 0x9200; TILESETS = 0x47BE; DUNGEONS = 0x47B2; W_BANK = 0xD52B; H_ANIM = 0xFFD7; H_COUNTER = 0xFFD8; W_BG = 0xD3AD; W_WARPS = 0xD3AE; W_SIGNS = 0xD4B0; W_SPRITES = 0xD4E1; W_HEIGHT2 = 0xD524; W_WIDTH2 = 0xD525; W_MUSIC = 0xD35B

@dataclass(frozen=True)
class Endpoint:
    a: claripy.ast.BV; f: claripy.ast.BV; b: claripy.ast.BV; c: claripy.ast.BV; d: claripy.ast.BV; e: claripy.ast.BV; h: claripy.ast.BV; l: claripy.ast.BV
    memory: claripy.ast.BV; constraints: tuple[claripy.ast.Bool, ...]

@dataclass(frozen=True)
class NormalEndpoint:
    a: claripy.ast.BV; f: claripy.ast.BV; b: claripy.ast.BV; c: claripy.ast.BV; d: claripy.ast.BV; e: claripy.ast.BV; h: claripy.ast.BV; l: claripy.ast.BV
    memory: claripy.ast.BV; constraints: tuple[claripy.ast.Bool, ...]

class MarkTown(angr.SimProcedure):
    def __init__(self, target: int) -> None: super().__init__(); self.target = target
    def run(self) -> None:
        self.state.memory.store(TOWN_VISITED, self.state.memory.load(TOWN_VISITED, 1) | claripy.BVV(1, 8))
        self.state.regs.a = claripy.BVV(0xff, 8); self.state.regs.f = claripy.BVV(0x42, 8); self.state.regs.hl = claripy.BVV(SOURCE + 1, 16); self.state.regs.de = claripy.BVV(TOGGLE_LIST, 16); self.state.memory.store(TOGGLE_LIST, claripy.BVV(0xff, 8)); self.jump(self.target)

class SwitchBank(angr.SimProcedure):
    def __init__(self, target: int) -> None: super().__init__(); self.target = target
    def run(self) -> None:
        self.state.regs.a = claripy.BVV(6, 8); self.state.regs.f = self.state.regs.f & 0x40; self.state.memory.store(H_LOADED, claripy.BVV(6, 8)); self.state.memory.store(ROMB, claripy.BVV(6, 8)); self.jump(self.target)

class ResetBit(angr.SimProcedure):
    def __init__(self, target: int) -> None: super().__init__(); self.target = target
    def run(self) -> None: self.state.regs.a = self.state.regs.a & 0x7f; self.jump(self.target)

class MoveAToB(angr.SimProcedure):
    def __init__(self, target: int) -> None: super().__init__(); self.target = target
    def run(self) -> None: self.state.regs.b = self.state.regs.a; self.jump(self.target)

class RetNZ(angr.SimProcedure):
    def run(self) -> None:
        z = (self.state.regs.b & 0x80) == 0
        self.state.regs.f = (self.state.regs.f & 0x01) | 0x10 | claripy.If(z, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        if self.state.solver.is_true(claripy.Not(z)): self.jump(RETURN)
        else: self.jump(self.addr + 2)

class FixedHeader(angr.SimProcedure):
    def __init__(self, target: int) -> None: super().__init__(); self.target = target
    def run(self) -> None:
        for i in range(10): self.state.memory.store(0xD367 + i, self.state.memory.load(HEADER + i, 1))
        self.state.regs.hl = claripy.BVV(HEADER + 10, 16); self.state.regs.de = claripy.BVV(0xD371, 16); self.state.regs.c = claripy.BVV(0, 8); self.state.regs.f = claripy.BVV(0x42, 8); self.jump(self.target)

class NoConnections(angr.SimProcedure):
    def __init__(self, target: int) -> None: super().__init__(); self.target = target
    def run(self) -> None:
        for address in (0xD371, 0xD37C, 0xD387, 0xD392): self.state.memory.store(address, claripy.BVV(0xFF, 8))
        self.state.regs.b = claripy.BVV(0, 8); self.state.regs.f = claripy.BVV(0x60, 8); self.jump(self.target)

class ZeroObjects(angr.SimProcedure):
    def __init__(self, target: int, warp_count: int = 0, sign_count: int = 0, sprite_count: int = 0, sprite_kind: int = 0) -> None: super().__init__(); self.target = target; self.warp_count = warp_count; self.sign_count = sign_count; self.sprite_count = sprite_count; self.sprite_kind = sprite_kind
    def run(self) -> None:
        self.state.globals["saved_hl"] = claripy.BVV(HEADER + 12, 16); self.state.memory.store(W_BG, self.state.memory.load(OBJECTS, 1)); self.state.memory.store(W_WARPS, claripy.BVV(self.warp_count, 8)); self.state.memory.store(W_SIGNS, claripy.BVV(self.sign_count, 8)); self.state.memory.store(W_SPRITES, claripy.BVV(self.sprite_count, 8))
        if self.warp_count:
            for i in range(4): self.state.memory.store(0xD3AF + i, self.state.memory.load(OBJECTS + 2 + i, 1))
            self.state.regs.hl = claripy.BVV(OBJECTS + 7, 16)
        if self.sign_count:
            for i, value in enumerate((0x12, 0x23, 0x34)): self.state.memory.store(0xD4B1 + i, claripy.BVV(value, 8))
            self.state.memory.store(0xD4D1, claripy.BVV(0x34, 8)); self.state.regs.hl = claripy.BVV(OBJECTS + 3 + self.warp_count * 4 + self.sign_count * 3, 16)
        elif not self.warp_count: self.state.regs.hl = claripy.BVV(OBJECTS + 2, 16)
        if self.sprite_count:
            source = OBJECTS + 3 + self.warp_count * 4 + self.sign_count * 3 + 1
            self.state.memory.store(0xC110, claripy.BVV(4, 8)); self.state.memory.store(0xC214, claripy.BVV(0x12, 8)); self.state.memory.store(0xC215, claripy.BVV(0x13, 8)); self.state.memory.store(0xC216, claripy.BVV(0xD3, 8)); self.state.memory.store(0xD4E4, claripy.BVV(0xD4, 8)); self.state.memory.store(0xD4E5, claripy.BVV(0x40 if self.sprite_kind == 1 else 0x80 if self.sprite_kind == 2 else 0, 8)); self.state.memory.store(0xD504, claripy.BVV(0x55 if self.sprite_kind == 1 else 0x66 if self.sprite_kind == 2 else 0, 8)); self.state.memory.store(0xD505, claripy.BVV(0x77 if self.sprite_kind == 1 else 0, 8)); self.state.regs.hl = claripy.BVV(source + 6 + (2 if self.sprite_kind == 1 else 1 if self.sprite_kind == 2 else 0), 16); self.state.regs.de = claripy.BVV(0xC120, 16); self.state.regs.b = claripy.BVV(0, 8); self.state.regs.c = claripy.BVV(2, 8)
        self.state.regs.a = claripy.BVV(0, 8); self.state.regs.f = claripy.BVV(0x40, 8); self.jump(self.target)

class Skip(angr.SimProcedure):
    def __init__(self, target: int) -> None: super().__init__(); self.target = target
    def run(self) -> None: self.jump(self.target)

class SpriteSummary(angr.SimProcedure):
    def __init__(self, target: int, sprite_kind: int = 0) -> None: super().__init__(); self.target = target; self.sprite_kind = sprite_kind
    def run(self) -> None:
        for i in range(0xF0): self.state.memory.store(0xC110 + i, claripy.BVV(0, 8)); self.state.memory.store(0xC210 + i, claripy.BVV(0, 8))
        for i in range(15): self.state.memory.store(0xC112 + i * 16, claripy.BVV(0xFF, 8))
        extra = 2 if self.sprite_kind == 1 else 1 if self.sprite_kind == 2 else 0; self.state.memory.store(0xC110, claripy.BVV(4, 8)); self.state.memory.store(0xC214, claripy.BVV(0x12, 8)); self.state.memory.store(0xC215, claripy.BVV(0x13, 8)); self.state.memory.store(0xC216, claripy.BVV(0xD3, 8)); self.state.memory.store(0xD4E4, claripy.BVV(0xD4, 8)); self.state.memory.store(0xD4E5, claripy.BVV(0x40 if self.sprite_kind == 1 else 0x80 if self.sprite_kind == 2 else 0, 8)); self.state.memory.store(0xD504, claripy.BVV(0x55 if self.sprite_kind == 1 else 0x66 if self.sprite_kind == 2 else 0, 8)); self.state.memory.store(0xD505, claripy.BVV(0x77 if self.sprite_kind == 1 else 0, 8)); self.state.regs.hl = claripy.BVV(OBJECTS + 10 + extra, 16); self.state.regs.de = claripy.BVV(0xC120, 16); self.state.regs.b = claripy.BVV(0, 8); self.state.regs.c = claripy.BVV(2, 8); self.state.regs.a = claripy.BVV(0, 8); self.state.regs.f = claripy.BVV(0x42, 8); self.jump(self.target)

class TilesetSummary(angr.SimProcedure):
    def __init__(self, target: int) -> None: super().__init__(); self.target = target
    def run(self) -> None:
        for i in range(11): self.state.memory.store(W_BANK + i, self.state.memory.load(TILESETS + i, 1))
        self.state.memory.store(H_ANIM, self.state.memory.load(TILESETS + 11, 1)); self.state.memory.store(H_COUNTER, claripy.BVV(0, 8)); self.state.regs.d = claripy.BVV((W_BANK + 11) >> 8, 8); self.state.regs.e = claripy.BVV((W_BANK + 11) & 0xFF, 8); self.state.regs.b = claripy.BVV(0, 8); self.state.regs.c = claripy.BVV(0, 8); self.state.regs.f = claripy.BVV(0x40, 8); self.jump(self.target)

class WildSummary(angr.SimProcedure):
    def __init__(self, target: int) -> None: super().__init__(); self.target = target
    def run(self) -> None:
        self.state.memory.store(0xD887, claripy.BVV(0, 8)); self.state.memory.store(0xD8A4, claripy.BVV(0, 8)); self.state.regs.hl = claripy.BVV(OBJECTS + 2, 16); self.state.regs.f = claripy.BVV(0x40, 8); self.jump(self.target)

class FinishNormal(angr.SimProcedure):
    def run(self) -> None:
        self.state.regs.hl = self.state.globals["saved_hl"]; self.state.memory.store(W_HEIGHT2, claripy.BVV(4, 8)); self.state.memory.store(W_WIDTH2, claripy.BVV(6, 8)); self.state.regs.a = claripy.BVV(0, 8); self.state.regs.b = claripy.BVV(0, 8); self.state.regs.c = claripy.BVV(0, 8); self.state.regs.hl = claripy.BVV(0x404D, 16); self.state.regs.a = self.state.memory.load(0x404D, 1); self.state.memory.store(W_MUSIC, self.state.regs.a); self.state.regs.hl = claripy.BVV(0x404E, 16); self.state.regs.a = self.state.memory.load(0x404E, 1); self.state.memory.store(W_MUSIC + 1, self.state.regs.a); self.state.memory.store(H_LOADED, claripy.BVV(2, 8)); self.state.memory.store(ROMB, claripy.BVV(2, 8)); self.jump(RETURN)

def _setup(state: angr.SimState, base: int) -> None:
    for address, value in ((W_MAP, 0), (W_TILESET, 0x80), (W_UNUSED_TILESET, 0), (H_PREVIOUS, 0), (H_LOADED, 2), (ROMB, 2), (TOWN_VISITED, 0), (TOGGLE_PTRS, SOURCE & 0xff), (TOGGLE_PTRS + 1, SOURCE >> 8), (SOURCE, 0xff)):
        state.memory.store(base + address, claripy.BVV(value, 8))
    state.memory.store(base + TOGGLE_LIST, claripy.BVV(0, 8))

def _setup_normal(state: angr.SimState, base: int, warp_count: int = 0, sign_count: int = 0, sprite_count: int = 0, battle_over: int = 1) -> None:
    _setup(state, base)
    state.memory.store(base + W_TILESET, claripy.BVV(0, 8)); state.memory.store(base + H_PREVIOUS, claripy.BVV(0, 8)); state.memory.store(base + 0xD72E, claripy.BVV(0x40 if battle_over else 0, 8))
    state.memory.store(base + MAP_POINTERS, claripy.BVV(HEADER & 0xFF, 8)); state.memory.store(base + MAP_POINTERS + 1, claripy.BVV(HEADER >> 8, 8))
    header = (0, 2, 3, 0x00, 0x93, 0x00, 0x94, 0x00, 0x95, 0)
    for i, value in enumerate(header): state.memory.store(base + HEADER + i, claripy.BVV(value, 8))
    state.memory.store(base + HEADER + 10, claripy.BVV(OBJECTS & 0xFF, 8)); state.memory.store(base + HEADER + 11, claripy.BVV(OBJECTS >> 8, 8))
    state.memory.store(base + OBJECTS, claripy.BVV(0x55, 8)); state.memory.store(base + OBJECTS + 1, claripy.BVV(warp_count, 8));
    for i, value in enumerate((0x11, 0x22, 0x33, 0x44)): state.memory.store(base + OBJECTS + 2 + i, claripy.BVV(value if warp_count else 0, 8))
    sign_offset = 2 + warp_count * 4; state.memory.store(base + OBJECTS + sign_offset, claripy.BVV(sign_count, 8))
    if sign_count: state.memory.store(base + OBJECTS + sign_offset + 1, claripy.BVV(0x12, 8)); state.memory.store(base + OBJECTS + sign_offset + 2, claripy.BVV(0x23, 8)); state.memory.store(base + OBJECTS + sign_offset + 3, claripy.BVV(0x34, 8))
    sprite_offset = sign_offset + 1 + sign_count * 3; state.memory.store(base + OBJECTS + sprite_offset, claripy.BVV(sprite_count, 8))
    if sprite_count:
        for i, value in enumerate((4, 0x12, 0x13, 0xD3, 0xD4, 0)): state.memory.store(base + OBJECTS + sprite_offset + 1 + i, claripy.BVV(value, 8))
    for i in range(4): state.memory.store(base + 0xD3AF + i, claripy.BVV(0, 8))
    for address in (0xD4B1, 0xD4B2, 0xD4D1): state.memory.store(base + address, claripy.BVV(0, 8))
    # The assembly harness enables ZERO_FILL_UNCONSTRAINED_MEMORY.  Seed the
    # sprite endpoint bytes explicitly too, so early battle-over exits have
    # the same concrete zero state on the native side.
    for address in (0xC110, 0xC214, 0xC215, 0xC216, 0xD4E4, 0xD4E5): state.memory.store(base + address, claripy.BVV(0, 8))
    state.memory.store(base + W_SPRITES, claripy.BVV(0, 8)); state.memory.store(base + W_HEIGHT2, claripy.BVV(0, 8)); state.memory.store(base + W_WIDTH2, claripy.BVV(0, 8))
    for i in range(12): state.memory.store(base + TILESETS + i, claripy.BVV(0x20 + i, 8))
    state.memory.store(base + DUNGEONS, claripy.BVV(0xFF, 8)); state.memory.store(base + 0x4EEB, claripy.BVV(0x00, 8)); state.memory.store(base + 0x4EEC, claripy.BVV(0x95, 8)); state.memory.store(base + 0x9500, claripy.BVV(0, 8)); state.memory.store(base + 0x9501, claripy.BVV(0, 8)); state.memory.store(base + 0x404D, claripy.BVV(0x12, 8)); state.memory.store(base + 0x404E, claripy.BVV(0x34, 8))
    for address, value in ((0xCC4F, 0x88), (0xCC50, 0x00), (0xCC51, 0x89), (0xCC52, 0x00), (0xCC53, 0x34), (0xCC54, 0x12)): state.memory.store(base + address, claripy.BVV(value, 8))

def _endpoint(state: angr.SimState, register_base: int, memory_base: int, native: bool) -> Endpoint:
    fields = native_registers(state, register_base) if native else assembly_registers(state)
    memory = claripy.Concat(*[state.memory.load(memory_base + a, 1) for a in (W_TILESET, W_UNUSED_TILESET, H_PREVIOUS, H_LOADED, ROMB, TOWN_VISITED, TOGGLE_LIST)])
    return Endpoint(**fields, memory=memory, constraints=tuple(state.solver.constraints))

def _normal_endpoint(state: angr.SimState, register_base: int, memory_base: int, native: bool) -> NormalEndpoint:
    fields = native_registers(state, register_base) if native else assembly_registers(state)
    chunks = [state.memory.load(memory_base + W_TILESET + i, 1) for i in range(10)]
    chunks += [state.memory.load(memory_base + a, 1) for a in (0xD371, 0xD37C, 0xD387, 0xD392, W_BG, W_WARPS)]
    chunks += [state.memory.load(memory_base + 0xD3AF + i, 1) for i in range(4)]
    chunks += [state.memory.load(memory_base + a, 1) for a in (W_SIGNS, W_SPRITES, H_ANIM, H_COUNTER, 0xD887, 0xD8A4, W_HEIGHT2, W_WIDTH2, W_MUSIC, W_MUSIC + 1, TOWN_VISITED, 0xD4B1, 0xD4B2, 0xD4D1)]
    chunks += [state.memory.load(memory_base + a, 1) for a in (0xC110, 0xC214, 0xC215, 0xC216, 0xD4E4, 0xD4E5)]
    chunks += [state.memory.load(memory_base + W_BANK + i, 1) for i in range(11)]
    return NormalEndpoint(**fields, memory=claripy.Concat(*chunks), constraints=tuple(state.solver.constraints))

def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    loc = symbol_location(SYMBOLS, "LoadMapHeader"); end = symbol_location(SYMBOLS, "CopyMapConnectionHeader"); body = linked_bytes(ROM, loc, end.address - loc.address); assert len(body) == 0x1bc
    p = angr.Project(rom_window(ROM, loc.bank), auto_load_libs=False, rebase_granularity=0x100, main_opts={"backend":"blob", "arch":ArchPcode("z80:LE:16:default"), "base_addr":0, "entry_point":loc.address})
    p.hook(loc.address + 0, MarkTown(loc.address + 8), length=8); p.hook(loc.address + 8, Sm83LoadAImmediate(W_TILESET, loc.address + 0xb), length=3); p.hook(loc.address + 0xb, Sm83StoreAImmediate(W_UNUSED_TILESET, loc.address + 0xe), length=3); p.hook(loc.address + 0xe, Sm83LoadAImmediate(W_MAP, loc.address + 0x11), length=3); p.hook(loc.address + 0x11, SwitchBank(loc.address + 0x14), length=3); p.hook(loc.address + 0x14, Sm83LoadAImmediate(W_TILESET, loc.address + 0x17), length=3); p.hook(loc.address + 0x17, MoveAToB(loc.address + 0x18), length=1); p.hook(loc.address + 0x18, ResetBit(loc.address + 0x1a), length=2); p.hook(loc.address + 0x1a, Sm83StoreAImmediate(W_TILESET, loc.address + 0x1d), length=3); p.hook(loc.address + 0x1d, Sm83StoreAHighImmediate(H_PREVIOUS & 0xff, loc.address + 0x1f), length=2); p.hook(loc.address + 0x1f, RetNZ(), length=2)
    s = p.factory.blank_state(addr=loc.address); set_assembly_registers(s, values); _setup(s, 0); s.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY); m = p.factory.simulation_manager(s); m.explore(find=RETURN); assert not m.errored and m.found; return [_endpoint(x, 0, 0, False) for x in m.found]

def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    p = angr.Project(ELF, auto_load_libs=False); fn = p.loader.find_symbol("port_load_map_header"); assert fn is not None; s = p.factory.call_state(fn.rebased_addr, NATIVE_STATE, NATIVE_MEMORY); store_native_registers(s, NATIVE_STATE, values); _setup(s, NATIVE_MEMORY); m = p.factory.simulation_manager(s); m.run(); assert not m.errored and len(m.deadended) == 1; return [_endpoint(m.deadended[0], NATIVE_STATE, NATIVE_MEMORY, True)]

def _assembly_normal(values: dict[str, claripy.ast.BV], warp_count: int = 0, sign_count: int = 0, sprite_count: int = 0) -> list[NormalEndpoint]:
    loc = symbol_location(SYMBOLS, "LoadMapHeader"); end = symbol_location(SYMBOLS, "CopyMapConnectionHeader"); body = linked_bytes(ROM, loc, end.address - loc.address); assert len(body) == 0x1bc
    p = angr.Project(rom_window(ROM, loc.bank), auto_load_libs=False, rebase_granularity=0x100, main_opts={"backend":"blob", "arch":ArchPcode("z80:LE:16:default"), "base_addr":0, "entry_point":loc.address})
    p.hook(loc.address + 0, MarkTown(loc.address + 8), length=8); p.hook(loc.address + 8, Sm83LoadAImmediate(W_TILESET, loc.address + 0xb), length=3); p.hook(loc.address + 0xb, Sm83StoreAImmediate(W_UNUSED_TILESET, loc.address + 0xe), length=3); p.hook(loc.address + 0xe, Sm83LoadAImmediate(W_MAP, loc.address + 0x11), length=3); p.hook(loc.address + 0x11, SwitchBank(loc.address + 0x14), length=3); p.hook(loc.address + 0x14, Sm83LoadAImmediate(W_TILESET, loc.address + 0x17), length=3); p.hook(loc.address + 0x17, MoveAToB(loc.address + 0x18), length=1); p.hook(loc.address + 0x18, ResetBit(loc.address + 0x1a), length=2); p.hook(loc.address + 0x1a, Sm83StoreAImmediate(W_TILESET, loc.address + 0x1d), length=3); p.hook(loc.address + 0x1d, Sm83StoreAHighImmediate(H_PREVIOUS & 0xff, loc.address + 0x1f), length=2); p.hook(loc.address + 0x1f, RetNZ(), length=2)
    p.hook(loc.address + 0x22, FixedHeader(loc.address + 0x40), length=0x1e); p.hook(loc.address + 0x40, NoConnections(loc.address + 0x7a), length=0x3a); p.hook(loc.address + 0x7a, ZeroObjects(loc.address + 0x94, warp_count, sign_count, sprite_count), length=0x1a); p.hook(loc.address + 0x94, Skip(loc.address + 0xa6), length=2); p.hook(loc.address + 0xa6, Skip(loc.address + 0xd4), length=0x2e); p.hook(loc.address + 0xd4, SpriteSummary(loc.address + 0x17c) if sprite_count else Skip(loc.address + 0x17c), length=7); p.hook(loc.address + 0x17c, TilesetSummary(loc.address + 0x180), length=4); p.hook(loc.address + 0x180, WildSummary(loc.address + 0x189), length=9); p.hook(loc.address + 0x189, FinishNormal(), length=0x33)
    s = p.factory.blank_state(addr=loc.address); set_assembly_registers(s, values); _setup_normal(s, 0, warp_count, sign_count, sprite_count, not sprite_count); s.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY); m = p.factory.simulation_manager(s); m.explore(find=RETURN); assert not m.errored and m.found; return [_normal_endpoint(x, 0, 0, False) for x in m.found]

def _native_normal(values: dict[str, claripy.ast.BV], warp_count: int = 0, sign_count: int = 0, sprite_count: int = 0) -> list[NormalEndpoint]:
    p = angr.Project(ELF, auto_load_libs=False); fn = p.loader.find_symbol("port_load_map_header"); assert fn is not None; s = p.factory.call_state(fn.rebased_addr, NATIVE_STATE, NATIVE_MEMORY); store_native_registers(s, NATIVE_STATE, values); _setup_normal(s, NATIVE_MEMORY, warp_count, sign_count, sprite_count, not sprite_count); m = p.factory.simulation_manager(s); m.run(); assert not m.errored and len(m.deadended) == 1; return [_normal_endpoint(m.deadended[0], NATIVE_STATE, NATIVE_MEMORY, True)]

@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(), reason="build artifacts missing")
def test_load_map_header_pathwise_equivalence() -> None:
    values = {register: claripy.BVV(0, 8) for register in REGISTERS}; assert_pathwise_equivalent(_assembly(values), _native(values), (*REGISTERS, "memory"))

@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(), reason="build artifacts missing")
def test_load_map_header_normal_empty_objects_pathwise_equivalence() -> None:
    values = {register: claripy.BVV(0, 8) for register in REGISTERS}; assert_pathwise_equivalent(_assembly_normal(values), _native_normal(values), (*REGISTERS, "memory"))

@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(), reason="build artifacts missing")
def test_load_map_header_normal_one_warp_pathwise_equivalence() -> None:
    values = {register: claripy.BVV(0, 8) for register in REGISTERS}; assert_pathwise_equivalent(_assembly_normal(values, 1), _native_normal(values, 1), (*REGISTERS, "memory"))

@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(), reason="build artifacts missing")
def test_load_map_header_normal_one_sign_pathwise_equivalence() -> None:
    values = {register: claripy.BVV(0, 8) for register in REGISTERS}; assert_pathwise_equivalent(_assembly_normal(values, 0, 1), _native_normal(values, 0, 1), (*REGISTERS, "memory"))

@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(), reason="build artifacts missing")
def test_load_map_header_normal_one_regular_sprite_pathwise_equivalence() -> None:
    values = {register: claripy.BVV(0, 8) for register in REGISTERS}; assert_pathwise_equivalent(_assembly_normal(values, 0, 0, 1), _native_normal(values, 0, 0, 1), (*REGISTERS, "memory"))
