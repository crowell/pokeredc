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

@dataclass(frozen=True)
class Endpoint:
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

def _setup(state: angr.SimState, base: int) -> None:
    for address, value in ((W_MAP, 0), (W_TILESET, 0x80), (W_UNUSED_TILESET, 0), (H_PREVIOUS, 0), (H_LOADED, 2), (ROMB, 2), (TOWN_VISITED, 0), (TOGGLE_PTRS, SOURCE & 0xff), (TOGGLE_PTRS + 1, SOURCE >> 8), (SOURCE, 0xff)):
        state.memory.store(base + address, claripy.BVV(value, 8))
    state.memory.store(base + TOGGLE_LIST, claripy.BVV(0, 8))

def _endpoint(state: angr.SimState, register_base: int, memory_base: int, native: bool) -> Endpoint:
    fields = native_registers(state, register_base) if native else assembly_registers(state)
    memory = claripy.Concat(*[state.memory.load(memory_base + a, 1) for a in (W_TILESET, W_UNUSED_TILESET, H_PREVIOUS, H_LOADED, ROMB, TOWN_VISITED, TOGGLE_LIST)])
    return Endpoint(**fields, memory=memory, constraints=tuple(state.solver.constraints))

def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    loc = symbol_location(SYMBOLS, "LoadMapHeader"); end = symbol_location(SYMBOLS, "CopyMapConnectionHeader"); body = linked_bytes(ROM, loc, end.address - loc.address); assert len(body) == 0x1bc
    p = angr.Project(rom_window(ROM, loc.bank), auto_load_libs=False, rebase_granularity=0x100, main_opts={"backend":"blob", "arch":ArchPcode("z80:LE:16:default"), "base_addr":0, "entry_point":loc.address})
    p.hook(loc.address + 0, MarkTown(loc.address + 8), length=8); p.hook(loc.address + 8, Sm83LoadAImmediate(W_TILESET, loc.address + 0xb), length=3); p.hook(loc.address + 0xb, Sm83StoreAImmediate(W_UNUSED_TILESET, loc.address + 0xe), length=3); p.hook(loc.address + 0xe, Sm83LoadAImmediate(W_MAP, loc.address + 0x11), length=3); p.hook(loc.address + 0x11, SwitchBank(loc.address + 0x14), length=3); p.hook(loc.address + 0x14, Sm83LoadAImmediate(W_TILESET, loc.address + 0x17), length=3); p.hook(loc.address + 0x17, MoveAToB(loc.address + 0x18), length=1); p.hook(loc.address + 0x18, ResetBit(loc.address + 0x1a), length=2); p.hook(loc.address + 0x1a, Sm83StoreAImmediate(W_TILESET, loc.address + 0x1d), length=3); p.hook(loc.address + 0x1d, Sm83StoreAHighImmediate(H_PREVIOUS & 0xff, loc.address + 0x1f), length=2); p.hook(loc.address + 0x1f, RetNZ(), length=2)
    s = p.factory.blank_state(addr=loc.address); set_assembly_registers(s, values); _setup(s, 0); s.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY); m = p.factory.simulation_manager(s); m.explore(find=RETURN); assert not m.errored and m.found; return [_endpoint(x, 0, 0, False) for x in m.found]

def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    p = angr.Project(ELF, auto_load_libs=False); fn = p.loader.find_symbol("port_load_map_header"); assert fn is not None; s = p.factory.call_state(fn.rebased_addr, NATIVE_STATE, NATIVE_MEMORY); store_native_registers(s, NATIVE_STATE, values); _setup(s, NATIVE_MEMORY); m = p.factory.simulation_manager(s); m.run(); assert not m.errored and len(m.deadended) == 1; return [_endpoint(m.deadended[0], NATIVE_STATE, NATIVE_MEMORY, True)]

@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(), reason="build artifacts missing")
def test_load_map_header_pathwise_equivalence() -> None:
    values = {register: claripy.BVV(0, 8) for register in REGISTERS}; assert_pathwise_equivalent(_assembly(values), _native(values), (*REGISTERS, "memory"))
