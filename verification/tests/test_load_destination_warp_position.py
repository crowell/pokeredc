from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr, claripy, pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS, assembly_registers, native_registers, set_assembly_registers, store_native_registers
from verification.harness.rom import linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair, Sm83LoadAHighImmediate, Sm83LoadAImmediate, Sm83StoreAHighImmediate, Sm83StoreAImmediate

ROOT = Path(__file__).resolve().parents[2]; ELF = ROOT / "verification/build/ports.elf"; ROM = ROOT / "pokered.gbc"; SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000; NATIVE_MEMORY = 0x200000; RETURN = 0xEFFF
W_PREDEF_PARENT_BANK = 0xCF12; H_LOADED_ROM_BANK = 0xFFB8; W_CURRENT = 0xD35F; R_ROMB = 0x2000; SOURCE = 0x9000

@dataclass(frozen=True)
class Endpoint:
    a: claripy.ast.BV; f: claripy.ast.BV; b: claripy.ast.BV; c: claripy.ast.BV; d: claripy.ast.BV; e: claripy.ast.BV; h: claripy.ast.BV; l: claripy.ast.BV
    bank: claripy.ast.BV; mapper: claripy.ast.BV; output: claripy.ast.BV; constraints: tuple[claripy.ast.Bool, ...]

class Jump(angr.SimProcedure):
    def __init__(self, target: int) -> None: super().__init__(); self.target = target
    def run(self) -> None: self.jump(self.target)

class MoveAToRegister(angr.SimProcedure):
    def __init__(self, register: str, target: int) -> None: super().__init__(); self.register = register; self.target = target
    def run(self) -> None: setattr(self.state.regs, self.register, self.state.regs.a); self.jump(self.target)

class LoadRegisterToA(angr.SimProcedure):
    def __init__(self, register: str, target: int) -> None: super().__init__(); self.register = register; self.target = target
    def run(self) -> None: self.state.regs.a = getattr(self.state.regs, self.register); self.jump(self.target)

class SetPair(angr.SimProcedure):
    def __init__(self, pair: str, value: int, target: int) -> None: super().__init__(); self.pair = pair; self.value = value; self.target = target
    def run(self) -> None:
        setattr(self.state.regs, self.pair, claripy.BVV(self.value, 16)); self.jump(self.target)

class SetRegister(angr.SimProcedure):
    def __init__(self, register: str, value: int, target: int) -> None: super().__init__(); self.register = register; self.value = value; self.target = target
    def run(self) -> None: setattr(self.state.regs, self.register, claripy.BVV(self.value, 8)); self.jump(self.target)

class DoubleTwiceAndMoveC(angr.SimProcedure):
    def __init__(self, target: int) -> None: super().__init__(); self.target = target
    def run(self) -> None: self.state.regs.a = self.state.regs.a * 4; self.state.regs.c = self.state.regs.a; self.jump(self.target)

class PushAF(angr.SimProcedure):
    def __init__(self, target: int) -> None: super().__init__(); self.target = target
    def run(self) -> None: self.state.globals["saved_af"] = (self.state.regs.a, self.state.regs.f); self.jump(self.target)

class PopAF(angr.SimProcedure):
    def __init__(self, target: int) -> None: super().__init__(); self.target = target
    def run(self) -> None:
        self.state.regs.a, self.state.regs.f = self.state.globals["saved_af"]; self.jump(self.target)

class CopyDataSummary(angr.SimProcedure):
    def __init__(self, target: int) -> None: super().__init__(); self.target = target
    def run(self) -> None:
        hl = self.state.regs.hl; de = self.state.regs.de; count = 4
        for _ in range(count):
            value = self.state.memory.load(hl, 1); self.state.memory.store(de, value); hl = hl + 1; de = de + 1
        self.state.regs.hl = hl; self.state.regs.de = de; self.state.regs.bc = 0; self.state.regs.a = 0; self.state.regs.f = 0x40; self.jump(self.target)

def _setup(state: angr.SimState, base: int, warp: int) -> None:
    state.memory.store(base + W_PREDEF_PARENT_BANK, claripy.BVV(0x12, 8)); state.memory.store(base + H_LOADED_ROM_BANK, claripy.BVV(0x06, 8)); state.memory.store(base + R_ROMB, claripy.BVV(0x06, 8))
    for i, value in enumerate((0x21, 0x32, 0x43, 0x54)): state.memory.store(base + SOURCE + warp * 4 + i, claripy.BVV(value, 8))
    for i in range(4): state.memory.store(base + W_CURRENT + i, claripy.BVV(0, 8))

def _endpoint(state: angr.SimState, base: int, native: bool = False, memory_base: int | None = None) -> Endpoint:
    if memory_base is None: memory_base = base
    fields = native_registers(state, base) if native else assembly_registers(state)
    return Endpoint(**fields, bank=state.memory.load(memory_base + H_LOADED_ROM_BANK, 1), mapper=state.memory.load(memory_base + R_ROMB, 1), output=state.memory.load(memory_base + W_CURRENT, 4), constraints=tuple(state.solver.constraints))

def _assembly(values: dict[str, claripy.ast.BV], warp: int) -> list[Endpoint]:
    loc = symbol_location(SYMBOLS, "LoadDestinationWarpPosition"); end = symbol_location(SYMBOLS, "DrawHPBar"); body = linked_bytes(ROM, loc, end.address - loc.address); assert len(body) == 35
    p = angr.Project(rom_window(ROM, loc.bank), auto_load_libs=False, rebase_granularity=0x100, main_opts={"backend":"blob", "arch":ArchPcode("z80:LE:16:default"), "base_addr":0, "entry_point":loc.address})
    p.hook(loc.address + 0, MoveAToRegister("b", loc.address + 1), length=1); p.hook(loc.address + 1, Sm83LoadAHighImmediate(0xb8, loc.address + 3), length=2); p.hook(loc.address + 3, PushAF(loc.address + 4), length=1)
    p.hook(loc.address + 4, Sm83LoadAImmediate(W_PREDEF_PARENT_BANK, loc.address + 7), length=3); p.hook(loc.address + 7, Sm83StoreAHighImmediate(0xb8, loc.address + 9), length=2); p.hook(loc.address + 9, Sm83StoreAImmediate(R_ROMB, loc.address + 0xc), length=3)
    p.hook(loc.address + 0xc, LoadRegisterToA("b", loc.address + 0xd), length=1); p.hook(loc.address + 0xd, DoubleTwiceAndMoveC(loc.address + 0x10), length=3); p.hook(loc.address + 0x10, SetRegister("b", 0, loc.address + 0x12), length=2); p.hook(loc.address + 0x12, Sm83AddHlRegisterPair("bc", loc.address + 0x13), length=1); p.hook(loc.address + 0x13, SetPair("bc", 4, loc.address + 0x16), length=3); p.hook(loc.address + 0x16, SetPair("de", W_CURRENT, loc.address + 0x19), length=3); p.hook(loc.address + 0x19, CopyDataSummary(loc.address + 0x1c), length=3); p.hook(loc.address + 0x1c, PopAF(loc.address + 0x1d), length=1); p.hook(loc.address + 0x1d, Sm83StoreAHighImmediate(0xb8, loc.address + 0x1f), length=2); p.hook(loc.address + 0x1f, Sm83StoreAImmediate(R_ROMB, loc.address + 0x22), length=3); p.hook(loc.address + 0x22, Jump(RETURN), length=1)
    s = p.factory.blank_state(addr=loc.address); set_assembly_registers(s, values); _setup(s, 0, warp); s.memory.store(SOURCE + warp * 4, claripy.BVV(0x21, 8)); s.memory.store(SOURCE + warp * 4 + 1, claripy.BVV(0x32, 8)); s.memory.store(SOURCE + warp * 4 + 2, claripy.BVV(0x43, 8)); s.memory.store(SOURCE + warp * 4 + 3, claripy.BVV(0x54, 8)); s.regs.a = claripy.BVV(warp, 8); s.regs.h = claripy.BVV(SOURCE >> 8, 8); s.regs.l = claripy.BVV(SOURCE & 0xff, 8); s.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY); m = p.factory.simulation_manager(s); m.explore(find=RETURN); assert not m.errored and m.found
    return [_endpoint(x, 0) for x in m.found]

def _native(values: dict[str, claripy.ast.BV], warp: int) -> list[Endpoint]:
    p = angr.Project(ELF, auto_load_libs=False); fn = p.loader.find_symbol("port_load_destination_warp_position"); assert fn is not None; s = p.factory.call_state(fn.rebased_addr, NATIVE_STATE, NATIVE_MEMORY); store_native_registers(s, NATIVE_STATE, values); s.memory.store(NATIVE_STATE, claripy.BVV(warp, 8)); s.memory.store(NATIVE_STATE + 6, claripy.BVV(SOURCE >> 8, 8)); s.memory.store(NATIVE_STATE + 7, claripy.BVV(SOURCE & 0xff, 8)); _setup(s, NATIVE_MEMORY, warp); s.memory.store(NATIVE_MEMORY + SOURCE + warp * 4, claripy.BVV(0x21, 8)); s.memory.store(NATIVE_MEMORY + SOURCE + warp * 4 + 1, claripy.BVV(0x32, 8)); s.memory.store(NATIVE_MEMORY + SOURCE + warp * 4 + 2, claripy.BVV(0x43, 8)); s.memory.store(NATIVE_MEMORY + SOURCE + warp * 4 + 3, claripy.BVV(0x54, 8)); m = p.factory.simulation_manager(s); m.run(); assert not m.errored and len(m.deadended) == 1; return [_endpoint(m.deadended[0], NATIVE_STATE, True, NATIVE_MEMORY)]

@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(), reason="build artifacts missing")
@pytest.mark.parametrize("warp", (0, 1, 3))
def test_load_destination_warp_position_pathwise_equivalence(warp: int) -> None:
    values = {register: claripy.BVV(0, 8) for register in REGISTERS}; assert_pathwise_equivalent(_assembly(values, warp), _native(values, warp), (*REGISTERS, "bank", "mapper", "output"))
