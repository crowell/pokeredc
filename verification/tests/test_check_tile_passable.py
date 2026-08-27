from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS, assembly_registers, native_registers, set_assembly_registers, store_native_registers
from verification.harness.rom import linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import Sm83CpImmediate, Sm83LoadAAtHlIncrement, Sm83LoadAImmediate, Sm83Scf, Sm83CpRegister

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"; ROM = ROOT / "pokered.gbc"; SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000; NATIVE_MEMORY = 0x200000; RETURN = 0xEFFF
W_TILE = 0xCFC6; W_COLLISION_PTR = 0xD530; W_TILEMAP = 0xC3A0
W_Y = 0xD361; W_X = 0xD362; W_FACING = 0xC109

@dataclass(frozen=True)
class Endpoint:
    a: claripy.ast.BV; f: claripy.ast.BV; b: claripy.ast.BV; c: claripy.ast.BV
    d: claripy.ast.BV; e: claripy.ast.BV; h: claripy.ast.BV; l: claripy.ast.BV
    tile: claripy.ast.BV; constraints: tuple[claripy.ast.Bool, ...]

class TilePredef(angr.SimProcedure):
    def __init__(self, target: int) -> None: super().__init__(); self.target = target
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(W_TILEMAP + 8 + 11 * 20, 1)
        self.state.regs.c = self.state.regs.a
        self.state.memory.store(W_TILE, self.state.regs.a)
        self.state.regs.d = claripy.BVV(11, 8); self.state.regs.e = claripy.BVV(10, 8)
        self.state.regs.f = claripy.BVV(0, 8); self.jump(self.target)

class Return(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(RETURN)


class MoveAToC(angr.SimProcedure):
    def __init__(self, target: int) -> None: super().__init__(); self.target = target
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.c = self.state.regs.a; self.jump(self.target)


class JumpIfZero(angr.SimProcedure):
    def __init__(self, taken: int, fallthrough: int) -> None:
        super().__init__(); self.taken = taken; self.fallthrough = fallthrough

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        condition = (self.state.regs.f & 0x40) != 0
        self.successors.add_successor(self.state.copy(), self.taken, condition, "Ijk_Boring")
        self.successors.add_successor(self.state.copy(), self.fallthrough, claripy.Not(condition), "Ijk_Boring")


class Jump(angr.SimProcedure):
    def __init__(self, target: int) -> None: super().__init__(); self.target = target
    def run(self) -> None:  # type: ignore[override]
        self.jump(self.target)

def _setup(state: angr.SimState, base: int, tile: int) -> None:
    state.memory.store(base + W_Y, claripy.BVV(10, 8)); state.memory.store(base + W_X, claripy.BVV(10, 8))
    state.memory.store(base + W_FACING, claripy.BVV(0, 8))
    state.memory.store(base + W_TILEMAP + 8 + 11 * 20, claripy.BVV(tile, 8))
    state.memory.store(base + W_TILE, claripy.BVV(0, 8))
    state.memory.store(base + W_COLLISION_PTR, claripy.BVV(0x9000, 16), endness="Iend_LE")
    for i, value in enumerate((0x11, 0x22, 0xff)): state.memory.store(base + 0x9000 + i, claripy.BVV(value, 8))

def _assembly(values: dict[str, claripy.ast.BV], tile: int) -> list[Endpoint]:
    loc = symbol_location(SYMBOLS, "CheckTilePassable"); end = symbol_location(SYMBOLS, "CheckForJumpingAndTilePairCollisions")
    body = linked_bytes(ROM, loc, end.address - loc.address); assert len(body) == 26
    project = angr.Project(rom_window(ROM, loc.bank), auto_load_libs=False, rebase_granularity=0x100,
        main_opts={"backend":"blob", "arch":ArchPcode("z80:LE:16:default"), "base_addr":0, "entry_point":loc.address})
    project.hook(loc.address + 2, TilePredef(loc.address + 5), length=3)
    project.hook(loc.address + 5, Sm83LoadAImmediate(W_TILE, loc.address + 8), length=3)
    project.hook(loc.address + 8, MoveAToC(loc.address + 9), length=1)
    project.hook(loc.address + 0x0C, Sm83LoadAAtHlIncrement(loc.address + 0x0D), length=1)
    project.hook(loc.address + 0x0F, Sm83LoadAAtHlIncrement(loc.address + 0x10), length=1)
    project.hook(loc.address + 0x10, Sm83CpImmediate(0xff, loc.address + 0x12), length=2)
    project.hook(loc.address + 0x14, Sm83CpRegister("c", loc.address + 0x15), length=1)
    project.hook(loc.address + 0x12, JumpIfZero(loc.address + 0x18, loc.address + 0x14), length=2)
    project.hook(loc.address + 0x15, JumpIfZero(RETURN, loc.address + 0x16), length=1)
    project.hook(loc.address + 0x16, Jump(loc.address + 0x0F), length=2)
    project.hook(loc.address + 0x18, Sm83Scf(loc.address + 0x19), length=1)
    project.hook(loc.address + 0x19, Return(), length=1)
    state = project.factory.blank_state(addr=loc.address); set_assembly_registers(state, values); _setup(state, 0, tile)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state); manager.explore(find=RETURN, num_find=8)
    assert not manager.errored and manager.found
    return [Endpoint(**assembly_registers(x), tile=x.memory.load(W_TILE, 1), constraints=tuple(x.solver.constraints)) for x in manager.found]

def _native(values: dict[str, claripy.ast.BV], tile: int) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False); function = project.loader.find_symbol("port_check_tile_passable"); assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY); store_native_registers(state, NATIVE_STATE, values); _setup(state, NATIVE_MEMORY, tile)
    manager = project.factory.simulation_manager(state); manager.run(); assert not manager.errored and len(manager.deadended) == 1
    return [Endpoint(**native_registers(x, NATIVE_STATE), tile=x.memory.load(NATIVE_MEMORY + W_TILE, 1), constraints=tuple(x.solver.constraints)) for x in manager.deadended]

@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(), reason="build artifacts missing")
@pytest.mark.parametrize("tile", (0x11, 0x33, 0xff))
def test_check_tile_passable_pathwise_equivalence(tile: int) -> None:
    # The helper's only behavioral inputs are the front tile and collision
    # table; fixed entry registers keep the tiny scan proof solver-friendly.
    values = {register: claripy.BVV(0, 8) for register in REGISTERS}
    assert_pathwise_equivalent(_assembly(values, tile), _native(values, tile), (*REGISTERS, "tile"))
