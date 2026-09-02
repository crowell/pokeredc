from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
    REGISTERS, assembly_registers, native_registers, set_assembly_registers,
    store_native_registers, symbolic_registers,
)
from verification.harness.rom import linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import (
    Sm83AddImmediate, Sm83AddRegister, Sm83CpImmediate, Sm83DecRegister,
    Sm83IncRegister, Sm83LoadAAtHlIncrement, Sm83LoadAHighImmediate,
    Sm83StoreAAtHlIncrement, Sm83XorA,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xd000
RETURN = 0xffff


@dataclass(frozen=True)
class Endpoint:
    a: claripy.ast.BV; f: claripy.ast.BV; b: claripy.ast.BV; c: claripy.ast.BV
    d: claripy.ast.BV; e: claripy.ast.BV; h: claripy.ast.BV; l: claripy.ast.BV
    state: claripy.ast.BV; constraints: tuple[claripy.ast.Bool, ...]


class LoadReg(angr.SimProcedure):
    def __init__(self, dst: str, src: str, nxt: int) -> None:
        super().__init__(); self.dst = dst; self.src = src; self.nxt = nxt
    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.dst, getattr(self.state.regs, self.src)); self.jump(self.nxt)


class LoadAtHL(angr.SimProcedure):
    def __init__(self, nxt: int) -> None: super().__init__(); self.nxt = nxt
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self.state.regs.hl, 1); self.jump(self.nxt)


class StoreAtHL(angr.SimProcedure):
    def __init__(self, nxt: int) -> None: super().__init__(); self.nxt = nxt
    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(self.state.regs.hl, self.state.regs.a); self.jump(self.nxt)


class BranchNZ(angr.SimProcedure):
    def __init__(self, taken: int, fallthrough: int) -> None:
        super().__init__(); self.taken = taken; self.fallthrough = fallthrough
    def run(self) -> None:  # type: ignore[override]
        z = (self.state.regs.f & 0x40) != 0
        taken, fallthrough = self.state.copy(), self.state.copy()
        taken.solver.add(~z); fallthrough.solver.add(z)
        taken.regs.ip = claripy.BVV(self.taken, 16); fallthrough.regs.ip = claripy.BVV(self.fallthrough, 16)
        self.inhibit_autoret = True
        self.successors.add_successor(taken, self.taken, ~z, "Ijk_Boring")
        self.successors.add_successor(fallthrough, self.fallthrough, z, "Ijk_Boring")


class ReturnNZ(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.solver.add((self.state.regs.f & 0x40) == 0)
        target = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp += 2; self.jump(target)


def _setup(state: angr.SimState, base: int, values: dict[str, claripy.ast.BV]) -> None:
    for offset in range(3, 9):
        state.memory.store(base + 0xc100 + offset, values[f"state_{offset}"])
    state.memory.store(base + 0xc200, values["walk_counter"])
    state.memory.store(base + 0xffda, claripy.BVV(0, 8))


def _endpoint(state: angr.SimState, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    regs = native_registers(state, NATIVE_STATE) if native else assembly_registers(state)
    return Endpoint(**regs, state=claripy.Concat(*(
        state.memory.load(base + address, 1)
        for address in (*range(0xc103, 0xc109), 0xc200, 0xffda)
    )), constraints=tuple(state.solver.constraints))


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "UpdateSpriteInWalkingAnimation")
    assert linked_bytes(ROM, location, 43).hex() == "f0dac6076f7e3c77fe042008af772c7e3ce60377f0dac6036f2a477e80222a477e8077f0da6f247e3d77c0"
    p = angr.Project(rom_window(ROM, location.bank), auto_load_libs=False, rebase_granularity=0x100,
        main_opts={"backend":"blob", "arch":ArchPcode("z80:LE:16:default"), "base_addr":0, "entry_point":location.address})
    q = location.address
    p.hook(q, Sm83LoadAHighImmediate(0xda, q + 2), length=2); p.hook(q+2, Sm83AddImmediate(7, q+4), length=2)
    p.hook(q+4, LoadReg("l", "a", q+5), length=1); p.hook(q+5, LoadAtHL(q+6), length=1)
    p.hook(q+6, Sm83IncRegister("a", q+7), length=1); p.hook(q+7, StoreAtHL(q+8), length=1)
    p.hook(q+8, Sm83CpImmediate(4, q+10), length=2); p.hook(q+10, BranchNZ(q+20, q+12), length=2)
    p.hook(q+12, Sm83XorA(q+13), length=1); p.hook(q+13, StoreAtHL(q+14), length=1)
    p.hook(q+14, Sm83IncRegister("l", q+15), length=1); p.hook(q+15, LoadAtHL(q+16), length=1)
    p.hook(q+16, Sm83IncRegister("a", q+17), length=1)
    # AND $03: SM83 sets H (Z80-layout bit 4) and Z from the result.
    class And3(angr.SimProcedure):
        def run(self) -> None:  # type: ignore[override]
            self.state.regs.a &= 3; self.state.regs.f = claripy.BVV(0x10,8) | claripy.If(self.state.regs.a == 0, claripy.BVV(0x40,8), claripy.BVV(0,8)); self.jump(q+19)
    p.hook(q+17, And3(), length=2); p.hook(q+19, StoreAtHL(q+20), length=1)
    p.hook(q+20, Sm83LoadAHighImmediate(0xda,q+22), length=2); p.hook(q+22, Sm83AddImmediate(3,q+24), length=2); p.hook(q+24, LoadReg("l","a",q+25), length=1)
    p.hook(q+25, Sm83LoadAAtHlIncrement(q+26), length=1); p.hook(q+26, LoadReg("b","a",q+27), length=1); p.hook(q+27, LoadAtHL(q+28), length=1); p.hook(q+28, Sm83AddRegister("b",q+29), length=1); p.hook(q+29, Sm83StoreAAtHlIncrement(q+30), length=1)
    p.hook(q+30, Sm83LoadAAtHlIncrement(q+31), length=1); p.hook(q+31, LoadReg("b","a",q+32), length=1); p.hook(q+32, LoadAtHL(q+33), length=1); p.hook(q+33, Sm83AddRegister("b",q+34), length=1); p.hook(q+34, StoreAtHL(q+35), length=1)
    p.hook(q+35, Sm83LoadAHighImmediate(0xda,q+37), length=2); p.hook(q+37, LoadReg("l","a",q+38), length=1); p.hook(q+38, Sm83IncRegister("h",q+39), length=1); p.hook(q+39, LoadAtHL(q+40), length=1); p.hook(q+40, Sm83DecRegister("a",q+41), length=1); p.hook(q+41, StoreAtHL(q+42), length=1); p.hook(q+42, ReturnNZ(), length=1)
    state = p.factory.blank_state(addr=q); set_assembly_registers(state, values); _setup(state, 0, values)
    state.solver.add(values["walk_counter"] != 1)
    state.regs.sp=STACK; state.memory.store(STACK, claripy.BVV(RETURN,16),endness="Iend_LE")
    m=p.factory.simulation_manager(state); m.explore(find=RETURN, num_find=10); assert not m.errored and m.found
    return [_endpoint(x,False) for x in m.found]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    p=angr.Project(ELF,auto_load_libs=False); fn=p.loader.find_symbol("port_update_sprite_in_walking_animation"); assert fn
    state=p.factory.call_state(fn.rebased_addr,NATIVE_STATE,NATIVE_MEMORY); store_native_registers(state,NATIVE_STATE,values); _setup(state,NATIVE_MEMORY,values)
    # Restrict to the post-DEC nonzero terminal, matching the assembly body above.
    state.solver.add(values["walk_counter"] != 1)
    m=p.factory.simulation_manager(state); m.run(); assert not m.errored and m.deadended
    return [_endpoint(x,True) for x in m.deadended]


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(), reason="build artifacts missing")
def test_update_sprite_walking_animation_nonterminal_pathwise_equivalence() -> None:
    values=symbolic_registers("walking_tick"); values["h"]=claripy.BVV(0xc1,8)
    for key in (*[f"state_{n}" for n in range(3,9)], "walk_counter"): values[key]=claripy.BVS(f"walking_tick_{key}",8)
    values["walk_counter"] = claripy.BVS("walking_tick_counter",8)
    # Both sides use the same explicit restriction; the terminal Random and
    # next-movement paths are exercised in a separate compositional proof.
    assert_pathwise_equivalent(_assembly(values),_native(values),(*REGISTERS,"state"))
