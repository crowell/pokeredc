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

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NS = 0x100000
NM = 0x200000
STACK = 0xd000
RET = 0xffff
S1 = 0xc100
S2 = 0xc200
MAP_SPRITE_MOVEMENT2 = 0xd4e2
CUR_MOVEMENT2 = 0xcf14
OFFSET = 0xffda
HIDDEN = 0xffe5
TOGGLE_LIST = 0xd5ce
TOGGLE_FLAGS = 0xd5a6
BODY = bytes.fromhex(
    "f0dacb373d8721e4d4856f7eea14cf26c1f0da6f2c7ea7caad50cddc50d826c1"
    "f0da6f2c7ecb7fc27f5047fac4cfcb47c2735078fe02ca5750fe03cafe4ffac5c"
    "fa7c0cdbd5026c2f0dac6066f7e3c28373c28343d773de5210fcf35e1115bcccd"
    "2f52fee0cac84ffeff200e772130d7cb86afea38cdea3acdc9fefe20103601115b"
    "cccd2f521806cd0752cd5c3e47fa14cffed02818fed1282bfed2283efed3284b78"
    "fe403013fa14cffe02282e112800191100010100041840fe803013fa14cffe0228"
    "2811d8ff191100ff0104081829fec03011fa14cffe0128e92b2b11ff0001080218"
    "14fa14cffe0128c12323110100010c011803110000"
)


@dataclass(frozen=True)
class E:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    state: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class Imm(angr.SimProcedure):
    def __init__(self, register: str, value: int, next_address: int) -> None:
        super().__init__(); self.register = register; self.value = value; self.next_address = next_address
    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.register, claripy.BVV(self.value, 8)); self.jump(self.next_address)


class Pair(angr.SimProcedure):
    def __init__(self, value: int, next_address: int) -> None:
        super().__init__(); self.value = value; self.next_address = next_address
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = claripy.BVV(self.value >> 8, 8)
        self.state.regs.l = claripy.BVV(self.value & 0xff, 8)
        self.jump(self.next_address)


class Reg(angr.SimProcedure):
    def __init__(self, destination: str, source: str, next_address: int) -> None:
        super().__init__(); self.destination = destination; self.source = source; self.next_address = next_address
    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.destination, getattr(self.state.regs, self.source)); self.jump(self.next_address)


class LoadHighA(angr.SimProcedure):
    def __init__(self, address: int, next_address: int) -> None:
        super().__init__(); self.address = address; self.next_address = next_address
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self.address, 1); self.jump(self.next_address)


class LoadAtHL(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__(); self.next_address = next_address
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self.state.regs.hl, 1); self.jump(self.next_address)


class StoreAbsoluteA(angr.SimProcedure):
    def __init__(self, address: int, next_address: int) -> None:
        super().__init__(); self.address = address; self.next_address = next_address
    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(self.address, self.state.regs.a); self.jump(self.next_address)


class SwapA(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__(); self.next_address = next_address
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = (self.state.regs.a << 4) | claripy.LShR(self.state.regs.a, 4)
        self.state.regs.f = claripy.If(self.state.regs.a == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        self.jump(self.next_address)


class DecA(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__(); self.next_address = next_address
    def run(self) -> None:  # type: ignore[override]
        before = self.state.regs.a; self.state.regs.a = before - 1
        self.state.regs.f = (self.state.regs.f & 1) | 2 | claripy.If(self.state.regs.a == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)) | claripy.If((before & 0xf) == 0, claripy.BVV(0x10, 8), claripy.BVV(0, 8))
        self.jump(self.next_address)


class AddA(angr.SimProcedure):
    def __init__(self, value: int | str, next_address: int) -> None:
        super().__init__(); self.value = value; self.next_address = next_address
    def run(self) -> None:  # type: ignore[override]
        left = self.state.regs.a
        right = getattr(self.state.regs, self.value) if isinstance(self.value, str) else claripy.BVV(self.value, 8)
        wide = claripy.ZeroExt(1, left) + claripy.ZeroExt(1, right); self.state.regs.a = wide[7:0]
        self.state.regs.f = claripy.If(self.state.regs.a == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)) | claripy.If((left & 0xf) + (right & 0xf) > 0xf, claripy.BVV(0x10, 8), claripy.BVV(0, 8)) | claripy.ZeroExt(7, wide[8])
        self.jump(self.next_address)


class IncL(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__(); self.next_address = next_address
    def run(self) -> None:  # type: ignore[override]
        before = self.state.regs.l; self.state.regs.l = before + 1
        self.state.regs.f = (self.state.regs.f & 1) | claripy.If(self.state.regs.l == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)) | claripy.If((before & 0xf) == 0xf, claripy.BVV(0x10, 8), claripy.BVV(0, 8))
        self.jump(self.next_address)


class AndA(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__(); self.next_address = next_address
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.f = claripy.BVV(0x10, 8) | claripy.If(self.state.regs.a == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)); self.jump(self.next_address)


class BranchZero(angr.SimProcedure):
    def __init__(self, taken: int, fallthrough: int) -> None:
        super().__init__(); self.taken = taken; self.fallthrough = fallthrough
    def run(self) -> None:  # type: ignore[override]
        condition = (self.state.regs.f & 0x40) != 0
        taken = self.state.copy(); fallthrough = self.state.copy()
        taken.solver.add(condition); fallthrough.solver.add(~condition)
        taken.regs.ip = claripy.BVV(self.taken, 16); fallthrough.regs.ip = claripy.BVV(self.fallthrough, 16)
        self.inhibit_autoret = True
        self.successors.add_successor(taken, self.taken, condition, "Ijk_Boring")
        self.successors.add_successor(fallthrough, self.fallthrough, ~condition, "Ijk_Boring")


class InitializeStatusBoundary(angr.SimProcedure):
    """Complete proven InitializeSpriteStatus transition for the entry slot."""
    def __init__(self, next_address: int) -> None:
        super().__init__(); self.next_address = next_address
    def run(self) -> None:  # type: ignore[override]
        offset = self.state.memory.load(OFFSET, 1)
        self.state.memory.store(self.state.regs.hl, claripy.BVV(1, 8))
        self.state.regs.l += 1
        self.state.memory.store(self.state.regs.hl, claripy.BVV(0xff, 8))
        self.state.regs.h += 1
        left = offset; result = left + 2
        self.state.regs.a = result
        self.state.regs.f = claripy.If(result == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)) | claripy.If((left & 0xf) + 2 > 0xf, claripy.BVV(0x10, 8), claripy.BVV(0, 8)) | claripy.If(claripy.UGT(claripy.ZeroExt(1, left) + 2, 0xff), claripy.BVV(1, 8), claripy.BVV(0, 8))
        self.state.regs.l = self.state.regs.a
        self.state.regs.a = claripy.BVV(8, 8)
        self.state.memory.store(self.state.regs.hl, self.state.regs.a)
        self.state.regs.l += 1
        self.state.memory.store(self.state.regs.hl, self.state.regs.a)
        self.jump(self.next_address)


class CheckAvailabilityHiddenBoundary(angr.SimProcedure):
    """Complete hidden-object CheckSpriteAvailability transition for this list."""
    def __init__(self, next_address: int) -> None:
        super().__init__(); self.next_address = next_address
    def run(self) -> None:  # type: ignore[override]
        offset = self.state.memory.load(OFFSET, 1)
        # IsObjectHidden first matches the configured toggle entry.
        self.state.regs.a = claripy.BVV(1, 8)
        self.state.regs.b = claripy.BVV(2, 8)
        self.state.regs.c = claripy.BVV(1, 8)
        self.state.regs.f = claripy.BVV(0x10, 8)
        self.state.regs.h = claripy.BVV(0xd5, 8)
        self.state.regs.l = claripy.BVV(0xa6, 8)
        self.state.memory.store(HIDDEN, claripy.BVV(1, 8))
        # The availability routine loads/ANDs the hidden flag, takes its
        # invisible branch, sets image index $ff, and SCF-returns.
        self.state.regs.h = claripy.BVV(0xc1, 8)
        self.state.regs.a = offset + 2
        self.state.regs.f = claripy.If(self.state.regs.a == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)) | claripy.If((offset & 0xf) + 2 > 0xf, claripy.BVV(0x10, 8), claripy.BVV(0, 8)) | claripy.ZeroExt(7, claripy.ZeroExt(1, offset + 2)[8])
        self.state.regs.l = self.state.regs.a
        self.state.memory.store(self.state.regs.hl, claripy.BVV(0xff, 8))
        self.state.regs.f = (self.state.regs.f & 0x40) | 1
        self.jump(self.next_address)


class ReturnCarry(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        assert self.state.solver.is_true((self.state.regs.f & 1) != 0)
        target = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp += 2
        self.jump(target)


def setup(state: angr.SimState, base: int, uninitialized: bool) -> None:
    for item in (*range(S1, S1 + 16), *range(S2, S2 + 16)):
        state.memory.store(base + item, claripy.BVV(0, 8))
    for item, value in ((OFFSET, 0), (MAP_SPRITE_MOVEMENT2, 0x55), (CUR_MOVEMENT2, 0),
                        (S1 + 1, 0 if uninitialized else 1), (S1 + 2, 0x13),
                        (S2 + 2, 0x27), (S2 + 3, 0x38), (HIDDEN, 0x55),
                        (TOGGLE_LIST, 0), (TOGGLE_LIST + 1, 0),
                        (TOGGLE_LIST + 2, 0xff), (TOGGLE_FLAGS, 1)):
        state.memory.store(base + item, claripy.BVV(value, 8))


def endpoint(state: angr.SimState, native: bool) -> E:
    base = NM if native else 0
    registers = native_registers(state, NS) if native else assembly_registers(state)
    watched = (*range(S1, S1 + 16), *range(S2, S2 + 16), MAP_SPRITE_MOVEMENT2,
               CUR_MOVEMENT2, OFFSET, HIDDEN, TOGGLE_LIST, TOGGLE_LIST + 1,
               TOGGLE_LIST + 2, TOGGLE_FLAGS)
    return E(**registers, state=claripy.Concat(*(state.memory.load(base + item, 1) for item in watched)), constraints=tuple(state.solver.constraints))


def assembly(values: dict[str, claripy.ast.BV], uninitialized: bool) -> list[E]:
    location = symbol_location(SYMBOLS, "UpdateNPCSprite")
    assert linked_bytes(ROM, location, len(BODY)) == BODY
    project = angr.Project(rom_window(ROM, location.bank), auto_load_libs=False, rebase_granularity=0x100,
                            main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0, "entry_point": location.address})
    q = location.address
    project.hook(q, LoadHighA(OFFSET, q + 2), length=2)
    project.hook(q + 2, SwapA(q + 4), length=2)
    project.hook(q + 4, DecA(q + 5), length=1)
    project.hook(q + 5, AddA("a", q + 6), length=1)
    project.hook(q + 6, Pair(0xd4e4, q + 9), length=3)
    project.hook(q + 9, AddA("l", q + 10), length=1)
    project.hook(q + 10, Reg("l", "a", q + 11), length=1)
    project.hook(q + 11, LoadAtHL(q + 12), length=1)
    project.hook(q + 12, StoreAbsoluteA(CUR_MOVEMENT2, q + 15), length=3)
    project.hook(q + 15, Imm("h", 0xc1, q + 17), length=2)
    project.hook(q + 17, LoadHighA(OFFSET, q + 19), length=2)
    project.hook(q + 19, Reg("l", "a", q + 20), length=1)
    project.hook(q + 20, IncL(q + 21), length=1)
    project.hook(q + 21, LoadAtHL(q + 22), length=1)
    project.hook(q + 22, AndA(q + 23), length=1)
    project.hook(q + 23, BranchZero(0x50ad, q + 26), length=3)
    project.hook(0x50ad, InitializeStatusBoundary(RET), length=16)
    project.hook(q + 26, CheckAvailabilityHiddenBoundary(q + 29), length=3)
    project.hook(q + 29, ReturnCarry(), length=1)
    state = project.factory.blank_state(addr=q)
    set_assembly_registers(state, values)
    setup(state, 0, uninitialized)
    state.regs.sp = claripy.BVV(STACK, 16)
    state.memory.store(STACK, claripy.BVV(RET, 16), endness="Iend_LE")
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RET, num_find=2)
    assert not manager.errored and manager.found
    return [endpoint(item, False) for item in manager.found]


def native(values: dict[str, claripy.ast.BV], uninitialized: bool) -> list[E]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_update_npc_sprite")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NS, NM)
    store_native_registers(state, NS, values)
    setup(state, NM, uninitialized)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and manager.deadended
    return [endpoint(item, True) for item in manager.deadended]


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(), reason="build artifacts missing")
def test_update_npc_sprite_uninitialized_slot_pathwise_equivalence() -> None:
    values = symbolic_registers("update_npc_sprite_uninitialized")
    assert_pathwise_equivalent(assembly(values, True), native(values, True), (*REGISTERS, "state"))


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(), reason="build artifacts missing")
def test_update_npc_sprite_hidden_slot_pathwise_equivalence() -> None:
    values = symbolic_registers("update_npc_sprite_hidden")
    assert_pathwise_equivalent(assembly(values, False), native(values, False), (*REGISTERS, "state"))
