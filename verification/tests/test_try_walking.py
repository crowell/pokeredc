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
    Sm83AddImmediate, Sm83AddRegister, Sm83LoadAAtHlIncrement,
    Sm83LoadAHighImmediate, Sm83Scf, Sm83StoreAAtHlIncrement,
)

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
OFFSET = 0xffda
TILE = 0xff93
RANDOM_ADD = 0xffd3
RANDOM_SUB = 0xffd4
DIV = 0xff04
COLLISION = 0xd530
TILE_POINTER = 0x0710
COLLISION_POINTER = 0x0720
BODY = bytes.fromhex("e526c1f0dac6096f71f0dac6036f722c2c73e1d54ecd6e51d1d826c2f0dac6046f7e82227e8377f0da6f3610252c3603c357")


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


class Reg(angr.SimProcedure):
    def __init__(self, destination: str, source: str, next_address: int) -> None:
        super().__init__(); self.destination = destination; self.source = source; self.next_address = next_address
    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.destination, getattr(self.state.regs, self.source)); self.jump(self.next_address)


class Imm(angr.SimProcedure):
    def __init__(self, register: str, value: int, next_address: int) -> None:
        super().__init__(); self.register = register; self.value = value; self.next_address = next_address
    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.register, claripy.BVV(self.value, 8)); self.jump(self.next_address)


class LoadAtHL(angr.SimProcedure):
    def __init__(self, register: str, next_address: int) -> None:
        super().__init__(); self.register = register; self.next_address = next_address
    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.register, self.state.memory.load(self.state.regs.hl, 1)); self.jump(self.next_address)


class StoreAtHL(angr.SimProcedure):
    def __init__(self, value: int | None, next_address: int) -> None:
        super().__init__(); self.value = value; self.next_address = next_address
    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(self.state.regs.hl, self.state.regs.a if self.value is None else claripy.BVV(self.value, 8)); self.jump(self.next_address)


class StoreRegisterAtHL(angr.SimProcedure):
    def __init__(self, register: str, next_address: int) -> None:
        super().__init__(); self.register = register; self.next_address = next_address
    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(self.state.regs.hl, getattr(self.state.regs, self.register)); self.jump(self.next_address)


class Inc(angr.SimProcedure):
    def __init__(self, register: str, next_address: int) -> None:
        super().__init__(); self.register = register; self.next_address = next_address
    def run(self) -> None:  # type: ignore[override]
        before = getattr(self.state.regs, self.register); result = before + 1
        setattr(self.state.regs, self.register, result)
        self.state.regs.f = (self.state.regs.f & 1) | claripy.If(result == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)) | claripy.If((before & 0xf) == 0xf, claripy.BVV(0x10, 8), claripy.BVV(0, 8))
        self.jump(self.next_address)


class DecH(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__(); self.next_address = next_address
    def run(self) -> None:  # type: ignore[override]
        before = self.state.regs.h; self.state.regs.h = before - 1
        self.state.regs.f = (self.state.regs.f & 1) | 2 | claripy.If(self.state.regs.h == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)) | claripy.If((before & 0xf) == 0, claripy.BVV(0x10, 8), claripy.BVV(0, 8))
        self.jump(self.next_address)


class Push(angr.SimProcedure):
    def __init__(self, pair: str, next_address: int) -> None:
        super().__init__(); self.pair = pair; self.next_address = next_address
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.sp -= 2; self.state.memory.store(self.state.regs.sp, getattr(self.state.regs, self.pair), endness="Iend_LE"); self.jump(self.next_address)


class Pop(angr.SimProcedure):
    def __init__(self, pair: str, next_address: int) -> None:
        super().__init__(); self.pair = pair; self.next_address = next_address
    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.pair, self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")); self.state.regs.sp += 2; self.jump(self.next_address)


class ReturnCarry(angr.SimProcedure):
    def __init__(self, fallthrough: int) -> None:
        super().__init__(); self.fallthrough = fallthrough
    def run(self) -> None:  # type: ignore[override]
        carry = (self.state.regs.f & 1) != 0
        returned = self.state.copy(); continued = self.state.copy()
        returned.solver.add(carry); continued.solver.add(~carry)
        returned.regs.ip = returned.memory.load(returned.regs.sp, 2, endness="Iend_LE"); returned.regs.sp += 2
        continued.regs.ip = claripy.BVV(self.fallthrough, 16)
        self.inhibit_autoret = True
        self.successors.add_successor(returned, returned.regs.ip, carry, "Ijk_Ret")
        self.successors.add_successor(continued, self.fallthrough, ~carry, "Ijk_Boring")


class CanWalkBoundary(angr.SimProcedure):
    """Complete CanWalkOntoTile transitions for its scripted and sentinel domains."""
    def __init__(self, failure: bool, next_address: int) -> None:
        super().__init__(); self.failure = failure; self.next_address = next_address
    def run(self) -> None:  # type: ignore[override]
        offset = self.state.memory.load(OFFSET, 1)
        self.state.regs.h = claripy.BVV(0xc2, 8)
        self.state.regs.a = offset + 6
        self.state.regs.l = self.state.regs.a
        movement = self.state.memory.load(self.state.regs.hl, 1)
        if not self.failure:
            self.state.regs.a = movement
            self.state.regs.f = claripy.BVV(0x10, 8) | claripy.If(movement == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
            self.jump(self.next_address); return
        self.state.regs.h = claripy.BVV(0xc1, 8)
        self.state.regs.a = offset + 1
        self.state.regs.l = self.state.regs.a
        self.state.memory.store(self.state.regs.hl, claripy.BVV(2, 8))
        self.state.regs.l += 2
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x40, 8)
        self.state.memory.store(self.state.regs.hl, self.state.regs.a)
        # `ld [hli], a` advances from state1+3 to +4; the following
        # `inc l` selects state1+5 (the stored Y step).
        self.state.regs.l += 2
        self.state.memory.store(self.state.regs.hl, self.state.regs.a)
        self.state.regs.h = claripy.BVV(0xc2, 8)
        self.state.regs.a = offset + 8
        self.state.regs.l = self.state.regs.a
        add0 = self.state.memory.load(RANDOM_ADD, 1)
        sub0 = self.state.memory.load(RANDOM_SUB, 1)
        div = self.state.memory.load(DIV, 1)
        wide = claripy.ZeroExt(1, add0) + claripy.ZeroExt(1, div)
        add = wide[7:0]
        sub = (claripy.ZeroExt(1, sub0) - claripy.ZeroExt(1, div) - claripy.ZeroExt(8, wide[8]))[7:0]
        self.state.memory.store(RANDOM_ADD, add)
        self.state.memory.store(RANDOM_SUB, sub)
        self.state.regs.a = add & 0x7f
        self.state.regs.f = claripy.If(self.state.regs.a == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)) | claripy.BVV(1, 8)
        self.state.memory.store(self.state.regs.hl, self.state.regs.a)
        self.jump(self.next_address)


class UpdateImageBoundary(angr.SimProcedure):
    """Complete proven UpdateSpriteImage transition over the active slot."""
    def __init__(self, next_address: int) -> None:
        super().__init__(); self.next_address = next_address
    def _add(self, value: claripy.ast.BV, right: claripy.ast.BV | int) -> claripy.ast.BV:
        wide = claripy.ZeroExt(1, value) + (claripy.ZeroExt(1, right) if isinstance(right, claripy.ast.BV) else right)
        result = wide[7:0]
        self.state.regs.f = claripy.If(result == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)) | claripy.If((value & 0xf) + (right & 0xf) > 0xf, claripy.BVV(0x10, 8), claripy.BVV(0, 8)) | claripy.ZeroExt(7, wide[8])
        return result
    def run(self) -> None:  # type: ignore[override]
        offset = self.state.memory.load(OFFSET, 1)
        self.state.regs.h = claripy.BVV(0xc1, 8)
        self.state.regs.a = self._add(offset, 8); self.state.regs.l = self.state.regs.a
        self.state.regs.a = self.state.memory.load(self.state.regs.hl, 1); self.state.regs.hl += 1
        self.state.regs.b = self.state.regs.a; self.state.regs.a = self.state.memory.load(self.state.regs.hl, 1)
        self.state.regs.a = self._add(self.state.regs.a, self.state.regs.b); self.state.regs.b = self.state.regs.a
        self.state.regs.a = self.state.memory.load(TILE, 1); self.state.regs.a = self._add(self.state.regs.a, self.state.regs.b); self.state.regs.b = self.state.regs.a
        self.state.regs.a = self._add(offset, 2); self.state.regs.l = self.state.regs.a
        self.state.memory.store(self.state.regs.hl, self.state.regs.b)
        self.jump(self.next_address)


def setup(state: angr.SimState, base: int, failure: bool, movement: claripy.ast.BV | int,
          random_add: claripy.ast.BV | None = None, random_sub: claripy.ast.BV | None = None,
          div: claripy.ast.BV | None = None) -> None:
    for address in (*range(S1, S1 + 16), *range(S2, S2 + 16)):
        state.memory.store(base + address, claripy.BVV(0, 8))
    for address, value in ((OFFSET, 0), (TILE, 0x20), (S1 + 8, 2), (S1 + 9, 4),
                           (S2 + 4, 7), (S2 + 5, 9), (S2 + 6, movement),
                           (TILE_POINTER, 0x33), (COLLISION, COLLISION_POINTER & 0xff),
                           (COLLISION + 1, COLLISION_POINTER >> 8),
                           (COLLISION_POINTER, 0xff)):
        state.memory.store(base + address, value if isinstance(value, claripy.ast.BV) else claripy.BVV(value, 8))
    for address, value in ((RANDOM_ADD, random_add), (RANDOM_SUB, random_sub), (DIV, div)):
        state.memory.store(base + address, claripy.BVV(0, 8) if value is None else value)
    if not failure:
        state.solver.add(movement.ULT(claripy.BVV(0xfe, 8)))  # type: ignore[union-attr]


def endpoint(state: angr.SimState, native: bool) -> E:
    base = NM if native else 0
    registers = native_registers(state, NS) if native else assembly_registers(state)
    watched = (*range(S1, S1 + 16), *range(S2, S2 + 16), TILE_POINTER,
               COLLISION, COLLISION + 1, COLLISION_POINTER, RANDOM_ADD, RANDOM_SUB, DIV, TILE, OFFSET)
    return E(**registers, state=claripy.Concat(*(state.memory.load(base + x, 1) for x in watched)), constraints=tuple(state.solver.constraints))


def assembly(values: dict[str, claripy.ast.BV], failure: bool, movement: claripy.ast.BV | int,
             random_add: claripy.ast.BV | None = None, random_sub: claripy.ast.BV | None = None,
             div: claripy.ast.BV | None = None) -> list[E]:
    location = symbol_location(SYMBOLS, "TryWalking")
    assert linked_bytes(ROM, location, len(BODY)) == BODY
    project = angr.Project(rom_window(ROM, location.bank), auto_load_libs=False, rebase_granularity=0x100,
                            main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0, "entry_point": location.address})
    q = location.address
    project.hook(q, Push("hl", q + 1), length=1)
    project.hook(q + 1, Imm("h", 0xc1, q + 3), length=2)
    project.hook(q + 3, Sm83LoadAHighImmediate(0xda, q + 5), length=2)
    project.hook(q + 5, Sm83AddImmediate(9, q + 7), length=2)
    project.hook(q + 7, Reg("l", "a", q + 8), length=1)
    project.hook(q + 8, StoreRegisterAtHL("c", q + 9), length=1)
    project.hook(q + 9, Sm83LoadAHighImmediate(0xda, q + 11), length=2)
    project.hook(q + 11, Sm83AddImmediate(3, q + 13), length=2)
    project.hook(q + 13, Reg("l", "a", q + 14), length=1)
    project.hook(q + 14, StoreRegisterAtHL("d", q + 15), length=1)
    project.hook(q + 15, Inc("l", q + 16), length=1)
    project.hook(q + 16, Inc("l", q + 17), length=1)
    project.hook(q + 17, StoreRegisterAtHL("e", q + 18), length=1)
    project.hook(q + 18, Pop("hl", q + 19), length=1)
    project.hook(q + 19, Push("de", q + 20), length=1)
    project.hook(q + 20, LoadAtHL("c", q + 21), length=1)
    project.hook(q + 21, CanWalkBoundary(failure, q + 24), length=3)
    project.hook(q + 24, Pop("de", q + 25), length=1)
    project.hook(q + 25, ReturnCarry(q + 26), length=1)
    project.hook(q + 26, Imm("h", 0xc2, q + 28), length=2)
    project.hook(q + 28, Sm83LoadAHighImmediate(0xda, q + 30), length=2)
    project.hook(q + 30, Sm83AddImmediate(4, q + 32), length=2)
    project.hook(q + 32, Reg("l", "a", q + 33), length=1)
    project.hook(q + 33, LoadAtHL("a", q + 34), length=1)
    project.hook(q + 34, Sm83AddRegister("d", q + 35), length=1)
    project.hook(q + 35, Sm83StoreAAtHlIncrement(q + 36), length=1)
    project.hook(q + 36, LoadAtHL("a", q + 37), length=1)
    project.hook(q + 37, Sm83AddRegister("e", q + 38), length=1)
    project.hook(q + 38, StoreAtHL(None, q + 39), length=1)
    project.hook(q + 39, Sm83LoadAHighImmediate(0xda, q + 41), length=2)
    project.hook(q + 41, Reg("l", "a", q + 42), length=1)
    project.hook(q + 42, StoreAtHL(0x10, q + 44), length=2)
    project.hook(q + 44, DecH(q + 45), length=1)
    project.hook(q + 45, Inc("l", q + 46), length=1)
    project.hook(q + 46, StoreAtHL(3, q + 48), length=2)
    project.hook(q + 48, UpdateImageBoundary(RET), length=3)
    state = project.factory.blank_state(addr=q)
    set_assembly_registers(state, values)
    setup(state, 0, failure, movement, random_add, random_sub, div)
    state.regs.sp = claripy.BVV(STACK, 16)
    state.memory.store(STACK, claripy.BVV(RET, 16), endness="Iend_LE")
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RET, num_find=4)
    assert not manager.errored and manager.found
    return [endpoint(x, False) for x in manager.found]


def native(values: dict[str, claripy.ast.BV], failure: bool, movement: claripy.ast.BV | int,
           random_add: claripy.ast.BV | None = None, random_sub: claripy.ast.BV | None = None,
           div: claripy.ast.BV | None = None) -> list[E]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_try_walking")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NS, NM)
    store_native_registers(state, NS, values)
    setup(state, NM, failure, movement, random_add, random_sub, div)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and manager.deadended
    return [endpoint(x, True) for x in manager.deadended]


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(), reason="build artifacts missing")
def test_try_walking_scripted_success_pathwise_equivalence() -> None:
    values = symbolic_registers("try_walking_success")
    values["h"] = claripy.BVV(TILE_POINTER >> 8, 8)
    values["l"] = claripy.BVV(TILE_POINTER & 0xff, 8)
    movement = claripy.BVS("try_walking_success_movement", 8)
    assert_pathwise_equivalent(assembly(values, False, movement), native(values, False, movement), (*REGISTERS, "state"))


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(), reason="build artifacts missing")
def test_try_walking_collision_failure_pathwise_equivalence() -> None:
    values = symbolic_registers("try_walking_failure")
    values["h"] = claripy.BVV(TILE_POINTER >> 8, 8)
    values["l"] = claripy.BVV(TILE_POINTER & 0xff, 8)
    random_add = claripy.BVS("try_walking_failure_random_add", 8)
    random_sub = claripy.BVS("try_walking_failure_random_sub", 8)
    div = claripy.BVS("try_walking_failure_div", 8)
    assert_pathwise_equivalent(assembly(values, True, 0xff, random_add, random_sub, div), native(values, True, 0xff, random_add, random_sub, div), (*REGISTERS, "state"))
