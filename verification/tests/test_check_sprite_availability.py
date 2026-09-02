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
TILEMAP = 0xc3a0
LIST = 0xd5ce
FLAGS = 0xd5a6
WALK = 0xcfc5
Y = 0xd361
X = 0xd362
GRASS = 0xd535
TILE = 0xff93
OFFSET = 0xffda
HIDDEN = 0xffe5
BODY = bytes.fromhex(
    "3e12cd6d3ef0e5a7c22e5126c2f0dac6066f7efefe3822f0dac6046f46fa61d3"
    "b82807302dc608b838282c46fa62d3b82807301ec609b83819cd075216602aba"
    "30103aba300c01ecff092aba30047eba380c26c1f0dac6026f36ff37181c4ffac"
    "5cfa72015cd575124f0dac6076ffa35d5b93e0020023e8077a7c9"
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


class Jump(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.jump(self.next_address)


class Reg(angr.SimProcedure):
    def __init__(self, destination: str, source: str, next_address: int) -> None:
        super().__init__()
        self.destination = destination
        self.source = source
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.destination, getattr(self.state.regs, self.source))
        self.jump(self.next_address)


class Imm(angr.SimProcedure):
    def __init__(self, register: str, value: int, next_address: int) -> None:
        super().__init__()
        self.register = register
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.register, claripy.BVV(self.value, 8))
        self.jump(self.next_address)


class LoadA(angr.SimProcedure):
    def __init__(self, address: int, next_address: int) -> None:
        super().__init__()
        self.address = address
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self.address, 1)
        self.jump(self.next_address)


class LoadAtHL(angr.SimProcedure):
    def __init__(self, register: str, increment: bool, next_address: int) -> None:
        super().__init__()
        self.register = register
        self.increment = increment
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        hl = self.state.regs.hl
        setattr(self.state.regs, self.register, self.state.memory.load(hl, 1))
        if self.increment:
            self.state.regs.hl = hl + int(self.increment)
        self.jump(self.next_address)


class StoreAtHL(angr.SimProcedure):
    def __init__(self, value: int | None, next_address: int) -> None:
        super().__init__()
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        value = self.state.regs.a if self.value is None else claripy.BVV(self.value, 8)
        self.state.memory.store(self.state.regs.hl, value)
        self.jump(self.next_address)


class AddA(angr.SimProcedure):
    def __init__(self, value: int, next_address: int) -> None:
        super().__init__()
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        left = self.state.regs.a
        wide = claripy.ZeroExt(1, left) + self.value
        result = wide[7:0]
        self.state.regs.a = result
        self.state.regs.f = claripy.If(result == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        self.state.regs.f |= claripy.If((left & 0xf) + (self.value & 0xf) > 0xf, claripy.BVV(0x10, 8), claripy.BVV(0, 8))
        self.state.regs.f |= claripy.ZeroExt(7, wide[8])
        self.jump(self.next_address)


class Cp(angr.SimProcedure):
    def __init__(self, value: int | str, next_address: int) -> None:
        super().__init__()
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        left = self.state.regs.a
        right = getattr(self.state.regs, self.value) if isinstance(self.value, str) else claripy.BVV(self.value, 8)
        self.state.regs.f = claripy.BVV(0x02, 8)
        self.state.regs.f |= claripy.If(left == right, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        self.state.regs.f |= claripy.If((left & 0xf).ULT(right & 0xf), claripy.BVV(0x10, 8), claripy.BVV(0, 8))
        self.state.regs.f |= claripy.If(left.ULT(right), claripy.BVV(1, 8), claripy.BVV(0, 8))
        self.jump(self.next_address)


class AndA(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.f = claripy.BVV(0x10, 8) | claripy.If(
            self.state.regs.a == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)
        )
        self.jump(self.next_address)


class Branch(angr.SimProcedure):
    def __init__(self, taken: int, fallthrough: int, flag: int, when_set: bool) -> None:
        super().__init__()
        self.taken = taken
        self.fallthrough = fallthrough
        self.flag = flag
        self.when_set = when_set

    def run(self) -> None:  # type: ignore[override]
        condition = (self.state.regs.f & self.flag) != 0
        if not self.when_set:
            condition = ~condition
        taken = self.state.copy()
        fallthrough = self.state.copy()
        taken.solver.add(condition)
        fallthrough.solver.add(~condition)
        taken.regs.ip = claripy.BVV(self.taken, 16)
        fallthrough.regs.ip = claripy.BVV(self.fallthrough, 16)
        self.inhibit_autoret = True
        self.successors.add_successor(taken, self.taken, condition, "Ijk_Boring")
        self.successors.add_successor(fallthrough, self.fallthrough, ~condition, "Ijk_Boring")


class AddHLBC(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        left = self.state.regs.hl
        right = self.state.regs.bc
        wide = claripy.ZeroExt(1, left) + claripy.ZeroExt(1, right)
        self.state.regs.hl = wide[15:0]
        self.state.regs.f = (self.state.regs.f & 0x40) | claripy.If(
            (left & 0xfff) + (right & 0xfff) > 0xfff, claripy.BVV(0x10, 8), claripy.BVV(0, 8)
        ) | claripy.ZeroExt(7, wide[16])
        self.jump(self.next_address)


class Inc(angr.SimProcedure):
    def __init__(self, register: str, next_address: int) -> None:
        super().__init__()
        self.register = register
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        before = getattr(self.state.regs, self.register)
        result = before + 1
        setattr(self.state.regs, self.register, result)
        self.state.regs.f = (self.state.regs.f & 1) | claripy.If(result == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)) | claripy.If(
            (before & 0xf) == 0xf, claripy.BVV(0x10, 8), claripy.BVV(0, 8)
        )
        self.jump(self.next_address)


class Scf(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.f = (self.state.regs.f & 0x40) | 1
        self.jump(self.next_address)


class Return(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        sp = self.state.regs.sp
        target = self.state.memory.load(sp, 2, endness="Iend_LE")
        self.state.regs.sp = sp + 2
        self.jump(target)


class IsObjectHiddenBoundary(angr.SimProcedure):
    """Complete proven transition over the two fixed list configurations."""

    def __init__(self, hidden: bool, next_address: int) -> None:
        super().__init__()
        self.hidden = hidden
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        if self.hidden:
            self.state.regs.a = claripy.BVV(1, 8)
            self.state.regs.b = claripy.BVV(2, 8)
            self.state.regs.c = claripy.BVV(1, 8)
            self.state.regs.f = claripy.BVV(0x10, 8)
            self.state.regs.h = claripy.BVV(0xd5, 8)
            self.state.regs.l = claripy.BVV(0xa6, 8)
            self.state.memory.store(HIDDEN, claripy.BVV(1, 8))
        else:
            self.state.regs.a = claripy.BVV(0, 8)
            self.state.regs.b = claripy.BVV(0, 8)
            self.state.regs.f = claripy.BVV(0x40, 8)
            self.state.regs.h = claripy.BVV(0xd5, 8)
            self.state.regs.l = claripy.BVV(0xcf, 8)
            self.state.memory.store(HIDDEN, claripy.BVV(0, 8))
        self.jump(self.next_address)


class GetTileBoundary(angr.SimProcedure):
    """Complete proven GetTileSpriteStandsOn transition against real memory."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def _add(self, value: claripy.ast.BV, right: int) -> claripy.ast.BV:
        wide = claripy.ZeroExt(1, value) + right
        result = wide[7:0]
        self.state.regs.f = claripy.If(result == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)) | claripy.If(
            (value & 0xf) + (right & 0xf) > 0xf, claripy.BVV(0x10, 8), claripy.BVV(0, 8)
        ) | claripy.ZeroExt(7, wide[8])
        return result

    def _add_hl(self, right: claripy.ast.BV) -> None:
        left = self.state.regs.hl
        wide = claripy.ZeroExt(1, left) + claripy.ZeroExt(1, right)
        self.state.regs.hl = wide[15:0]
        self.state.regs.f = (self.state.regs.f & 0x40) | claripy.If(
            (left & 0xfff) + (right & 0xfff) > 0xfff, claripy.BVV(0x10, 8), claripy.BVV(0, 8)
        ) | claripy.ZeroExt(7, wide[16])

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = claripy.BVV(0xc1, 8)
        self.state.regs.a = self._add(self.state.memory.load(OFFSET, 1), 4)
        self.state.regs.l = self.state.regs.a
        self.state.regs.a = self.state.memory.load(self.state.regs.hl, 1)
        self.state.regs.hl += 1
        self.state.regs.a = self._add(self.state.regs.a, 4) & 0xf0
        self.state.regs.f = claripy.BVV(0x10, 8) | claripy.If(self.state.regs.a == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        carry = self.state.regs.a & 1
        self.state.regs.a = claripy.LShR(self.state.regs.a, 1)
        self.state.regs.f = claripy.If(self.state.regs.a == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)) | carry
        self.state.regs.c = self.state.regs.a
        self.state.regs.b = claripy.BVV(0, 8)
        self.state.regs.l += 1
        self.state.regs.a = self.state.memory.load(self.state.regs.hl, 1)
        for _ in range(3):
            carry = self.state.regs.a & 1
            self.state.regs.a = claripy.LShR(self.state.regs.a, 1)
            self.state.regs.f = claripy.If(self.state.regs.a == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)) | carry
        self.state.regs.a = self._add(self.state.regs.a, 20)
        self.state.regs.d = claripy.BVV(0, 8)
        self.state.regs.e = self.state.regs.a
        self.state.regs.hl = claripy.BVV(TILEMAP, 16)
        for _ in range(5):
            self._add_hl(self.state.regs.bc)
        self._add_hl(self.state.regs.de)
        self.jump(self.next_address)


class UpdateImageBoundary(angr.SimProcedure):
    """Complete proven UpdateSpriteImage transition against real memory."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def _add(self, value: claripy.ast.BV, right: claripy.ast.BV | int) -> claripy.ast.BV:
        wide = claripy.ZeroExt(1, value) + (claripy.ZeroExt(1, right) if isinstance(right, claripy.ast.BV) else right)
        result = wide[7:0]
        self.state.regs.f = claripy.If(result == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)) | claripy.If(
            (value & 0xf) + (right & 0xf) > 0xf, claripy.BVV(0x10, 8), claripy.BVV(0, 8)
        ) | claripy.ZeroExt(7, wide[8])
        return result

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = claripy.BVV(0xc1, 8)
        self.state.regs.a = self._add(self.state.memory.load(OFFSET, 1), 8)
        self.state.regs.l = self.state.regs.a
        self.state.regs.a = self.state.memory.load(self.state.regs.hl, 1)
        self.state.regs.hl += 1
        self.state.regs.b = self.state.regs.a
        self.state.regs.a = self.state.memory.load(self.state.regs.hl, 1)
        self.state.regs.a = self._add(self.state.regs.a, self.state.regs.b)
        self.state.regs.b = self.state.regs.a
        self.state.regs.a = self.state.memory.load(TILE, 1)
        self.state.regs.a = self._add(self.state.regs.a, self.state.regs.b)
        self.state.regs.b = self.state.regs.a
        self.state.regs.a = self._add(self.state.memory.load(OFFSET, 1), 2)
        self.state.regs.l = self.state.regs.a
        self.state.memory.store(self.state.regs.hl, self.state.regs.b)
        self.jump(self.next_address)


def setup(state: angr.SimState, base: int, *, hidden: bool, movement: int, map_y: int,
          tiles: tuple[int, int, int, int], walk: int) -> None:
    for address in (*range(S1, S1 + 10), *range(S2, S2 + 8)):
        state.memory.store(base + address, claripy.BVV(0, 8))
    for address, value in ((OFFSET, 0), (TILE, 0x20), (WALK, walk), (Y, 0), (X, 0),
                           (GRASS, 0x33), (S1 + 2, 0x55), (S1 + 4, 0), (S1 + 5, 0),
                           (S1 + 8, 2), (S1 + 9, 4), (S2 + 4, map_y), (S2 + 5, 0),
                           (S2 + 6, movement), (S2 + 7, 0), (LIST, 0 if hidden else 0xff),
                           (LIST + 1, 0), (LIST + 2, 0xff), (FLAGS, 1 if hidden else 0),
                           (HIDDEN, 0x55)):
        state.memory.store(base + address, claripy.BVV(value, 8))
    for address, value in zip((TILEMAP + 20, TILEMAP + 21, TILEMAP, TILEMAP + 1), tiles):
        state.memory.store(base + address, claripy.BVV(value, 8))


def endpoint(state: angr.SimState, native: bool) -> E:
    base = NM if native else 0
    registers = native_registers(state, NS) if native else assembly_registers(state)
    watched = (*range(S1, S1 + 10), *range(S2, S2 + 8), TILEMAP, TILEMAP + 1,
               TILEMAP + 20, TILEMAP + 21, LIST, LIST + 1, LIST + 2, FLAGS,
               WALK, Y, X, GRASS, TILE, OFFSET, HIDDEN)
    return E(**registers, state=claripy.Concat(*(state.memory.load(base + x, 1) for x in watched)), constraints=tuple(state.solver.constraints))


def assembly(values: dict[str, claripy.ast.BV], **case: object) -> list[E]:
    location = symbol_location(SYMBOLS, "CheckSpriteAvailability")
    assert linked_bytes(ROM, location, len(BODY)) == BODY
    project = angr.Project(rom_window(ROM, location.bank), auto_load_libs=False,
                            rebase_granularity=0x100,
                            main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                                       "base_addr": 0, "entry_point": location.address})
    q = location.address
    hidden = bool(case["hidden"])
    project.hook(q, IsObjectHiddenBoundary(hidden, q + 5), length=5)
    project.hook(q + 5, LoadA(HIDDEN, q + 7), length=2)
    project.hook(q + 7, AndA(q + 8), length=1)
    project.hook(q + 8, Branch(q + 82, q + 11, 0x40, False), length=3)
    project.hook(q + 11, Imm("h", 0xc2, q + 13), length=2)
    project.hook(q + 13, LoadA(OFFSET, q + 15), length=2)
    project.hook(q + 15, AddA(6, q + 17), length=2)
    project.hook(q + 17, Reg("l", "a", q + 18), length=1)
    project.hook(q + 18, LoadAtHL("a", False, q + 19), length=1)
    project.hook(q + 19, Cp(0xfe, q + 21), length=2)
    project.hook(q + 21, Branch(q + 57, q + 23, 1, True), length=2)
    project.hook(q + 23, LoadA(OFFSET, q + 25), length=2)
    project.hook(q + 25, AddA(4, q + 27), length=2)
    project.hook(q + 27, Reg("l", "a", q + 28), length=1)
    project.hook(q + 28, LoadAtHL("b", False, q + 29), length=1)
    project.hook(q + 29, LoadA(Y, q + 32), length=3)
    project.hook(q + 32, Cp("b", q + 33), length=1)
    project.hook(q + 33, Branch(q + 42, q + 35, 0x40, True), length=2)
    project.hook(q + 35, Branch(q + 82, q + 37, 1, False), length=2)
    project.hook(q + 37, AddA(8, q + 39), length=2)
    project.hook(q + 39, Cp("b", q + 40), length=1)
    project.hook(q + 40, Branch(q + 82, q + 42, 1, True), length=2)
    project.hook(q + 42, Inc("l", q + 43), length=1)
    project.hook(q + 43, LoadAtHL("b", False, q + 44), length=1)
    project.hook(q + 44, LoadA(X, q + 47), length=3)
    project.hook(q + 47, Cp("b", q + 48), length=1)
    project.hook(q + 48, Branch(q + 57, q + 50, 0x40, True), length=2)
    project.hook(q + 50, Branch(q + 82, q + 52, 1, False), length=2)
    project.hook(q + 52, AddA(9, q + 54), length=2)
    project.hook(q + 54, Cp("b", q + 55), length=1)
    project.hook(q + 55, Branch(q + 82, q + 57, 1, True), length=2)
    project.hook(q + 57, GetTileBoundary(q + 60), length=3)
    project.hook(q + 60, Imm("d", 0x60, q + 62), length=2)
    project.hook(q + 62, LoadAtHL("a", True, q + 63), length=1)
    project.hook(q + 63, Cp("d", q + 64), length=1)
    project.hook(q + 64, Branch(q + 82, q + 66, 1, False), length=2)
    project.hook(q + 66, LoadAtHL("a", -1, q + 67), length=1)
    project.hook(q + 67, Cp("d", q + 68), length=1)
    project.hook(q + 68, Branch(q + 82, q + 70, 1, False), length=2)
    project.hook(q + 70, Imm("b", 0xff, q + 71), length=3)
    project.hook(q + 71, Imm("c", 0xec, q + 73), length=0)
    project.hook(q + 73, AddHLBC(q + 74), length=1)
    project.hook(q + 74, LoadAtHL("a", True, q + 75), length=1)
    project.hook(q + 75, Cp("d", q + 76), length=1)
    project.hook(q + 76, Branch(q + 82, q + 78, 1, False), length=2)
    project.hook(q + 78, LoadAtHL("a", False, q + 79), length=1)
    project.hook(q + 79, Cp("d", q + 80), length=1)
    project.hook(q + 80, Branch(q + 94, q + 82, 1, True), length=2)
    project.hook(q + 82, Imm("h", 0xc1, q + 84), length=2)
    project.hook(q + 84, LoadA(OFFSET, q + 86), length=2)
    project.hook(q + 86, AddA(2, q + 88), length=2)
    project.hook(q + 88, Reg("l", "a", q + 89), length=1)
    project.hook(q + 89, StoreAtHL(0xff, q + 91), length=2)
    project.hook(q + 91, Scf(q + 92), length=1)
    project.hook(q + 92, Jump(q + 122), length=2)
    project.hook(q + 94, Reg("c", "a", q + 95), length=1)
    project.hook(q + 95, LoadA(WALK, q + 98), length=3)
    project.hook(q + 98, AndA(q + 99), length=1)
    project.hook(q + 99, Branch(q + 122, q + 101, 0x40, False), length=2)
    project.hook(q + 101, UpdateImageBoundary(q + 104), length=3)
    project.hook(q + 104, Inc("h", q + 105), length=1)
    project.hook(q + 105, LoadA(OFFSET, q + 107), length=2)
    project.hook(q + 107, AddA(7, q + 109), length=2)
    project.hook(q + 109, Reg("l", "a", q + 110), length=1)
    project.hook(q + 110, LoadA(GRASS, q + 113), length=3)
    project.hook(q + 113, Cp("c", q + 114), length=1)
    project.hook(q + 114, Imm("a", 0, q + 116), length=2)
    project.hook(q + 116, Branch(q + 118, q + 117, 0x40, False), length=2)
    project.hook(q + 117, Imm("a", 0x80, q + 119), length=2)
    project.hook(q + 119, StoreAtHL(None, q + 120), length=1)
    project.hook(q + 120, AndA(q + 121), length=1)
    project.hook(q + 121, Return(), length=1)
    project.hook(q + 122, Return(), length=1)
    state = project.factory.blank_state(addr=q)
    set_assembly_registers(state, values)
    setup(state, 0, **case)  # type: ignore[arg-type]
    state.regs.sp = claripy.BVV(STACK, 16)
    state.memory.store(STACK, claripy.BVV(RET, 16), endness="Iend_LE")
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RET, num_find=10)
    assert not manager.errored and manager.found
    return [endpoint(x, False) for x in manager.found]


def native(values: dict[str, claripy.ast.BV], **case: object) -> list[E]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_check_sprite_availability")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NS, NM)
    store_native_registers(state, NS, values)
    setup(state, NM, **case)  # type: ignore[arg-type]
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and manager.deadended
    return [endpoint(x, True) for x in manager.deadended]


CASES = [
    dict(hidden=True, movement=0, map_y=0, tiles=(0x10, 0x11, 0x12, 0x33), walk=0),
    dict(hidden=False, movement=0xfe, map_y=10, tiles=(0x10, 0x11, 0x12, 0x33), walk=0),
    dict(hidden=False, movement=0, map_y=0, tiles=(0x60, 0x11, 0x12, 0x33), walk=0),
    dict(hidden=False, movement=0, map_y=0, tiles=(0x10, 0x11, 0x12, 0x33), walk=0),
    dict(hidden=False, movement=0, map_y=0, tiles=(0x10, 0x11, 0x12, 0x33), walk=1),
]


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(), reason="build artifacts missing")
@pytest.mark.parametrize("case", CASES)
def test_check_sprite_availability_pathwise_equivalence(case: dict[str, object]) -> None:
    values = symbolic_registers("sprite_availability")
    assert_pathwise_equivalent(assembly(values, **case), native(values, **case), (*REGISTERS, "state"))
