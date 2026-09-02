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
    Sm83AddImmediate, Sm83AddRegister, Sm83AndImmediate, Sm83BitRegister,
    Sm83CpImmediate, Sm83CpRegister, Sm83IncRegister, Sm83SubImmediate,
    Sm83LoadAAtHlIncrement, Sm83LoadAHighImmediate, Sm83LoadAImmediate,
    Sm83Scf, Sm83StoreAAtHlIncrement, Sm83XorA,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xd000
RETURN = 0xffff
H_CURRENT_SPRITE_OFFSET = 0xffda
SPRITE_DATA1 = 0xc100
SPRITE_DATA2 = 0xc200


@dataclass(frozen=True)
class Endpoint:
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


class LoadRegister(angr.SimProcedure):
    def __init__(self, destination: str, source: str, next_address: int) -> None:
        super().__init__()
        self.destination = destination
        self.source = source
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.destination, getattr(self.state.regs, self.source))
        self.jump(self.next_address)


class LoadAtHL(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self.state.regs.hl, 1)
        self.jump(self.next_address)


class LoadHImmediate(angr.SimProcedure):
    def __init__(self, value: int, next_address: int) -> None:
        super().__init__()
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = claripy.BVV(self.value, 8)
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


class BranchCarryClear(angr.SimProcedure):
    def __init__(self, taken: int, fallthrough: int) -> None:
        super().__init__()
        self.taken = taken
        self.fallthrough = fallthrough

    def run(self) -> None:  # type: ignore[override]
        carry = (self.state.regs.f & 1) != 0
        taken = self.state.copy()
        fallthrough = self.state.copy()
        taken.solver.add(~carry)
        fallthrough.solver.add(carry)
        taken.regs.ip = claripy.BVV(self.taken, 16)
        fallthrough.regs.ip = claripy.BVV(self.fallthrough, 16)
        self.inhibit_autoret = True
        self.successors.add_successor(taken, self.taken, ~carry, "Ijk_Boring")
        self.successors.add_successor(fallthrough, self.fallthrough, carry, "Ijk_Boring")


class BranchFlag(angr.SimProcedure):
    def __init__(self, taken: int, fallthrough: int, flag: int,
                 taken_when_set: bool) -> None:
        super().__init__()
        self.taken = taken
        self.fallthrough = fallthrough
        self.flag = flag
        self.taken_when_set = taken_when_set

    def run(self) -> None:  # type: ignore[override]
        condition = ((self.state.regs.f >> self.flag) & 1) != 0
        if not self.taken_when_set:
            condition = ~condition
        taken = self.state.copy()
        fallthrough = self.state.copy()
        taken.solver.add(condition)
        fallthrough.solver.add(~condition)
        taken.regs.ip = claripy.BVV(self.taken, 16)
        fallthrough.regs.ip = claripy.BVV(self.fallthrough, 16)
        self.inhibit_autoret = True
        self.successors.add_successor(taken, self.taken, condition, "Ijk_Boring")
        self.successors.add_successor(fallthrough, self.fallthrough, ~condition,
                                      "Ijk_Boring")


class StoreImmediateAtHL(angr.SimProcedure):
    def __init__(self, value: int, next_address: int) -> None:
        super().__init__()
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(self.state.regs.hl, claripy.BVV(self.value, 8))
        self.jump(self.next_address)


class StoreAtHL(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(self.state.regs.hl, self.state.regs.a)
        self.jump(self.next_address)


class IncH(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h += 1
        self.jump(self.next_address)


class RandomBoundary(angr.SimProcedure):
    """Complete proven Random transition at the CanWalkOntoTile call seam."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        div = self.state.memory.load(0xff04, 1)
        random_add = self.state.memory.load(0xffd3, 1)
        random_sub = self.state.memory.load(0xffd4, 1)
        carry = self.state.regs.f[0:0]
        add_wide = (claripy.ZeroExt(1, random_add) + claripy.ZeroExt(1, div)
                    + claripy.ZeroExt(8, carry))
        add = add_wide[7:0]
        add_carry = add_wide[8]
        borrow = claripy.ZeroExt(1, div) + claripy.ZeroExt(8, add_carry)
        sub = (claripy.ZeroExt(1, random_sub) - borrow)[7:0]
        flags = claripy.BVV(0x02, 8)
        flags |= claripy.If(sub == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        flags |= claripy.If(
            claripy.ZeroExt(1, random_sub[3:0]).ULT(
                claripy.ZeroExt(1, div[3:0]) + claripy.ZeroExt(4, add_carry)
            ), claripy.BVV(0x10, 8), claripy.BVV(0, 8)
        )
        flags |= claripy.If(claripy.ZeroExt(1, random_sub).ULT(borrow),
                            claripy.BVV(1, 8), claripy.BVV(0, 8))
        self.state.memory.store(0xffd3, add)
        self.state.memory.store(0xffd4, sub)
        self.state.regs.a = add
        self.state.regs.f = flags
        self.jump(self.next_address)


class PushPair(angr.SimProcedure):
    def __init__(self, pair: str, next_address: int) -> None:
        super().__init__()
        self.pair = pair
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        value = getattr(self.state.regs, self.pair)
        sp = self.state.regs.sp - 2
        self.state.memory.store(sp, value, endness="Iend_LE")
        self.state.regs.sp = sp
        self.jump(self.next_address)


class Call(angr.SimProcedure):
    def __init__(self, target: int, return_address: int) -> None:
        super().__init__()
        self.target = target
        self.return_address = return_address

    def run(self) -> None:  # type: ignore[override]
        sp = self.state.regs.sp - 2
        self.state.memory.store(sp, claripy.BVV(self.return_address, 16),
                                endness="Iend_LE")
        self.state.regs.sp = sp
        self.jump(self.target)


class ReturnIfZero(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        assert self.state.solver.is_true((self.state.regs.f & 0x40) != 0)
        target = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp += 2
        self.jump(target)


class PopPair(angr.SimProcedure):
    def __init__(self, pair: str, next_address: int) -> None:
        super().__init__()
        self.pair = pair
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.pair,
                self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE"))
        self.state.regs.sp += 2
        self.jump(self.next_address)


class Jump(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.jump(self.next_address)


class StoreAtHLDecrement(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(self.state.regs.hl, self.state.regs.a)
        self.state.regs.hl -= 1
        self.jump(self.next_address)


def _endpoint(state: angr.SimState, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    registers = native_registers(state, NATIVE_STATE) if native else assembly_registers(state)
    return Endpoint(
        **registers,
        state=claripy.Concat(*(
            state.memory.load(base + SPRITE_DATA1 + 0x20 + offset, 1)
            for offset in range(16)
        ), *(state.memory.load(base + SPRITE_DATA2 + 0x20 + offset, 1)
             for offset in range(16)),
            *(state.memory.load(base + address, 1) for address in (0xff04, 0xffd3, 0xffd4))),
        constraints=tuple(state.solver.constraints),
    )


def _setup(state: angr.SimState, base: int, movement: claripy.ast.BV) -> None:
    state.memory.store(base + H_CURRENT_SPRITE_OFFSET, claripy.BVV(0x20, 8))
    for address in range(SPRITE_DATA1 + 0x20, SPRITE_DATA1 + 0x30):
        state.memory.store(base + address, claripy.BVV(0, 8))
    for address in range(SPRITE_DATA2 + 0x20, SPRITE_DATA2 + 0x30):
        state.memory.store(base + address, claripy.BVV(0, 8))
    state.memory.store(base + SPRITE_DATA2 + 0x26, movement)
    for address in (0xff04, 0xffd3, 0xffd4):
        state.memory.store(base + address, claripy.BVV(0, 8))
    state.solver.add(movement.ULT(claripy.BVV(0xfe, 8)))


def _setup_stay_failure(state: angr.SimState, base: int,
                        random_add: claripy.ast.BV, random_sub: claripy.ast.BV,
                        div: claripy.ast.BV, sentinel: bool = False,
                        leading_nonmatch: bool = False, movement: int = 0xff,
                        y_pixels: int = 0, x_pixels: int = 0) -> None:
    state.memory.store(base + H_CURRENT_SPRITE_OFFSET, claripy.BVV(0x20, 8))
    for address in range(SPRITE_DATA1 + 0x20, SPRITE_DATA1 + 0x30):
        state.memory.store(base + address, claripy.BVV(0, 8))
    for address in range(SPRITE_DATA2 + 0x20, SPRITE_DATA2 + 0x30):
        state.memory.store(base + address, claripy.BVV(0, 8))
    state.memory.store(base + SPRITE_DATA2 + 0x26, claripy.BVV(movement, 8))
    state.memory.store(base + SPRITE_DATA1 + 0x24, claripy.BVV(y_pixels, 8))
    state.memory.store(base + SPRITE_DATA1 + 0x26, claripy.BVV(x_pixels, 8))
    state.memory.store(base + 0xd530, claripy.BVV(0x700, 16), endness="Iend_LE")
    state.memory.store(base + 0x700, claripy.BVV(
        0xff if sentinel else 0x20 if leading_nonmatch else 0x33, 8
    ))
    state.memory.store(base + 0x701, claripy.BVV(0x33 if leading_nonmatch else 0xff, 8))
    state.memory.store(base + 0x702, claripy.BVV(0xff, 8))
    state.memory.store(base + 0xff04, div)
    state.memory.store(base + 0xffd3, random_add)
    state.memory.store(base + 0xffd4, random_sub)


def _assembly(values: dict[str, claripy.ast.BV], movement: claripy.ast.BV) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "CanWalkOntoTile")
    assert linked_bytes(ROM, location, 14).hex() == "26c2f0dac6066f7efefe3002a7c9"
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    q = location.address
    project.hook(q, LoadHImmediate(0xc2, q + 2), length=2)
    project.hook(q + 2, Sm83LoadAHighImmediate(0xda, q + 4), length=2)
    project.hook(q + 4, Sm83AddImmediate(6, q + 6), length=2)
    project.hook(q + 6, LoadRegister("l", "a", q + 7), length=1)
    project.hook(q + 7, LoadAtHL(q + 8), length=1)
    project.hook(q + 8, Sm83CpImmediate(0xfe, q + 10), length=2)
    project.hook(q + 10, BranchCarryClear(q + 14, q + 12), length=2)
    project.hook(q + 12, AndA(q + 13), length=1)
    state = project.factory.blank_state(addr=q)
    set_assembly_registers(state, values)
    _setup(state, 0, movement)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN)
    assert not manager.errored and len(manager.found) == 1
    return [_endpoint(manager.found[0], False)]


def _native(values: dict[str, claripy.ast.BV], movement: claripy.ast.BV) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_can_walk_onto_tile")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, NATIVE_MEMORY, movement)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [_endpoint(manager.deadended[0], True)]


def _assembly_stay_failure(values: dict[str, claripy.ast.BV], random_add: claripy.ast.BV,
                           random_sub: claripy.ast.BV, div: claripy.ast.BV,
                           sentinel: bool = False,
                           leading_nonmatch: bool = False, movement: int = 0xff,
                           y_pixels: int = 0, x_pixels: int = 0) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "CanWalkOntoTile")
    assert linked_bytes(ROM, location, 153).hex().endswith("f0d3e67f7737c9")
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    q = location.address
    project.hook(q, LoadHImmediate(0xc2, q + 2), length=2)
    project.hook(q + 2, Sm83LoadAHighImmediate(0xda, q + 4), length=2)
    project.hook(q + 4, Sm83AddImmediate(6, q + 6), length=2)
    project.hook(q + 6, LoadRegister("l", "a", q + 7), length=1)
    project.hook(q + 7, LoadAtHL(q + 8), length=1)
    project.hook(q + 8, Sm83CpImmediate(0xfe, q + 10), length=2)
    project.hook(q + 10, BranchCarryClear(q + 14, q + 12), length=2)
    project.hook(q + 14, Sm83LoadAImmediate(0xd530, q + 17), length=3)
    project.hook(q + 17, LoadRegister("l", "a", q + 18), length=1)
    project.hook(q + 18, Sm83LoadAImmediate(0xd531, q + 21), length=3)
    project.hook(q + 21, LoadRegister("h", "a", q + 22), length=1)
    project.hook(q + 22, Sm83LoadAAtHlIncrement(q + 23), length=1)
    project.hook(q + 23, Sm83CpImmediate(0xff, q + 25), length=2)
    project.hook(q + 25, BranchFlag(q + 123, q + 27, 6, True), length=2)
    project.hook(q + 27, Sm83CpRegister("c", q + 28), length=1)
    project.hook(q + 28, BranchFlag(q + 22, q + 30, 6, False), length=2)
    project.hook(q + 30, LoadHImmediate(0xc2, q + 32), length=2)
    project.hook(q + 32, Sm83LoadAHighImmediate(0xda, q + 34), length=2)
    project.hook(q + 34, Sm83AddImmediate(6, q + 36), length=2)
    project.hook(q + 36, LoadRegister("l", "a", q + 37), length=1)
    project.hook(q + 37, LoadAtHL(q + 38), length=1)
    project.hook(q + 38, Sm83IncRegister("a", q + 39), length=1)
    project.hook(q + 39, BranchFlag(q + 123, q + 41, 6, True), length=2)
    project.hook(q + 41, LoadHImmediate(0xc1, q + 43), length=2)
    project.hook(q + 43, Sm83LoadAHighImmediate(0xda, q + 45), length=2)
    project.hook(q + 45, Sm83AddImmediate(4, q + 47), length=2)
    project.hook(q + 47, LoadRegister("l", "a", q + 48), length=1)
    project.hook(q + 48, Sm83LoadAAtHlIncrement(q + 49), length=1)
    project.hook(q + 49, Sm83AddImmediate(4, q + 51), length=2)
    project.hook(q + 51, Sm83AddRegister("d", q + 52), length=1)
    project.hook(q + 52, Sm83CpImmediate(0x80, q + 54), length=2)
    project.hook(q + 54, BranchCarryClear(q + 123, q + 56), length=2)
    project.hook(q + 56, Sm83IncRegister("l", q + 57), length=1)
    project.hook(q + 57, LoadAtHL(q + 58), length=1)
    project.hook(q + 58, Sm83AddRegister("e", q + 59), length=1)
    project.hook(q + 59, Sm83CpImmediate(0x90, q + 61), length=2)
    project.hook(q + 61, BranchCarryClear(q + 123, q + 63), length=2)
    project.hook(q + 123, LoadHImmediate(0xc1, q + 125), length=2)
    project.hook(q + 125, Sm83LoadAHighImmediate(0xda, q + 127), length=2)
    project.hook(q + 127, Sm83IncRegister("a", q + 128), length=1)
    project.hook(q + 128, LoadRegister("l", "a", q + 129), length=1)
    project.hook(q + 129, StoreImmediateAtHL(2, q + 131), length=2)
    project.hook(q + 131, Sm83IncRegister("l", q + 132), length=1)
    project.hook(q + 132, Sm83IncRegister("l", q + 133), length=1)
    project.hook(q + 133, Sm83XorA(q + 134), length=1)
    project.hook(q + 134, Sm83StoreAAtHlIncrement(q + 135), length=1)
    project.hook(q + 135, Sm83IncRegister("l", q + 136), length=1)
    project.hook(q + 136, StoreAtHL(q + 137), length=1)
    project.hook(q + 137, IncH(q + 138), length=1)
    project.hook(q + 138, Sm83LoadAHighImmediate(0xda, q + 140), length=2)
    project.hook(q + 140, Sm83AddImmediate(8, q + 142), length=2)
    project.hook(q + 142, LoadRegister("l", "a", q + 143), length=1)
    project.hook(q + 143, RandomBoundary(q + 146), length=3)
    project.hook(q + 146, Sm83LoadAHighImmediate(0xd3, q + 148), length=2)
    project.hook(q + 148, Sm83AndImmediate(0x7f, q + 150), length=2)
    project.hook(q + 150, StoreAtHL(q + 151), length=1)
    project.hook(q + 151, Sm83Scf(q + 152), length=1)
    state = project.factory.blank_state(addr=q)
    set_assembly_registers(state, values)
    _setup_stay_failure(state, 0, random_add, random_sub, div, sentinel,
                        leading_nonmatch, movement, y_pixels, x_pixels)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN)
    assert not manager.errored and len(manager.found) == 1
    return [_endpoint(manager.found[0], False)]


def _native_stay_failure(values: dict[str, claripy.ast.BV], random_add: claripy.ast.BV,
                         random_sub: claripy.ast.BV, div: claripy.ast.BV,
                         sentinel: bool = False,
                         leading_nonmatch: bool = False, movement: int = 0xff,
                         y_pixels: int = 0, x_pixels: int = 0) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_can_walk_onto_tile")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup_stay_failure(state, NATIVE_MEMORY, random_add, random_sub, div, sentinel,
                        leading_nonmatch, movement, y_pixels, x_pixels)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [_endpoint(manager.deadended[0], True)]


def _setup_unused_detector_success(state: angr.SimState, base: int) -> None:
    state.memory.store(base + H_CURRENT_SPRITE_OFFSET, claripy.BVV(0x20, 8))
    for address in range(SPRITE_DATA1 + 0x20, SPRITE_DATA1 + 0x30):
        state.memory.store(base + address, claripy.BVV(0, 8))
    for address in range(SPRITE_DATA2 + 0x20, SPRITE_DATA2 + 0x30):
        state.memory.store(base + address, claripy.BVV(0, 8))
    state.memory.store(base + SPRITE_DATA2 + 0x22, claripy.BVV(8, 8))
    state.memory.store(base + SPRITE_DATA2 + 0x23, claripy.BVV(8, 8))
    state.memory.store(base + SPRITE_DATA2 + 0x26, claripy.BVV(0xfe, 8))
    state.memory.store(base + 0xd530, claripy.BVV(0x700, 16), endness="Iend_LE")
    state.memory.store(base + 0x700, claripy.BVV(0x33, 8))
    state.memory.store(base + 0x701, claripy.BVV(0xff, 8))
    for address in (0xff04, 0xffd3, 0xffd4):
        state.memory.store(base + address, claripy.BVV(0, 8))


def _assembly_unused_detector_success(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "CanWalkOntoTile")
    detector = symbol_location(SYMBOLS, "DetectCollisionBetweenSprites")
    assert linked_bytes(ROM, location, 123).hex().endswith("3272a7c9")
    assert linked_bytes(ROM, detector, 11).hex() == "0026c1f0dac6006f7ea7c8"
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    q = location.address
    project.hook(q, LoadHImmediate(0xc2, q + 2), length=2)
    project.hook(q + 2, Sm83LoadAHighImmediate(0xda, q + 4), length=2)
    project.hook(q + 4, Sm83AddImmediate(6, q + 6), length=2)
    project.hook(q + 6, LoadRegister("l", "a", q + 7), length=1)
    project.hook(q + 7, LoadAtHL(q + 8), length=1)
    project.hook(q + 8, Sm83CpImmediate(0xfe, q + 10), length=2)
    project.hook(q + 10, BranchCarryClear(q + 14, q + 12), length=2)
    project.hook(q + 14, Sm83LoadAImmediate(0xd530, q + 17), length=3)
    project.hook(q + 17, LoadRegister("l", "a", q + 18), length=1)
    project.hook(q + 18, Sm83LoadAImmediate(0xd531, q + 21), length=3)
    project.hook(q + 21, LoadRegister("h", "a", q + 22), length=1)
    project.hook(q + 22, Sm83LoadAAtHlIncrement(q + 23), length=1)
    project.hook(q + 23, Sm83CpImmediate(0xff, q + 25), length=2)
    project.hook(q + 25, BranchFlag(q + 123, q + 27, 6, True), length=2)
    project.hook(q + 27, Sm83CpRegister("c", q + 28), length=1)
    project.hook(q + 28, BranchFlag(q + 22, q + 30, 6, False), length=2)
    project.hook(q + 30, LoadHImmediate(0xc2, q + 32), length=2)
    project.hook(q + 32, Sm83LoadAHighImmediate(0xda, q + 34), length=2)
    project.hook(q + 34, Sm83AddImmediate(6, q + 36), length=2)
    project.hook(q + 36, LoadRegister("l", "a", q + 37), length=1)
    project.hook(q + 37, LoadAtHL(q + 38), length=1)
    project.hook(q + 38, Sm83IncRegister("a", q + 39), length=1)
    project.hook(q + 39, BranchFlag(q + 123, q + 41, 6, True), length=2)
    project.hook(q + 41, LoadHImmediate(0xc1, q + 43), length=2)
    project.hook(q + 43, Sm83LoadAHighImmediate(0xda, q + 45), length=2)
    project.hook(q + 45, Sm83AddImmediate(4, q + 47), length=2)
    project.hook(q + 47, LoadRegister("l", "a", q + 48), length=1)
    project.hook(q + 48, Sm83LoadAAtHlIncrement(q + 49), length=1)
    project.hook(q + 49, Sm83AddImmediate(4, q + 51), length=2)
    project.hook(q + 51, Sm83AddRegister("d", q + 52), length=1)
    project.hook(q + 52, Sm83CpImmediate(0x80, q + 54), length=2)
    project.hook(q + 54, BranchCarryClear(q + 123, q + 56), length=2)
    project.hook(q + 56, Sm83IncRegister("l", q + 57), length=1)
    project.hook(q + 57, LoadAtHL(q + 58), length=1)
    project.hook(q + 58, Sm83AddRegister("e", q + 59), length=1)
    project.hook(q + 59, Sm83CpImmediate(0x90, q + 61), length=2)
    project.hook(q + 61, BranchCarryClear(q + 123, q + 63), length=2)
    project.hook(q + 63, PushPair("de", q + 64), length=1)
    project.hook(q + 64, PushPair("bc", q + 65), length=1)
    project.hook(q + 65, Call(detector.address, q + 68), length=3)
    d = detector.address
    project.hook(d, Jump(d + 1), length=1)
    project.hook(d + 1, LoadHImmediate(0xc1, d + 3), length=2)
    project.hook(d + 3, Sm83LoadAHighImmediate(0xda, d + 5), length=2)
    project.hook(d + 5, Sm83AddImmediate(0, d + 7), length=2)
    project.hook(d + 7, LoadRegister("l", "a", d + 8), length=1)
    project.hook(d + 8, LoadAtHL(d + 9), length=1)
    project.hook(d + 9, AndA(d + 10), length=1)
    project.hook(d + 10, ReturnIfZero(), length=1)
    project.hook(q + 68, PopPair("bc", q + 69), length=1)
    project.hook(q + 69, PopPair("de", q + 70), length=1)
    project.hook(q + 70, LoadHImmediate(0xc1, q + 72), length=2)
    project.hook(q + 72, Sm83LoadAHighImmediate(0xda, q + 74), length=2)
    project.hook(q + 74, Sm83AddImmediate(12, q + 76), length=2)
    project.hook(q + 76, LoadRegister("l", "a", q + 77), length=1)
    project.hook(q + 77, LoadAtHL(q + 78), length=1)
    from verification.harness.sm83_shims import Sm83AndRegister
    project.hook(q + 78, Sm83AndRegister("b", q + 79), length=1)
    project.hook(q + 79, BranchFlag(q + 123, q + 81, 6, False), length=2)
    project.hook(q + 81, LoadHImmediate(0xc2, q + 83), length=2)
    project.hook(q + 83, Sm83LoadAHighImmediate(0xda, q + 85), length=2)
    project.hook(q + 85, Sm83AddImmediate(2, q + 87), length=2)
    project.hook(q + 87, LoadRegister("l", "a", q + 88), length=1)
    project.hook(q + 88, Sm83LoadAAtHlIncrement(q + 89), length=1)
    project.hook(q + 89, Sm83BitRegister(7, "d", q + 91), length=2)
    project.hook(q + 91, BranchFlag(q + 100, q + 93, 6, False), length=2)
    project.hook(q + 93, Sm83AddRegister("d", q + 94), length=1)
    project.hook(q + 94, Sm83CpImmediate(5, q + 96), length=2)
    project.hook(q + 96, BranchFlag(q + 123, q + 98, 0, True), length=2)
    project.hook(q + 98, Jump(q + 104), length=2)
    project.hook(q + 100, Sm83SubImmediate(1, q + 102), length=2)
    project.hook(q + 102, BranchFlag(q + 123, q + 104, 0, True), length=2)
    project.hook(q + 104, LoadRegister("d", "a", q + 105), length=1)
    project.hook(q + 105, LoadAtHL(q + 106), length=1)
    project.hook(q + 106, Sm83BitRegister(7, "e", q + 108), length=2)
    project.hook(q + 108, BranchFlag(q + 115, q + 110, 6, False), length=2)
    project.hook(q + 110, Sm83AddRegister("e", q + 111), length=1)
    project.hook(q + 111, Sm83CpImmediate(5, q + 113), length=2)
    project.hook(q + 113, Jump(q + 119), length=2)
    project.hook(q + 115, Sm83SubImmediate(1, q + 117), length=2)
    project.hook(q + 117, BranchFlag(q + 123, q + 119, 0, True), length=2)
    project.hook(q + 119, StoreAtHLDecrement(q + 120), length=1)
    project.hook(q + 120, StoreAtHL(q + 121), length=1)
    project.hook(q + 121, AndA(q + 122), length=1)
    state = project.factory.blank_state(addr=q)
    set_assembly_registers(state, values)
    _setup_unused_detector_success(state, 0)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN)
    assert not manager.errored and len(manager.found) == 1
    return [_endpoint(manager.found[0], False)]


def _native_unused_detector_success(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_can_walk_onto_tile")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup_unused_detector_success(state, NATIVE_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [_endpoint(manager.deadended[0], True)]


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),
                    reason="build artifacts missing")
def test_can_walk_onto_tile_scripted_movement_pathwise_equivalence() -> None:
    """Every movement byte below WALK takes the early success terminal."""
    values = symbolic_registers("can_walk_scripted")
    movement = claripy.BVS("can_walk_scripted_movement", 8)
    assert_pathwise_equivalent(
        _assembly(values, movement), _native(values, movement), (*REGISTERS, "state")
    )


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),
                    reason="build artifacts missing")
def test_can_walk_onto_tile_stay_failure_pathwise_equivalence() -> None:
    values = symbolic_registers("can_walk_stay")
    values["c"] = claripy.BVV(0x33, 8)
    random_add = claripy.BVS("can_walk_stay_random_add", 8)
    random_sub = claripy.BVS("can_walk_stay_random_sub", 8)
    div = claripy.BVS("can_walk_stay_div", 8)
    assert_pathwise_equivalent(
        _assembly_stay_failure(values, random_add, random_sub, div),
        _native_stay_failure(values, random_add, random_sub, div),
        (*REGISTERS, "state"),
    )


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),
                    reason="build artifacts missing")
def test_can_walk_onto_tile_collision_sentinel_pathwise_equivalence() -> None:
    values = symbolic_registers("can_walk_sentinel")
    random_add = claripy.BVS("can_walk_sentinel_random_add", 8)
    random_sub = claripy.BVS("can_walk_sentinel_random_sub", 8)
    div = claripy.BVS("can_walk_sentinel_div", 8)
    assert_pathwise_equivalent(
        _assembly_stay_failure(values, random_add, random_sub, div, sentinel=True),
        _native_stay_failure(values, random_add, random_sub, div, sentinel=True),
        (*REGISTERS, "state"),
    )


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),
                    reason="build artifacts missing")
def test_can_walk_onto_tile_collision_table_loop_pathwise_equivalence() -> None:
    values = symbolic_registers("can_walk_table_loop")
    values["c"] = claripy.BVV(0x33, 8)
    random_add = claripy.BVS("can_walk_table_loop_random_add", 8)
    random_sub = claripy.BVS("can_walk_table_loop_random_sub", 8)
    div = claripy.BVS("can_walk_table_loop_div", 8)
    assert_pathwise_equivalent(
        _assembly_stay_failure(values, random_add, random_sub, div,
                               leading_nonmatch=True),
        _native_stay_failure(values, random_add, random_sub, div,
                             leading_nonmatch=True),
        (*REGISTERS, "state"),
    )


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),
                    reason="build artifacts missing")
def test_can_walk_onto_tile_vertical_bounds_failure_pathwise_equivalence() -> None:
    values = symbolic_registers("can_walk_y_bound")
    values["c"] = claripy.BVV(0x33, 8)
    values["d"] = claripy.BVV(0, 8)
    random_add = claripy.BVS("can_walk_y_bound_random_add", 8)
    random_sub = claripy.BVS("can_walk_y_bound_random_sub", 8)
    div = claripy.BVS("can_walk_y_bound_div", 8)
    assert_pathwise_equivalent(
        _assembly_stay_failure(values, random_add, random_sub, div,
                               movement=0xfe, y_pixels=0x7c),
        _native_stay_failure(values, random_add, random_sub, div,
                             movement=0xfe, y_pixels=0x7c),
        (*REGISTERS, "state"),
    )


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),
                    reason="build artifacts missing")
def test_can_walk_onto_tile_horizontal_bounds_failure_pathwise_equivalence() -> None:
    values = symbolic_registers("can_walk_x_bound")
    values["c"] = claripy.BVV(0x33, 8)
    values["d"] = claripy.BVV(0, 8)
    values["e"] = claripy.BVV(0, 8)
    random_add = claripy.BVS("can_walk_x_bound_random_add", 8)
    random_sub = claripy.BVS("can_walk_x_bound_random_sub", 8)
    div = claripy.BVS("can_walk_x_bound_div", 8)
    assert_pathwise_equivalent(
        _assembly_stay_failure(values, random_add, random_sub, div,
                               movement=0xfe, x_pixels=0x90),
        _native_stay_failure(values, random_add, random_sub, div,
                             movement=0xfe, x_pixels=0x90),
        (*REGISTERS, "state"),
    )


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),
                    reason="build artifacts missing")
def test_can_walk_onto_tile_unused_sprite_success_pathwise_equivalence() -> None:
    values = symbolic_registers("can_walk_unused_success")
    values["b"] = claripy.BVV(1, 8)
    values["c"] = claripy.BVV(0x33, 8)
    values["d"] = claripy.BVV(0, 8)
    values["e"] = claripy.BVV(0, 8)
    assert_pathwise_equivalent(
        _assembly_unused_detector_success(values),
        _native_unused_detector_success(values),
        (*REGISTERS, "state"),
    )
