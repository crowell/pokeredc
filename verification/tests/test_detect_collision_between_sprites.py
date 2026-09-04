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
    Sm83AddImmediate, Sm83AddRegister, Sm83AndRegister, Sm83CpImmediate, Sm83CpRegister,
    Sm83DecRegister, Sm83IncRegister, Sm83LoadAAtHlIncrement, Sm83LoadAHighImmediate,
    Sm83RlRegister, Sm83StoreAAtHlDecrement, Sm83StoreAAtHlIncrement,
    Sm83StoreAHighImmediate,
    Sm83SubAtHl, Sm83SubRegister, Sm83SwapRegister, Sm83XorA,
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
    current_offset: claripy.ast.BV
    sprite_data: claripy.ast.BV
    collision_work: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class Sm83AndA(angr.SimProcedure):
    """Correct SM83 AND A flags (including the mandatory H bit)."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.f = claripy.BVV(0x10, 8) | claripy.If(
            self.state.regs.a == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)
        )
        self.jump(self.next_address)


class Sm83Nop(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.jump(self.next_address)


class Sm83Branch(angr.SimProcedure):
    """Fork an SM83 conditional branch from its explicitly modeled flags."""

    def __init__(self, taken: int, fallthrough: int, flag: int,
                 taken_when_set: bool) -> None:
        super().__init__()
        self.taken = taken
        self.fallthrough = fallthrough
        self.flag = flag
        self.taken_when_set = taken_when_set

    def run(self) -> None:  # type: ignore[override]
        condition = (self.state.regs.f >> self.flag) & 1
        if not self.taken_when_set:
            condition = condition == 0
        else:
            condition = condition == 1
        taken = self.state.copy()
        fallthrough = self.state.copy()
        taken.solver.add(condition)
        fallthrough.solver.add(claripy.Not(condition))
        taken.regs.ip = claripy.BVV(self.taken, 16)
        fallthrough.regs.ip = claripy.BVV(self.fallthrough, 16)
        self.inhibit_autoret = True
        self.successors.add_successor(taken, self.taken, condition, "Ijk_Boring")
        self.successors.add_successor(
            fallthrough, self.fallthrough, claripy.Not(condition), "Ijk_Boring"
        )


class Sm83CplA(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = ~self.state.regs.a
        self.state.regs.f = (self.state.regs.f & 0x41) | 0x12
        self.jump(self.next_address)


class Sm83LoadHImmediate(angr.SimProcedure):
    def __init__(self, value: int, next_address: int) -> None:
        super().__init__()
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = claripy.BVV(self.value, 8)
        self.jump(self.next_address)


class Sm83LoadRegister(angr.SimProcedure):
    def __init__(self, destination: str, source: str, next_address: int) -> None:
        super().__init__()
        self.destination = destination
        self.source = source
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.destination, getattr(self.state.regs, self.source))
        self.jump(self.next_address)


class Sm83LoadImmediate(angr.SimProcedure):
    def __init__(self, destination: str, value: int, next_address: int) -> None:
        super().__init__()
        self.destination = destination
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.destination, claripy.BVV(self.value, 8))
        self.jump(self.next_address)


class Sm83LoadAAtHl(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self.state.regs.hl, 1)
        self.jump(self.next_address)


class Sm83LoadAAtDe(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self.state.regs.de, 1)
        self.jump(self.next_address)


class Sm83AndImmediate(angr.SimProcedure):
    def __init__(self, value: int, next_address: int) -> None:
        super().__init__()
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a &= self.value
        self.state.regs.f = claripy.BVV(0x10, 8) | claripy.If(
            self.state.regs.a == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)
        )
        self.jump(self.next_address)


class Sm83OrRegister(angr.SimProcedure):
    def __init__(self, register: str, next_address: int) -> None:
        super().__init__()
        self.register = register
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a |= getattr(self.state.regs, self.register)
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)
        )
        self.jump(self.next_address)


class Sm83Ccf(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.f = (self.state.regs.f & 0x40) | ((self.state.regs.f ^ 1) & 1)
        self.jump(self.next_address)


class Sm83PushAF(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        sp = self.state.regs.sp - 2
        self.state.memory.store(sp, self.state.regs.f)
        self.state.memory.store(sp + 1, self.state.regs.a)
        self.state.regs.sp = sp
        self.jump(self.next_address)


class Sm83PopAF(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        sp = self.state.regs.sp
        self.state.regs.f = self.state.memory.load(sp, 1)
        self.state.regs.a = self.state.memory.load(sp + 1, 1)
        self.state.regs.sp = sp + 2
        self.jump(self.next_address)


class Sm83PushBC(Sm83PushAF):
    def run(self) -> None:  # type: ignore[override]
        sp = self.state.regs.sp - 2
        self.state.memory.store(sp, self.state.regs.c)
        self.state.memory.store(sp + 1, self.state.regs.b)
        self.state.regs.sp = sp
        self.jump(self.next_address)


class Sm83PopBC(Sm83PopAF):
    def run(self) -> None:  # type: ignore[override]
        sp = self.state.regs.sp
        self.state.regs.c = self.state.memory.load(sp, 1)
        self.state.regs.b = self.state.memory.load(sp + 1, 1)
        self.state.regs.sp = sp + 2
        self.jump(self.next_address)


class Sm83StoreAAtHl(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(self.state.regs.hl, self.state.regs.a)
        self.jump(self.next_address)


class Sm83OrAtHl(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a |= self.state.memory.load(self.state.regs.hl, 1)
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)
        )
        self.jump(self.next_address)


class Sm83LoadDEImmediate(angr.SimProcedure):
    def __init__(self, value: int, next_address: int) -> None:
        super().__init__()
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.de = claripy.BVV(self.value, 16)
        self.jump(self.next_address)


class Sm83IncDE(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.de += 1
        self.jump(self.next_address)


class SetSpriteCollisionValuesBoundary(angr.SimProcedure):
    """Complete transition of the separately proven direct callee."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        value = self.state.regs.a

        is_zero = value == 0
        is_negative_one = value == 0xff
        self.state.regs.a = claripy.If(
            is_zero | is_negative_one, value, claripy.BVV(0, 8)
        )
        self.state.regs.b = claripy.If(
            is_negative_one, value, claripy.BVV(0, 8)
        )
        self.state.regs.c = claripy.If(
            is_zero, claripy.BVV(0, 8),
            claripy.If(is_negative_one, claripy.BVV(9, 8), claripy.BVV(7, 8)),
        )
        self.state.regs.f = claripy.If(
            is_zero, claripy.BVV(0x50, 8), claripy.BVV(0x13, 8)
        )
        self.jump(self.next_address)


def _collect_returns(project: angr.Project, state: angr.SimState) -> list[angr.SimState]:
    """Run pcode one hook-delimited block at a time.

    Unlike VEX, the pcode lifter does not automatically end a translated block
    at a SimProcedure address.  Supplying the procedure addresses as explicit
    stop points is required for the individual SM83 instruction adapters below
    to run.
    """
    manager = project.factory.simulation_manager(state)
    manager.stashes["returned"] = []
    stop_points = set(project._sim_procedures)
    while manager.active:
        manager.move(
            from_stash="active",
            to_stash="returned",
            filter_func=lambda candidate: candidate.addr == RETURN,
        )
        if manager.active:
            manager.step(extra_stop_points=stop_points)
    assert not manager.errored and manager.returned
    return manager.returned


def _endpoint(state: angr.SimState, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    registers = native_registers(state, NATIVE_STATE) if native else assembly_registers(state)
    return Endpoint(
        **registers,
        current_offset=state.memory.load(base + H_CURRENT_SPRITE_OFFSET, 1),
        sprite_data=claripy.Concat(*(
            state.memory.load(base + SPRITE_DATA1 + offset, 1)
            for offset in range(256)
        )),
        collision_work=claripy.Concat(*(
            state.memory.load(base + address, 1)
            for address in range(0xff8f, 0xff93)
        )),
        constraints=tuple(state.solver.constraints),
    )


def _store_sprite_data(state: angr.SimState, base: int, sprite_data: bytes,
                       overrides: dict[int, claripy.ast.BV] | None = None) -> None:
    for offset, value in enumerate(sprite_data):
        state.memory.store(base + SPRITE_DATA1 + offset, claripy.BVV(value, 8))
    for offset, value in (overrides or {}).items():
        state.memory.store(base + SPRITE_DATA1 + offset, value)


def _assembly(values: dict[str, claripy.ast.BV], sprite_data: bytes = bytes(256),
              current_offset: int = 0,
              overrides: dict[int, claripy.ast.BV] | None = None) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "DetectCollisionBetweenSprites")
    assert linked_bytes(ROM, location, 11).hex() == "0026c1f0dac6006f7ea7c8"
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    start = location.address
    project.hook(start, Sm83Nop(start + 1), length=1)
    project.hook(start + 1, Sm83LoadHImmediate(0xc1, start + 3), length=2)
    project.hook(start + 3, Sm83LoadAHighImmediate(0xda, start + 5), length=2)
    project.hook(start + 5, Sm83AddImmediate(0, start + 7), length=2)
    project.hook(start + 7, Sm83LoadRegister("l", "a", start + 8), length=1)
    project.hook(start + 9, Sm83AndA(start + 10), length=1)
    project.hook(start + 11, Sm83LoadRegister("a", "l", start + 12), length=1)
    project.hook(start + 12, Sm83AddImmediate(3, start + 14), length=2)
    project.hook(start + 14, Sm83LoadRegister("l", "a", start + 15), length=1)
    project.hook(start + 15, Sm83LoadAAtHlIncrement(start + 16), length=1)
    project.hook(start + 16, SetSpriteCollisionValuesBoundary(start + 19), length=3)
    project.hook(start + 19, Sm83LoadAAtHlIncrement(start + 20), length=1)
    project.hook(start + 20, Sm83AddImmediate(4, start + 22), length=2)
    project.hook(start + 22, Sm83AddRegister("b", start + 23), length=1)
    project.hook(start + 23, Sm83AndImmediate(0xf0, start + 25), length=2)
    project.hook(start + 25, Sm83OrRegister("c", start + 26), length=1)
    project.hook(start + 26, Sm83StoreAHighImmediate(0x90, start + 28), length=2)
    project.hook(start + 28, Sm83LoadAAtHlIncrement(start + 29), length=1)
    project.hook(start + 29, SetSpriteCollisionValuesBoundary(start + 32), length=3)
    project.hook(start + 32, Sm83LoadAAtHl(start + 33), length=1)
    project.hook(start + 33, Sm83AddRegister("b", start + 34), length=1)
    project.hook(start + 34, Sm83AndImmediate(0xf0, start + 36), length=2)
    project.hook(start + 36, Sm83OrRegister("c", start + 37), length=1)
    project.hook(start + 37, Sm83StoreAHighImmediate(0x91, start + 39), length=2)
    project.hook(start + 39, Sm83LoadRegister("a", "l", start + 40), length=1)
    project.hook(start + 40, Sm83AddImmediate(7, start + 42), length=2)
    project.hook(start + 42, Sm83LoadRegister("l", "a", start + 43), length=1)
    project.hook(start + 43, Sm83XorA(start + 44), length=1)
    project.hook(start + 44, Sm83StoreAAtHlDecrement(start + 45), length=1)
    project.hook(start + 45, Sm83StoreAAtHlDecrement(start + 46), length=1)
    project.hook(start + 46, Sm83LoadAHighImmediate(0x91, start + 48), length=2)
    project.hook(start + 48, Sm83StoreAAtHlDecrement(start + 49), length=1)
    project.hook(start + 49, Sm83LoadAHighImmediate(0x90, start + 51), length=2)
    project.hook(start + 52, Sm83XorA(start + 53), length=1)
    project.hook(start + 53, Sm83StoreAHighImmediate(0x8f, start + 55), length=2)
    project.hook(start + 55, Sm83SwapRegister("a", start + 57), length=2)
    project.hook(start + 57, Sm83LoadRegister("e", "a", start + 58), length=1)
    project.hook(start + 58, Sm83LoadAHighImmediate(0xda, start + 60), length=2)
    project.hook(start + 60, Sm83CpRegister("e", start + 61), length=1)
    project.hook(start + 61, Sm83Branch(start + 249, start + 64, 6, True), length=3)
    project.hook(start + 64, Sm83LoadRegister("d", "h", start + 65), length=1)
    project.hook(start + 65, Sm83LoadAAtDe(start + 66), length=1)
    project.hook(start + 66, Sm83AndA(start + 67), length=1)
    project.hook(start + 67, Sm83Branch(start + 249, start + 70, 6, True), length=3)
    project.hook(start + 70, Sm83IncRegister("e", start + 71), length=1)
    project.hook(start + 71, Sm83IncRegister("e", start + 72), length=1)
    project.hook(start + 72, Sm83LoadAAtDe(start + 73), length=1)
    project.hook(start + 73, Sm83IncRegister("a", start + 74), length=1)
    project.hook(start + 74, Sm83Branch(start + 249, start + 77, 6, True), length=3)
    project.hook(start + 77, Sm83LoadAHighImmediate(0xda, start + 79), length=2)
    project.hook(start + 79, Sm83AddImmediate(10, start + 81), length=2)
    project.hook(start + 81, Sm83LoadRegister("l", "a", start + 82), length=1)
    project.hook(start + 82, Sm83IncRegister("e", start + 83), length=1)
    project.hook(start + 83, Sm83LoadAAtDe(start + 84), length=1)
    project.hook(start + 84, SetSpriteCollisionValuesBoundary(start + 87), length=3)
    project.hook(start + 87, Sm83IncRegister("e", start + 88), length=1)
    project.hook(start + 88, Sm83LoadAAtDe(start + 89), length=1)
    project.hook(start + 89, Sm83AddImmediate(4, start + 91), length=2)
    project.hook(start + 91, Sm83AddRegister("b", start + 92), length=1)
    project.hook(start + 92, Sm83AndImmediate(0xf0, start + 94), length=2)
    project.hook(start + 94, Sm83OrRegister("c", start + 95), length=1)
    project.hook(start + 95, Sm83SubAtHl(start + 96), length=1)
    project.hook(start + 96, Sm83Branch(start + 100, start + 98, 0, False), length=2)
    project.hook(start + 98, Sm83CplA(start + 99), length=1)
    project.hook(start + 99, Sm83IncRegister("a", start + 100), length=1)
    project.hook(start + 100, Sm83StoreAHighImmediate(0x90, start + 102), length=2)
    project.hook(start + 102, Sm83PushAF(start + 103), length=1)
    project.hook(start + 103, Sm83RlRegister("c", start + 105), length=2)
    project.hook(start + 105, Sm83PopAF(start + 106), length=1)
    project.hook(start + 106, Sm83Ccf(start + 107), length=1)
    project.hook(start + 107, Sm83RlRegister("c", start + 109), length=2)
    project.hook(start + 109, Sm83LoadImmediate("b", 7, start + 111), length=2)
    project.hook(start + 111, Sm83LoadAAtHl(start + 112), length=1)
    project.hook(start + 112, Sm83AndImmediate(0x0f, start + 114), length=2)
    project.hook(start + 114, Sm83Branch(start + 118, start + 116, 6, True), length=2)
    project.hook(start + 116, Sm83LoadImmediate("b", 9, start + 118), length=2)
    project.hook(start + 118, Sm83LoadAHighImmediate(0x90, start + 120), length=2)
    project.hook(start + 120, Sm83SubRegister("b", start + 121), length=1)
    project.hook(start + 121, Sm83StoreAHighImmediate(0x92, start + 123), length=2)
    project.hook(start + 123, Sm83LoadRegister("a", "b", start + 124), length=1)
    project.hook(start + 124, Sm83StoreAHighImmediate(0x90, start + 126), length=2)
    project.hook(start + 126, Sm83Branch(start + 145, start + 128, 0, True), length=2)
    project.hook(start + 128, Sm83LoadImmediate("b", 7, start + 130), length=2)
    project.hook(start + 130, Sm83IncRegister("e", start + 131), length=1)
    project.hook(start + 131, Sm83LoadAAtDe(start + 132), length=1)
    project.hook(start + 132, Sm83IncRegister("e", start + 133), length=1)
    project.hook(start + 133, Sm83AndA(start + 134), length=1)
    project.hook(start + 134, Sm83Branch(start + 138, start + 136, 6, True), length=2)
    project.hook(start + 136, Sm83LoadImmediate("b", 9, start + 138), length=2)
    project.hook(start + 138, Sm83LoadAHighImmediate(0x92, start + 140), length=2)
    project.hook(start + 140, Sm83SubRegister("b", start + 141), length=1)
    project.hook(start + 141, Sm83Branch(start + 145, start + 143, 6, True), length=2)
    project.hook(start + 143, Sm83Branch(start + 249, start + 145, 0, False), length=2)
    project.hook(start + 145, Sm83IncRegister("e", start + 146), length=1)
    project.hook(start + 146, Sm83IncRegister("l", start + 147), length=1)
    project.hook(start + 147, Sm83LoadAAtDe(start + 148), length=1)
    project.hook(start + 148, Sm83PushBC(start + 149), length=1)
    project.hook(start + 149, SetSpriteCollisionValuesBoundary(start + 152), length=3)
    project.hook(start + 152, Sm83IncRegister("e", start + 153), length=1)
    project.hook(start + 153, Sm83LoadAAtDe(start + 154), length=1)
    project.hook(start + 154, Sm83AddRegister("b", start + 155), length=1)
    project.hook(start + 155, Sm83AndImmediate(0xf0, start + 157), length=2)
    project.hook(start + 157, Sm83OrRegister("c", start + 158), length=1)
    project.hook(start + 158, Sm83PopBC(start + 159), length=1)
    project.hook(start + 159, Sm83SubAtHl(start + 160), length=1)
    project.hook(start + 160, Sm83Branch(start + 164, start + 162, 0, False), length=2)
    project.hook(start + 162, Sm83CplA(start + 163), length=1)
    project.hook(start + 163, Sm83IncRegister("a", start + 164), length=1)
    project.hook(start + 164, Sm83StoreAHighImmediate(0x91, start + 166), length=2)
    project.hook(start + 166, Sm83PushAF(start + 167), length=1)
    project.hook(start + 167, Sm83RlRegister("c", start + 169), length=2)
    project.hook(start + 169, Sm83PopAF(start + 170), length=1)
    project.hook(start + 170, Sm83Ccf(start + 171), length=1)
    project.hook(start + 171, Sm83RlRegister("c", start + 173), length=2)
    project.hook(start + 173, Sm83LoadImmediate("b", 7, start + 175), length=2)
    project.hook(start + 175, Sm83LoadAAtHl(start + 176), length=1)
    project.hook(start + 176, Sm83AndImmediate(0x0f, start + 178), length=2)
    project.hook(start + 178, Sm83Branch(start + 182, start + 180, 6, True), length=2)
    project.hook(start + 180, Sm83LoadImmediate("b", 9, start + 182), length=2)
    project.hook(start + 182, Sm83LoadAHighImmediate(0x91, start + 184), length=2)
    project.hook(start + 184, Sm83SubRegister("b", start + 185), length=1)
    project.hook(start + 185, Sm83StoreAHighImmediate(0x92, start + 187), length=2)
    project.hook(start + 187, Sm83LoadRegister("a", "b", start + 188), length=1)
    project.hook(start + 188, Sm83StoreAHighImmediate(0x91, start + 190), length=2)
    project.hook(start + 190, Sm83Branch(start + 209, start + 192, 0, True), length=2)
    project.hook(start + 192, Sm83LoadImmediate("b", 7, start + 194), length=2)
    project.hook(start + 194, Sm83DecRegister("e", start + 195), length=1)
    project.hook(start + 195, Sm83LoadAAtDe(start + 196), length=1)
    project.hook(start + 196, Sm83IncRegister("e", start + 197), length=1)
    project.hook(start + 197, Sm83AndA(start + 198), length=1)
    project.hook(start + 198, Sm83Branch(start + 202, start + 200, 6, True), length=2)
    project.hook(start + 200, Sm83LoadImmediate("b", 9, start + 202), length=2)
    project.hook(start + 202, Sm83LoadAHighImmediate(0x92, start + 204), length=2)
    project.hook(start + 204, Sm83SubRegister("b", start + 205), length=1)
    project.hook(start + 205, Sm83Branch(start + 209, start + 207, 6, True), length=2)
    project.hook(start + 207, Sm83Branch(start + 249, start + 209, 0, False), length=2)
    project.hook(start + 209, Sm83LoadAHighImmediate(0x91, start + 211), length=2)
    project.hook(start + 211, Sm83LoadRegister("b", "a", start + 212), length=1)
    project.hook(start + 212, Sm83LoadAHighImmediate(0x90, start + 214), length=2)
    project.hook(start + 214, Sm83IncRegister("l", start + 215), length=1)
    project.hook(start + 215, Sm83CpRegister("b", start + 216), length=1)
    project.hook(start + 216, Sm83Branch(start + 222, start + 218, 0, True), length=2)
    project.hook(start + 218, Sm83LoadImmediate("b", 0x0c, start + 220), length=2)
    project.hook(start + 220, Sm83Nop(start + 224), length=2)
    project.hook(start + 222, Sm83LoadImmediate("b", 3, start + 224), length=2)
    project.hook(start + 224, Sm83LoadRegister("a", "c", start + 225), length=1)
    project.hook(start + 225, Sm83AndRegister("b", start + 226), length=1)
    project.hook(start + 226, Sm83OrAtHl(start + 227), length=1)
    project.hook(start + 227, Sm83StoreAAtHl(start + 228), length=1)
    project.hook(start + 228, Sm83LoadRegister("a", "c", start + 229), length=1)
    project.hook(start + 229, Sm83IncRegister("l", start + 230), length=1)
    project.hook(start + 230, Sm83IncRegister("l", start + 231), length=1)
    project.hook(start + 231, Sm83LoadAHighImmediate(0x8f, start + 233), length=2)
    project.hook(start + 233, Sm83LoadDEImmediate(0x4d85, start + 236), length=3)
    project.hook(start + 236, Sm83AddRegister("a", start + 237), length=1)
    project.hook(start + 237, Sm83AddRegister("e", start + 238), length=1)
    project.hook(start + 238, Sm83LoadRegister("e", "a", start + 239), length=1)
    project.hook(start + 239, Sm83Branch(start + 242, start + 241, 0, False), length=2)
    project.hook(start + 241, Sm83IncRegister("d", start + 242), length=1)
    project.hook(start + 242, Sm83LoadAAtDe(start + 243), length=1)
    project.hook(start + 243, Sm83OrAtHl(start + 244), length=1)
    project.hook(start + 244, Sm83StoreAAtHlIncrement(start + 245), length=1)
    project.hook(start + 245, Sm83IncDE(start + 246), length=1)
    project.hook(start + 246, Sm83LoadAAtDe(start + 247), length=1)
    project.hook(start + 247, Sm83OrAtHl(start + 248), length=1)
    project.hook(start + 248, Sm83StoreAAtHl(start + 249), length=1)
    project.hook(start + 249, Sm83LoadAHighImmediate(0x8f, start + 251), length=2)
    project.hook(start + 251, Sm83IncRegister("a", start + 252), length=1)
    project.hook(start + 252, Sm83CpImmediate(16, start + 254), length=2)
    project.hook(start + 254, Sm83Branch(start + 53, start + 257, 6, False), length=3)
    state = project.factory.blank_state(addr=start)
    set_assembly_registers(state, values)
    state.memory.store(H_CURRENT_SPRITE_OFFSET, claripy.BVV(current_offset, 8))
    for address in range(0xff8f, 0xff93):
        state.memory.store(address, claripy.BVV(0, 8))
    _store_sprite_data(state, 0, sprite_data, overrides)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    states = _collect_returns(project, state)
    return [_endpoint(result, False) for result in states]


def _native(values: dict[str, claripy.ast.BV], sprite_data: bytes = bytes(256),
            current_offset: int = 0,
            overrides: dict[int, claripy.ast.BV] | None = None) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_detect_collision_between_sprites")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(
        NATIVE_MEMORY + H_CURRENT_SPRITE_OFFSET, claripy.BVV(current_offset, 8)
    )
    for address in range(0xff8f, 0xff93):
        state.memory.store(NATIVE_MEMORY + address, claripy.BVV(0, 8))
    _store_sprite_data(state, NATIVE_MEMORY, sprite_data, overrides)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and manager.deadended
    return [_endpoint(result, True) for result in manager.deadended]


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),
                    reason="build artifacts missing")
def test_detect_collision_between_sprites_unused_slot_pathwise_equivalence() -> None:
    values = symbolic_registers("detect_collision_unused")
    assert_pathwise_equivalent(
        _assembly(values), _native(values),
        (*REGISTERS, "current_offset", "sprite_data", "collision_work"),
    )


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),
                    reason="build artifacts missing")
def test_detect_collision_between_sprites_occupied_slot_smoke() -> None:
    values = {register: claripy.BVV(0, 8) for register in REGISTERS}
    sprite_data = bytearray(256)
    sprite_data[0] = 1
    assert_pathwise_equivalent(
        _assembly(values, bytes(sprite_data)), _native(values, bytes(sprite_data)),
        (*REGISTERS, "current_offset", "sprite_data", "collision_work"),
    )


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),
                    reason="build artifacts missing")
def test_detect_collision_between_sprites_offscreen_peer_pathwise_equivalence() -> None:
    values = {register: claripy.BVV(0, 8) for register in REGISTERS}
    sprite_data = bytearray(256)
    sprite_data[0] = 1
    sprite_data[0x10] = 1
    sprite_data[0x12] = 0xff
    assert_pathwise_equivalent(
        _assembly(values, bytes(sprite_data)), _native(values, bytes(sprite_data)),
        (*REGISTERS, "current_offset", "sprite_data", "collision_work"),
    )


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),
                    reason="build artifacts missing")
def test_detect_collision_between_sprites_visible_peer_pathwise_equivalence() -> None:
    values = {register: claripy.BVV(0, 8) for register in REGISTERS}
    sprite_data = bytearray(256)
    sprite_data[0] = 1
    sprite_data[0x10] = 1
    assert_pathwise_equivalent(
        _assembly(values, bytes(sprite_data)), _native(values, bytes(sprite_data)),
        (*REGISTERS, "current_offset", "sprite_data", "collision_work"),
    )


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),
                    reason="build artifacts missing")
def test_detect_collision_between_sprites_multiple_peers_pathwise_equivalence() -> None:
    """Collision bits and direction data accumulate across peer iterations."""
    values = {register: claripy.BVV(0, 8) for register in REGISTERS}
    sprite_data = bytearray(256)
    sprite_data[0] = 1
    sprite_data[0x10] = 1
    sprite_data[0x20] = 1
    sprite_data[0x90] = 1
    assert_pathwise_equivalent(
        _assembly(values, bytes(sprite_data)), _native(values, bytes(sprite_data)),
        (*REGISTERS, "current_offset", "sprite_data", "collision_work"),
    )


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),
                    reason="build artifacts missing")
def test_detect_collision_between_sprites_symbolic_y_step_pathwise_equivalence() -> None:
    """Exhaust Y-direction handling for one visible peer.

    The remaining 15 slots are concretely unused, so the linked assembly still
    completes its full 16-slot loop without creating unrelated peer paths.
    """
    values = symbolic_registers("detect_collision_single_peer")
    sprite_data = bytearray(256)
    sprite_data[0] = 1
    sprite_data[0x10] = 1
    overrides = {
        offset: claripy.BVS(f"detect_collision_single_peer_data_{offset}", 8)
        for offset in (3, 0x13)
    }
    assert_pathwise_equivalent(
        _assembly(values, bytes(sprite_data), overrides=overrides),
        _native(values, bytes(sprite_data), overrides=overrides),
        (*REGISTERS, "current_offset", "sprite_data", "collision_work"),
    )


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),
                    reason="build artifacts missing")
def test_detect_collision_between_sprites_symbolic_x_step_pathwise_equivalence() -> None:
    """Exhaust X-direction handling for one visible peer."""
    values = symbolic_registers("detect_collision_single_peer_x")
    sprite_data = bytearray(256)
    sprite_data[0] = 1
    sprite_data[0x10] = 1
    overrides = {
        offset: claripy.BVS(f"detect_collision_single_peer_x_data_{offset}", 8)
        for offset in (5, 0x15)
    }
    assert_pathwise_equivalent(
        _assembly(values, bytes(sprite_data), overrides=overrides),
        _native(values, bytes(sprite_data), overrides=overrides),
        (*REGISTERS, "current_offset", "sprite_data", "collision_work"),
    )


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),
                    reason="build artifacts missing")
def test_detect_collision_between_sprites_symbolic_y_pixels_pathwise_equivalence() -> None:
    """Exhaust vertical distance handling for one stationary visible peer."""
    values = symbolic_registers("detect_collision_single_peer_y_pixels")
    sprite_data = bytearray(256)
    sprite_data[0] = 1
    sprite_data[0x10] = 1
    overrides = {
        offset: claripy.BVS(f"detect_collision_single_peer_y_pixels_data_{offset}", 8)
        for offset in (4, 0x14)
    }
    assert_pathwise_equivalent(
        _assembly(values, bytes(sprite_data), overrides=overrides),
        _native(values, bytes(sprite_data), overrides=overrides),
        (*REGISTERS, "current_offset", "sprite_data", "collision_work"),
    )


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),
                    reason="build artifacts missing")
def test_detect_collision_between_sprites_symbolic_x_pixels_pathwise_equivalence() -> None:
    """Exhaust horizontal distance handling for one stationary visible peer."""
    values = symbolic_registers("detect_collision_single_peer_x_pixels")
    sprite_data = bytearray(256)
    sprite_data[0] = 1
    sprite_data[0x10] = 1
    overrides = {
        offset: claripy.BVS(f"detect_collision_single_peer_x_pixels_data_{offset}", 8)
        for offset in (6, 0x16)
    }
    assert_pathwise_equivalent(
        _assembly(values, bytes(sprite_data), overrides=overrides),
        _native(values, bytes(sprite_data), overrides=overrides),
        (*REGISTERS, "current_offset", "sprite_data", "collision_work"),
    )


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),
                    reason="build artifacts missing")
@pytest.mark.parametrize(
    ("current_offset", "peer_offset", "current_step", "peer_step", "current_y", "peer_y"),
    [
        (0x00, 0x10, 0x00, 0x00, 0x00, 0x20),  # Y distance rejects the peer.
        (0x00, 0x10, 0x01, 0xff, 0x00, 0x00),  # Opposing vertical movement.
        (0x00, 0x80, 0x00, 0x00, 0x00, 0x00),  # High collision-bit byte.
        (0x20, 0x70, 0xff, 0x01, 0x10, 0x10),  # Nonzero current slot.
    ],
)
def test_detect_collision_between_sprites_additional_pathwise_equivalence(
    current_offset: int, peer_offset: int, current_step: int, peer_step: int,
    current_y: int, peer_y: int,
) -> None:
    values = {register: claripy.BVV(0, 8) for register in REGISTERS}
    sprite_data = bytearray(256)
    sprite_data[current_offset] = 1
    sprite_data[current_offset + 3] = current_step
    sprite_data[current_offset + 4] = current_y
    sprite_data[peer_offset] = 1
    sprite_data[peer_offset + 3] = peer_step
    sprite_data[peer_offset + 4] = peer_y
    assert_pathwise_equivalent(
        _assembly(values, bytes(sprite_data), current_offset),
        _native(values, bytes(sprite_data), current_offset),
        (*REGISTERS, "current_offset", "sprite_data", "collision_work"),
    )
