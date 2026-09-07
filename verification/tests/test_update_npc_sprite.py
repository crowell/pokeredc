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
from verification.harness.registers import sm83_flags_to_z80
from verification.harness.sm83_shims import (
    Sm83AddHlRegisterPair, Sm83BitRegister, Sm83CpImmediate, Sm83DecAtHl,
    Sm83DecRegister, Sm83IncRegister, Sm83ResAtHl,
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
MAP_SPRITE_MOVEMENT2 = 0xd4e2
CUR_MOVEMENT2 = 0xcf14
OFFSET = 0xffda
HIDDEN = 0xffe5
TOGGLE_LIST = 0xd5ce
TOGGLE_FLAGS = 0xd5a6
FONT = 0xcfc4
WALK_COUNTER = 0xcfc5
SCRIPTED_STEPS = 0xcf0f
DIRECTIONS = 0xcc5b
STATUS5 = 0xd730
STATUS3 = 0xd72d
PLAYER_DIRECTION = 0xd52a
PLAYER_TILE = 0xff93
SIMULATED_INDEX = 0xcd38
OVERRIDE_INDEX = 0xcd3a
TRACE = 0xef00
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
    def __init__(self, next_address: int, increment: bool = False) -> None:
        super().__init__(); self.next_address = next_address; self.increment = increment
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self.state.regs.hl, 1)
        if self.increment: self.state.regs.hl += 1
        self.jump(self.next_address)


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


class BranchFlag(angr.SimProcedure):
    def __init__(self, mask: int, taken_when_set: bool, taken: int, fallthrough: int) -> None:
        super().__init__(); self.mask = mask; self.taken_when_set = taken_when_set; self.taken = taken; self.fallthrough = fallthrough
    def run(self) -> None:  # type: ignore[override]
        condition = (self.state.regs.f & self.mask) != 0
        if not self.taken_when_set:
            condition = ~condition
        yes = self.state.copy(); no = self.state.copy(); yes.solver.add(condition); no.solver.add(~condition)
        yes.regs.ip = claripy.BVV(self.taken, 16); no.regs.ip = claripy.BVV(self.fallthrough, 16); self.inhibit_autoret = True
        self.successors.add_successor(yes, self.taken, condition, "Ijk_Boring"); self.successors.add_successor(no, self.fallthrough, ~condition, "Ijk_Boring")


class LoadAbsoluteA(angr.SimProcedure):
    def __init__(self, address: int, next_address: int) -> None: super().__init__(); self.address = address; self.next_address = next_address
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self.address, 1); self.jump(self.next_address)


class StoreAtHL(angr.SimProcedure):
    def __init__(self, value: int | str | None, next_address: int) -> None: super().__init__(); self.value = value; self.next_address = next_address
    def run(self) -> None:  # type: ignore[override]
        value = self.state.regs.a if self.value is None else getattr(self.state.regs, self.value) if isinstance(self.value, str) else claripy.BVV(self.value, 8)
        self.state.memory.store(self.state.regs.hl, value); self.jump(self.next_address)


class PushHL(angr.SimProcedure):
    def __init__(self, next_address: int) -> None: super().__init__(); self.next_address = next_address
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.sp -= 2; self.state.memory.store(self.state.regs.sp, self.state.regs.hl, endness="Iend_LE"); self.jump(self.next_address)


class PopHL(angr.SimProcedure):
    def __init__(self, next_address: int) -> None: super().__init__(); self.next_address = next_address
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.hl = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE"); self.state.regs.sp += 2; self.jump(self.next_address)


class RegisterBoundary(angr.SimProcedure):
    def __init__(self, values: dict[str, claripy.ast.BV], next_address: int, kind: int) -> None:
        super().__init__(); self.values = values; self.next_address = next_address; self.kind = kind
    def run(self) -> None:  # type: ignore[override]
        offset = self.state.memory.load(OFFSET, 1)
        for register in REGISTERS:
            value = self.values[register]
            if register == "f": value = sm83_flags_to_z80(value)
            setattr(self.state.regs, register, value)
        if self.kind == 1:
            self.state.memory.store(S1 + offset + 2, self.values["image"])
            self.state.memory.store(S2 + offset + 7, self.values["grass"])
        else:
            self.state.memory.store(S1 + offset + 4, self.values["screen_y"])
            self.state.memory.store(S1 + offset + 6, self.values["screen_x"])
        self.state.memory.store(TRACE + self.kind, claripy.BVV(self.kind, 8)); self.jump(self.next_address)


class NativeRegisterBoundary(angr.SimProcedure):
    def __init__(self, values: dict[str, claripy.ast.BV], kind: int) -> None:
        super().__init__(); self.values = values; self.kind = kind
    def run(self, pointer: claripy.ast.BV, memory: claripy.ast.BV | None = None) -> None:  # type: ignore[override]
        for index, register in enumerate(REGISTERS): self.state.memory.store(pointer + index, self.values[register])
        offset = self.state.memory.load(NM + OFFSET, 1)
        if self.kind == 1:
            self.state.memory.store(NM + S1 + offset + 2, self.values["image"])
            self.state.memory.store(NM + S2 + offset + 7, self.values["grass"])
        else:
            self.state.memory.store(pointer + 13, self.values["screen_y"])
            self.state.memory.store(pointer + 14, self.values["screen_x"])
        self.state.memory.store(NM + TRACE + self.kind, claripy.BVV(self.kind, 8))


class ComputedLoadBoundary(angr.SimProcedure):
    def __init__(self, next_address: int, native: bool) -> None: super().__init__(); self.next_address = next_address; self.native = native
    def run(self, pointer: claripy.ast.BV | None = None) -> None:  # type: ignore[override]
        base = NM if self.native else 0
        p = (pointer if pointer is not None else self.state.regs.rdi) if self.native else None
        def get(register: str) -> claripy.ast.BV:
            return self.state.memory.load(p + REGISTERS.index(register), 1) if self.native else getattr(self.state.regs, register)
        a = get("a"); e = get("e"); d = get("d"); wide = claripy.ZeroExt(1, a) + claripy.ZeroExt(1, e); result = wide[7:0]
        flags = claripy.If(result == 0, claripy.BVV(0x80 if self.native else 0x40, 8), claripy.BVV(0, 8)) | claripy.If((a & 15) + (e & 15) > 15, claripy.BVV(0x20 if self.native else 0x10, 8), claripy.BVV(0, 8)) | claripy.If(wide[8] == 1, claripy.BVV(0x10 if self.native else 1, 8), claripy.BVV(0, 8))
        carried_d = d + 1
        carried_flags = claripy.BVV(0x10 if self.native else 1, 8) | claripy.If(carried_d == 0, claripy.BVV(0x80 if self.native else 0x40, 8), claripy.BVV(0, 8)) | claripy.If((d & 15) == 15, claripy.BVV(0x20 if self.native else 0x10, 8), claripy.BVV(0, 8))
        final_d = claripy.If(wide[8] == 1, carried_d, d); final_flags = claripy.If(wide[8] == 1, carried_flags, flags)
        address_value = claripy.Concat(final_d, result)
        if self.native:
            address_value = claripy.ZeroExt(48, address_value)
        fetched = self.state.memory.load(base + address_value, 1)
        if self.native:
            for register, value in (("a", fetched), ("f", final_flags), ("d", final_d), ("e", result)): self.state.memory.store(p + REGISTERS.index(register), value)
            count = self.state.memory.load(NM + TRACE, 1); self.state.memory.store(NM + TRACE, count + 1)
        else:
            self.state.regs.a = fetched; self.state.regs.f = final_flags; self.state.regs.d = final_d; self.state.regs.e = result
            count = self.state.memory.load(TRACE, 1); self.state.memory.store(TRACE, count + 1); self.jump(self.next_address)


class TerminalBoundary(angr.SimProcedure):
    def __init__(self, native: bool) -> None: super().__init__(); self.native = native
    def run(self, registers: claripy.ast.BV | None = None, memory: claripy.ast.BV | None = None) -> None:  # type: ignore[override]
        self.state.memory.store((NM if self.native else 0) + TRACE + 3, claripy.BVV(3, 8))
        if not self.native: self.jump(RET)


class PairTo(angr.SimProcedure):
    def __init__(self, pair: str, value: int, next_address: int) -> None: super().__init__(); self.pair = pair; self.value = value; self.next_address = next_address
    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.pair, claripy.BVV(self.value, 16)); self.jump(self.next_address)


class Jump(angr.SimProcedure):
    def __init__(self, next_address: int) -> None: super().__init__(); self.next_address = next_address
    def run(self) -> None:  # type: ignore[override]
        self.jump(self.next_address)


class XorA(angr.SimProcedure):
    def __init__(self, next_address: int) -> None: super().__init__(); self.next_address = next_address
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8); self.state.regs.f = claripy.BVV(0x40, 8); self.jump(self.next_address)


class ReturnTo(angr.SimProcedure):
    def __init__(self, target: int) -> None: super().__init__(); self.target = target
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.sp += 2; self.jump(self.target)


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


def scripted_reload_setup(
    state: angr.SimState, base: int, offset: int,
    check: dict[str, claripy.ast.BV], init: dict[str, claripy.ast.BV],
    first_direction: int = 0xFE,
    walk_counter: int | claripy.ast.BV = 0,
    movement_status: int | claripy.ast.BV = 1,
    face: dict[str, claripy.ast.BV] | None = None,
    font: int | claripy.ast.BV = 0,
    movement_byte: int | claripy.ast.BV = 0x20,
    movement_delay: int | claripy.ast.BV = 0,
) -> None:
    for address in (*range(S1, S1 + 0x100), *range(S2, S2 + 0x100)):
        state.memory.store(base + address, claripy.BVV(0, 8))
    movement2_address = 0xD400 | ((0xE4 + 2 * (((offset >> 4) - 1) & 0xFF)) & 0xFF)
    for address, value in (
        (OFFSET, offset), (movement2_address, 0xD0), (CUR_MOVEMENT2, 0),
        (S1 + offset + 1, movement_status), (S1 + offset + 2, 0x22),
        (S1 + offset + 4, 0x30), (S1 + offset + 6, 0x40),
        (S1 + offset + 8, 0 if face is None else face["animation"]),
        (S1 + offset + 9, 0 if face is None else face["facing"]),
        (S2 + offset + 4, 7), (S2 + offset + 5, 9),
        (S2 + offset + 6, movement_byte), (S2 + offset + 7, 0),
        (S2 + offset + 8, movement_delay),
        (FONT, font), (WALK_COUNTER, walk_counter), (SCRIPTED_STEPS, 5),
        (0xD361, 4), (0xD362, 6),
        (DIRECTIONS + 0x20, first_direction), (DIRECTIONS + 0xFE, 0x55),
        (STATUS3, 0 if face is None else face["status"]),
        (PLAYER_DIRECTION, 0 if face is None else face["direction"]),
        (PLAYER_TILE, 0 if face is None else face["tile"]),
        (STATUS5, 0xFF), (SIMULATED_INDEX, 0x66), (OVERRIDE_INDEX, 0x77),
        (TRACE, 0), (TRACE + 1, 0), (TRACE + 2, 0), (TRACE + 3, 0),
    ):
        state.memory.store(base + address, value if isinstance(value, claripy.ast.BV) else claripy.BVV(value, 8))
    state.memory.store(base + S1 + offset + 2, check["image"])
    state.memory.store(base + S2 + offset + 7, check["grass"])
    state.memory.store(base + S1 + offset + 4, init["screen_y"])
    state.memory.store(base + S1 + offset + 6, init["screen_x"])


def scripted_reload_endpoint(state: angr.SimState, native_side: bool, offset: int) -> E:
    base = NM if native_side else 0
    registers = native_registers(state, NS) if native_side else assembly_registers(state)
    watched = (
        *range(S1 + offset, S1 + offset + 16),
        *range(S2 + offset, S2 + offset + 16),
        CUR_MOVEMENT2, OFFSET, FONT, WALK_COUNTER, SCRIPTED_STEPS,
        DIRECTIONS + 0x20, DIRECTIONS + 0xFE, STATUS5,
        STATUS3, PLAYER_DIRECTION, PLAYER_TILE,
        SIMULATED_INDEX, OVERRIDE_INDEX, TRACE, TRACE + 1, TRACE + 2, TRACE + 3,
    )
    return E(**registers, state=claripy.Concat(*(state.memory.load(base + address, 1) for address in watched)), constraints=tuple(state.solver.constraints))


def scripted_reload_assembly(
    values: dict[str, claripy.ast.BV], offset: int,
    check: dict[str, claripy.ast.BV], init: dict[str, claripy.ast.BV],
    first_direction: int = 0xFE,
    walk_counter: int | claripy.ast.BV = 0,
    movement_status: int | claripy.ast.BV = 1,
    face: dict[str, claripy.ast.BV] | None = None,
    font: int | claripy.ast.BV = 0,
    movement_byte: int | claripy.ast.BV = 0x20,
    movement_delay: int | claripy.ast.BV = 0,
) -> list[E]:
    location = symbol_location(SYMBOLS, "UpdateNPCSprite")
    assert linked_bytes(ROM, location, len(BODY)) == BODY
    project = angr.Project(rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100, main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0, "entry_point": location.address})
    q = location.address
    project.hook(q, LoadHighA(OFFSET, q + 2), length=2); project.hook(q + 2, SwapA(q + 4), length=2)
    project.hook(q + 4, DecA(q + 5), length=1); project.hook(q + 5, AddA("a", q + 6), length=1)
    project.hook(q + 6, Pair(0xd4e4, q + 9), length=3); project.hook(q + 9, AddA("l", q + 10), length=1)
    project.hook(q + 10, Reg("l", "a", q + 11), length=1); project.hook(q + 11, LoadAtHL(q + 12), length=1)
    project.hook(q + 12, StoreAbsoluteA(CUR_MOVEMENT2, q + 15), length=3); project.hook(q + 15, Imm("h", 0xc1, q + 17), length=2)
    project.hook(q + 17, LoadHighA(OFFSET, q + 19), length=2); project.hook(q + 19, Reg("l", "a", q + 20), length=1)
    project.hook(q + 20, IncL(q + 21), length=1); project.hook(q + 21, LoadAtHL(q + 22), length=1)
    project.hook(q + 22, AndA(q + 23), length=1); project.hook(q + 23, BranchZero(0x50ad, q + 26), length=3)
    project.hook(q + 26, RegisterBoundary(check, q + 29, 1), length=3)
    project.hook(q + 29, BranchFlag(1, True, RET, q + 30), length=1)
    project.hook(q + 30, Imm("h", 0xc1, q + 32), length=2); project.hook(q + 32, LoadHighA(OFFSET, q + 34), length=2)
    project.hook(q + 34, Reg("l", "a", q + 35), length=1); project.hook(q + 35, IncL(q + 36), length=1)
    project.hook(q + 36, LoadAtHL(q + 37), length=1); project.hook(q + 37, Sm83BitRegister(7, "a", q + 39), length=2)
    project.hook(q + 39, BranchFlag(0x40, False, 0x507f, q + 42), length=3); project.hook(q + 42, Reg("b", "a", q + 43), length=1)
    project.hook(q + 43, LoadAbsoluteA(FONT, q + 46), length=3); project.hook(q + 46, Sm83BitRegister(0, "a", q + 48), length=2)
    project.hook(q + 48, BranchFlag(0x40, False, 0x5073, q + 51), length=3); project.hook(q + 51, Reg("a", "b", q + 52), length=1)
    project.hook(q + 52, Sm83CpImmediate(2, q + 54), length=2); project.hook(q + 54, BranchFlag(0x40, True, 0x5057, q + 57), length=3)
    project.hook(q + 57, Sm83CpImmediate(3, q + 59), length=2); project.hook(q + 59, BranchFlag(0x40, True, 0x4ffe, q + 62), length=3)
    project.hook(q + 62, LoadAbsoluteA(WALK_COUNTER, q + 65), length=3); project.hook(q + 65, AndA(q + 66), length=1)
    project.hook(q + 66, BranchFlag(0x40, False, RET, q + 67), length=1); project.hook(q + 67, RegisterBoundary(init, q + 70, 2), length=3)
    project.hook(q + 70, Imm("h", 0xc2, q + 72), length=2); project.hook(q + 72, LoadHighA(OFFSET, q + 74), length=2)
    project.hook(q + 74, AddA(6, q + 76), length=2); project.hook(q + 76, Reg("l", "a", q + 77), length=1)
    project.hook(q + 77, LoadAtHL(q + 78), length=1); project.hook(q + 78, Sm83IncRegister("a", q + 79), length=1)
    project.hook(q + 79, BranchFlag(0x40, True, q + 136, q + 81), length=2); project.hook(q + 81, Sm83IncRegister("a", q + 82), length=1)
    project.hook(q + 82, BranchFlag(0x40, True, q + 136, q + 84), length=2); project.hook(q + 84, Sm83DecRegister("a", q + 85), length=1)
    project.hook(q + 85, StoreAtHL(None, q + 86), length=1); project.hook(q + 86, Sm83DecRegister("a", q + 87), length=1)
    project.hook(q + 87, PushHL(q + 88), length=1); project.hook(q + 88, Pair(SCRIPTED_STEPS, q + 91), length=3)
    project.hook(q + 91, Sm83DecAtHl(q + 92), length=1); project.hook(q + 92, PopHL(q + 93), length=1)
    project.hook(q + 93, PairTo("de", DIRECTIONS, q + 96), length=3); project.hook(q + 96, ComputedLoadBoundary(q + 99, False), length=3)
    project.hook(q + 99, Sm83CpImmediate(0xe0, q + 101), length=2); project.hook(q + 101, BranchFlag(0x40, True, 0x4fc8, q + 104), length=3)
    project.hook(q + 104, Sm83CpImmediate(0xff, q + 106), length=2); project.hook(q + 106, BranchFlag(0x40, False, q + 122, q + 108), length=2)
    project.hook(q + 108, StoreAtHL(None, q + 109), length=1); project.hook(q + 109, Pair(STATUS5, q + 112), length=3)
    project.hook(q + 112, Sm83ResAtHl(0, q + 114), length=2); project.hook(q + 114, XorA(q + 115), length=1)
    project.hook(q + 115, StoreAbsoluteA(SIMULATED_INDEX, q + 118), length=3); project.hook(q + 118, StoreAbsoluteA(OVERRIDE_INDEX, q + 121), length=3)
    project.hook(q + 121, ReturnTo(RET), length=1)
    project.hook(q + 122, Sm83CpImmediate(0xfe, q + 124), length=2); project.hook(q + 124, BranchFlag(0x40, False, q + 142, q + 126), length=2)
    project.hook(q + 126, StoreAtHL(1, q + 128), length=2); project.hook(q + 128, PairTo("de", DIRECTIONS, q + 131), length=3)
    project.hook(q + 131, ComputedLoadBoundary(q + 134, False), length=3); project.hook(q + 134, Jump(q + 142), length=2)
    project.hook(q + 142, Reg("b", "a", q + 143), length=1); project.hook(q + 143, LoadAbsoluteA(CUR_MOVEMENT2, q + 146), length=3)
    project.hook(q + 146, Sm83CpImmediate(0xd0, q + 148), length=2); project.hook(q + 148, BranchFlag(0x40, True, q + 174, q + 150), length=2)
    project.hook(q + 174, PairTo("de", 40, q + 177), length=3); project.hook(q + 177, Sm83AddHlRegisterPair("de", q + 178), length=1)
    project.hook(q + 178, PairTo("de", 0x0100, q + 181), length=3); project.hook(q + 181, PairTo("bc", 0x0400, q + 184), length=3)
    project.hook(q + 184, TerminalBoundary(False), length=2)
    make_face = symbol_location(SYMBOLS, "MakeNPCFacePlayer"); not_yet = symbol_location(SYMBOLS, "NotYetMoving"); update = symbol_location(SYMBOLS, "UpdateSpriteImage")
    assert linked_bytes(ROM, make_face, 46) == bytes.fromhex("fa2dd7cb6f20edcbbefa2ad5cb5f28040e001812cb5728040e04180acb4f28040e0c18020e08f0dac6096f7118c6")
    assert linked_bytes(ROM, not_yet, 12) == bytes.fromhex("26c1f0dac6086f3600c35751")
    assert linked_bytes(ROM, update, 23) == bytes.fromhex("26c1f0dac6086f2a477e8047f0938047f0dac6026f70c9")
    qf = make_face.address
    project.hook(qf, LoadAbsoluteA(STATUS3, qf + 3), length=3); project.hook(qf + 3, Sm83BitRegister(5, "a", qf + 5), length=2)
    project.hook(qf + 7, Sm83ResAtHl(7, qf + 9), length=2); project.hook(qf + 9, LoadAbsoluteA(PLAYER_DIRECTION, qf + 12), length=3)
    project.hook(qf + 12, Sm83BitRegister(3, "a", qf + 14), length=2); project.hook(qf + 20, Sm83BitRegister(2, "a", qf + 22), length=2)
    project.hook(qf + 28, Sm83BitRegister(1, "a", qf + 30), length=2); project.hook(qf + 38, LoadHighA(OFFSET, qf + 40), length=2)
    project.hook(qf + 40, AddA(9, qf + 42), length=2); project.hook(qf + 43, StoreAtHL("c", qf + 44), length=1)
    qn = not_yet.address
    project.hook(qn + 2, LoadHighA(OFFSET, qn + 4), length=2); project.hook(qn + 4, AddA(8, qn + 6), length=2)
    project.hook(qn + 7, StoreAtHL(0, qn + 9), length=2)
    qu = update.address
    project.hook(qu + 2, LoadHighA(OFFSET, qu + 4), length=2); project.hook(qu + 4, AddA(8, qu + 6), length=2)
    project.hook(qu + 7, LoadAtHL(qu + 8, increment=True), length=1); project.hook(qu + 9, LoadAtHL(qu + 10), length=1)
    project.hook(qu + 10, AddA("b", qu + 11), length=1); project.hook(qu + 12, LoadHighA(PLAYER_TILE, qu + 14), length=2)
    project.hook(qu + 14, AddA("b", qu + 15), length=1); project.hook(qu + 16, LoadHighA(OFFSET, qu + 18), length=2)
    project.hook(qu + 18, AddA(2, qu + 20), length=2); project.hook(qu + 21, StoreAtHL("b", qu + 22), length=1)
    delay = symbol_location(SYMBOLS, "UpdateSpriteMovementDelay")
    assert linked_bytes(ROM, delay, 40) == bytes.fromhex("26c2f0dac6066f7e2c2cfefe30043600180335200725f0da3c6f360126c1f0dac6086f3600c35751")
    qd = delay.address
    project.hook(qd + 2, LoadHighA(OFFSET, qd + 4), length=2); project.hook(qd + 4, AddA(6, qd + 6), length=2)
    project.hook(qd + 7, LoadAtHL(qd + 8), length=1); project.hook(qd + 10, Sm83CpImmediate(0xfe, qd + 12), length=2)
    project.hook(qd + 12, BranchFlag(1, False, qd + 18, qd + 14), length=2); project.hook(qd + 14, StoreAtHL(0, qd + 16), length=2)
    project.hook(qd + 16, Jump(qd + 21), length=2); project.hook(qd + 18, Sm83DecAtHl(qd + 19), length=1)
    project.hook(qd + 19, BranchFlag(0x40, False, qd + 28, qd + 21), length=2); project.hook(qd + 21, Sm83DecRegister("h", qd + 22), length=1)
    project.hook(qd + 22, LoadHighA(OFFSET, qd + 24), length=2); project.hook(qd + 24, Sm83IncRegister("a", qd + 25), length=1)
    project.hook(qd + 25, Reg("l", "a", qd + 26), length=1); project.hook(qd + 26, StoreAtHL(1, qd + 28), length=2)
    state = project.factory.blank_state(addr=q); set_assembly_registers(state, values); scripted_reload_setup(state, 0, offset, check, init, first_direction, walk_counter, movement_status, face, font, movement_byte, movement_delay)
    if isinstance(walk_counter, claripy.ast.BV): state.solver.add(walk_counter != 0)
    if isinstance(movement_status, claripy.ast.BV): state.solver.add((movement_status & 0x80) != 0)
    if isinstance(font, claripy.ast.BV): state.solver.add((font & 1) != 0)
    state.regs.sp = claripy.BVV(STACK, 16); state.memory.store(STACK, claripy.BVV(RET, 16), endness="Iend_LE")
    manager = project.factory.simulation_manager(state); manager.explore(find=RET, num_find=8)
    assert not manager.errored and manager.found
    return [scripted_reload_endpoint(item, False, offset) for item in manager.found]


def scripted_reload_native(
    values: dict[str, claripy.ast.BV], offset: int,
    check: dict[str, claripy.ast.BV], init: dict[str, claripy.ast.BV],
    first_direction: int = 0xFE,
    walk_counter: int | claripy.ast.BV = 0,
    movement_status: int | claripy.ast.BV = 1,
    face: dict[str, claripy.ast.BV] | None = None,
    font: int | claripy.ast.BV = 0,
    movement_byte: int | claripy.ast.BV = 0x20,
    movement_delay: int | claripy.ast.BV = 0,
) -> list[E]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_update_npc_sprite"); availability = project.loader.find_symbol("port_check_sprite_availability")
    initialize = project.loader.find_symbol("port_initialize_sprite_screen_position"); load = project.loader.find_symbol("port_load_de_plus_a"); walking = project.loader.find_symbol("port_try_walking")
    assert function and availability and initialize and load and walking
    project.hook(availability.rebased_addr, NativeRegisterBoundary(check, 1)); project.hook(initialize.rebased_addr, NativeRegisterBoundary(init, 2))
    project.hook(load.rebased_addr, ComputedLoadBoundary(0, True)); project.hook(walking.rebased_addr, TerminalBoundary(True))
    state = project.factory.call_state(function.rebased_addr, NS, NM); store_native_registers(state, NS, values); scripted_reload_setup(state, NM, offset, check, init, first_direction, walk_counter, movement_status, face, font, movement_byte, movement_delay)
    if isinstance(walk_counter, claripy.ast.BV): state.solver.add(walk_counter != 0)
    if isinstance(movement_status, claripy.ast.BV): state.solver.add((movement_status & 0x80) != 0)
    if isinstance(font, claripy.ast.BV): state.solver.add((font & 1) != 0)
    manager = project.factory.simulation_manager(state); manager.run(); assert not manager.errored and manager.deadended
    return [scripted_reload_endpoint(item, True, offset) for item in manager.deadended]


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(), reason="build artifacts missing")
@pytest.mark.parametrize("offset", range(0, 0x100, 0x10))
def test_update_npc_sprite_scripted_walk_reload_pathwise_equivalence(offset: int) -> None:
    values = symbolic_registers(f"update_npc_scripted_reload_{offset:02x}")
    check = symbolic_registers(f"update_npc_scripted_reload_{offset:02x}_check")
    check["f"] = claripy.Concat(claripy.BVS(f"update_npc_scripted_reload_{offset:02x}_check_znh", 3), claripy.BVV(0, 5))
    check["image"] = claripy.BVS(f"update_npc_scripted_reload_{offset:02x}_image", 8); check["grass"] = claripy.BVS(f"update_npc_scripted_reload_{offset:02x}_grass", 8)
    init = symbolic_registers(f"update_npc_scripted_reload_{offset:02x}_init")
    init["screen_y"] = claripy.BVS(f"update_npc_scripted_reload_{offset:02x}_screen_y", 8); init["screen_x"] = claripy.BVS(f"update_npc_scripted_reload_{offset:02x}_screen_x", 8)
    assert_pathwise_equivalent(scripted_reload_assembly(values, offset, check, init), scripted_reload_native(values, offset, check, init), (*REGISTERS, "state"))


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(), reason="build artifacts missing")
@pytest.mark.parametrize("offset", range(0, 0x100, 0x10))
def test_update_npc_sprite_scripted_end_pathwise_equivalence(offset: int) -> None:
    values = symbolic_registers(f"update_npc_scripted_end_{offset:02x}")
    check = symbolic_registers(f"update_npc_scripted_end_{offset:02x}_check")
    check["f"] = claripy.Concat(claripy.BVS(f"update_npc_scripted_end_{offset:02x}_check_znh", 3), claripy.BVV(0, 5))
    check["image"] = claripy.BVS(f"update_npc_scripted_end_{offset:02x}_image", 8); check["grass"] = claripy.BVS(f"update_npc_scripted_end_{offset:02x}_grass", 8)
    init = symbolic_registers(f"update_npc_scripted_end_{offset:02x}_init")
    init["screen_y"] = claripy.BVS(f"update_npc_scripted_end_{offset:02x}_screen_y", 8); init["screen_x"] = claripy.BVS(f"update_npc_scripted_end_{offset:02x}_screen_x", 8)
    assert_pathwise_equivalent(scripted_reload_assembly(values, offset, check, init, 0xFF), scripted_reload_native(values, offset, check, init, 0xFF), (*REGISTERS, "state"))


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(), reason="build artifacts missing")
@pytest.mark.parametrize("offset", range(0, 0x100, 0x10))
def test_update_npc_sprite_player_walking_pathwise_equivalence(offset: int) -> None:
    values = symbolic_registers(f"update_npc_player_walking_{offset:02x}")
    check = symbolic_registers(f"update_npc_player_walking_{offset:02x}_check")
    check["f"] = claripy.Concat(claripy.BVS(f"update_npc_player_walking_{offset:02x}_check_znh", 3), claripy.BVV(0, 5))
    check["image"] = claripy.BVS(f"update_npc_player_walking_{offset:02x}_image", 8); check["grass"] = claripy.BVS(f"update_npc_player_walking_{offset:02x}_grass", 8)
    init = symbolic_registers(f"update_npc_player_walking_{offset:02x}_init")
    init["screen_y"] = claripy.BVS(f"update_npc_player_walking_{offset:02x}_screen_y", 8); init["screen_x"] = claripy.BVS(f"update_npc_player_walking_{offset:02x}_screen_x", 8)
    walk_counter = claripy.BVS(f"update_npc_player_walking_{offset:02x}_counter", 8)
    assembly_paths = scripted_reload_assembly(values, offset, check, init, walk_counter=walk_counter)
    native_paths = scripted_reload_native(values, offset, check, init, walk_counter=walk_counter)
    assert_pathwise_equivalent(assembly_paths, native_paths, (*REGISTERS, "state"))


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(), reason="build artifacts missing")
@pytest.mark.parametrize("offset", range(0, 0x100, 0x10))
def test_update_npc_sprite_face_player_pathwise_equivalence(offset: int) -> None:
    prefix = f"update_npc_face_player_{offset:02x}"
    values = symbolic_registers(prefix)
    check = symbolic_registers(f"{prefix}_check")
    check["f"] = claripy.Concat(claripy.BVS(f"{prefix}_check_znh", 3), claripy.BVV(0, 5))
    check["image"] = claripy.BVS(f"{prefix}_image", 8); check["grass"] = claripy.BVS(f"{prefix}_grass", 8)
    init = symbolic_registers(f"{prefix}_init")
    init["screen_y"] = claripy.BVS(f"{prefix}_screen_y", 8); init["screen_x"] = claripy.BVS(f"{prefix}_screen_x", 8)
    movement_status = claripy.BVS(f"{prefix}_movement_status", 8)
    face = {name: claripy.BVS(f"{prefix}_{name}", 8) for name in ("status", "direction", "tile", "animation", "facing")}
    assembly_paths = scripted_reload_assembly(values, offset, check, init, movement_status=movement_status, face=face)
    native_paths = scripted_reload_native(values, offset, check, init, movement_status=movement_status, face=face)
    assert len(assembly_paths) == 5
    assert len(native_paths) >= 5
    assert_pathwise_equivalent(assembly_paths, native_paths, (*REGISTERS, "state"))


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(), reason="build artifacts missing")
@pytest.mark.parametrize("offset", range(0, 0x100, 0x10))
def test_update_npc_sprite_font_loaded_pathwise_equivalence(offset: int) -> None:
    prefix = f"update_npc_font_loaded_{offset:02x}"
    values = symbolic_registers(prefix)
    check = symbolic_registers(f"{prefix}_check")
    check["f"] = claripy.Concat(claripy.BVS(f"{prefix}_check_znh", 3), claripy.BVV(0, 5))
    check["image"] = claripy.BVS(f"{prefix}_image", 8); check["grass"] = claripy.BVS(f"{prefix}_grass", 8)
    init = symbolic_registers(f"{prefix}_init")
    init["screen_y"] = claripy.BVS(f"{prefix}_screen_y", 8); init["screen_x"] = claripy.BVS(f"{prefix}_screen_x", 8)
    face = {name: claripy.BVS(f"{prefix}_{name}", 8) for name in ("status", "direction", "tile", "animation", "facing")}
    font = claripy.BVS(f"{prefix}_font", 8)
    assembly_paths = scripted_reload_assembly(values, offset, check, init, face=face, font=font)
    native_paths = scripted_reload_native(values, offset, check, init, face=face, font=font)
    assert_pathwise_equivalent(assembly_paths, native_paths, (*REGISTERS, "state"))


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(), reason="build artifacts missing")
@pytest.mark.parametrize("offset", range(0, 0x100, 0x10))
def test_update_npc_sprite_movement_delay_pathwise_equivalence(offset: int) -> None:
    prefix = f"update_npc_movement_delay_{offset:02x}"
    values = symbolic_registers(prefix)
    check = symbolic_registers(f"{prefix}_check")
    check["f"] = claripy.Concat(claripy.BVS(f"{prefix}_check_znh", 3), claripy.BVV(0, 5))
    check["image"] = claripy.BVS(f"{prefix}_image", 8); check["grass"] = claripy.BVS(f"{prefix}_grass", 8)
    init = symbolic_registers(f"{prefix}_init")
    init["screen_y"] = claripy.BVS(f"{prefix}_screen_y", 8); init["screen_x"] = claripy.BVS(f"{prefix}_screen_x", 8)
    face = {name: claripy.BVS(f"{prefix}_{name}", 8) for name in ("status", "direction", "tile", "animation", "facing")}
    movement_byte = claripy.BVS(f"{prefix}_movement_byte", 8)
    movement_delay = claripy.BVS(f"{prefix}_movement_delay", 8)
    assembly_paths = scripted_reload_assembly(values, offset, check, init, movement_status=2, face=face, movement_byte=movement_byte, movement_delay=movement_delay)
    native_paths = scripted_reload_native(values, offset, check, init, movement_status=2, face=face, movement_byte=movement_byte, movement_delay=movement_delay)
    assert len(assembly_paths) == 3
    assert_pathwise_equivalent(assembly_paths, native_paths, (*REGISTERS, "state"))
