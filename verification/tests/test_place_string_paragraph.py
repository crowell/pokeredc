from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS, assembly_registers, native_registers, set_assembly_registers, store_native_registers, symbolic_registers
from verification.harness.rom import collect_returns, rom_window, sm83_flags_to_z80, symbol_location
from verification.harness.sm83_shims import Sm83StoreAImmediate

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMS = ROOT / "pokered.sym"
NS = 0x100000
NM = 0x200000
STACK = 0xD000
RETURN = 0xEFFF
SOURCE = 0xC500
DESTINATION = 0xC400
TILEMAP = 0xC3A0
REGION = 0x200
ARROW = 0xC4F2
W_LINKSTATE = 0xD12B


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
    tilemap: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class Return(angr.SimProcedure):
    def run(self) -> None:
        ret = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp = self.state.regs.sp + 2
        self.jump(ret)


class IncDE(angr.SimProcedure):
    def run(self) -> None:
        self.state.regs.de = self.state.regs.de + 1
        self.jump(self.state.addr + 1)


class Protected(angr.SimProcedure):
    def run(self) -> None:
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0xC0, 8))
        self.jump(self.state.addr + 3)


class Manual(angr.SimProcedure):
    def run(self) -> None:
        self.state.regs.a = claripy.BVV(0x90, 8)
        self.jump(self.state.addr + 3)


class ClearArea(angr.SimProcedure):
    def __init__(self, rows: int, start: int) -> None:
        super().__init__()
        self.rows = rows
        self.start = start

    def run(self) -> None:
        hl = self.start
        for row in range(self.rows):
            for col in range(18):
                self.state.memory.store(hl + row * 20 + col, claripy.BVV(0x7F, 8))
        self.state.regs.a = claripy.BVV(0x7F, 8)
        self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0xC0, 8))
        self.state.regs.b = claripy.BVV(0, 8)
        self.state.regs.c = claripy.BVV(18, 8)
        self.state.regs.d = claripy.BVV(0, 8)
        self.state.regs.e = claripy.BVV(20, 8)
        self.state.regs.h = claripy.BVV(0xC4, 8)
        self.state.regs.l = claripy.BVV(0xF5, 8)
        self.jump(self.state.addr + 3)


class DelayFrames(angr.SimProcedure):
    def run(self) -> None:
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0xC0, 8))
        self.state.regs.c = claripy.BVV(0, 8)
        self.jump(self.state.addr + 3)


class SetHL(angr.SimProcedure):
    def __init__(self, low: int) -> None:
        super().__init__()
        self.low = low

    def run(self) -> None:
        self.state.regs.h = claripy.BVV(0xC4, 8)
        self.state.regs.l = claripy.BVV(self.low, 8)
        self.jump(self.state.addr + 3)


def _tilemap(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(*(state.memory.load(base + TILEMAP + i, 1) for i in range(REGION)))


def _setup(state: angr.SimState, base: int, token: int) -> None:
    for i in range(REGION):
        state.memory.store(base + TILEMAP + i, claripy.BVV((i * 13) & 0xFF, 8))
    state.memory.store(base + SOURCE, claripy.BVV(token, 8))
    state.memory.store(base + SOURCE + 1, claripy.BVV(0x50, 8))
    state.memory.store(base + ARROW, claripy.BVV(0x33, 8))
    state.memory.store(base + W_LINKSTATE, claripy.BVV(0, 8))


def _assembly(values: dict[str, claripy.ast.BV], token: int, rows: int, target: int) -> list[Endpoint]:
    location = symbol_location(SYMS, "PlaceString")
    p = angr.Project(rom_window(ROM, location.bank), auto_load_libs=False, rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0, "entry_point": location.address})
    p.hook(0x195E, Return(), length=1)
    p.hook(0x19E8, IncDE(), length=1)
    if rows == 4:
        arrow, protected, manual, clear, delay, set_hl, clear_start = (0x1AB7, 0x1ABA, 0x1ABD, 0x1AC6, 0x1ACB, 0x1ACF, 0xC4A5)
    else:
        arrow, protected, manual, clear, delay, set_hl, clear_start = (0x1AD8, 0x1ADB, 0x1ADE, 0x1AE7, 0x1AEC, 0x1AF1, 0xC469)
    p.hook(arrow, Sm83StoreAImmediate(ARROW, protected), length=3)
    p.hook(protected, Protected(), length=3)
    p.hook(manual, Manual(), length=3)
    p.hook(clear, ClearArea(rows, clear_start), length=3)
    p.hook(delay, DelayFrames(), length=3)
    p.hook(set_hl, SetHL(target & 0xFF), length=3)
    s = p.factory.blank_state(addr=location.address)
    set_assembly_registers(s, values)
    s.regs.sp = STACK
    s.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    _setup(s, 0, token)
    s.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    return [Endpoint(**assembly_registers(x), tilemap=_tilemap(x, 0), constraints=tuple(x.solver.constraints)) for x in collect_returns(p, s, RETURN)]


def _native(values: dict[str, claripy.ast.BV], token: int) -> list[Endpoint]:
    p = angr.Project(ELF, auto_load_libs=False)
    fn = p.loader.find_symbol("port_place_string")
    assert fn is not None
    s = p.factory.call_state(fn.rebased_addr, NS, NM)
    store_native_registers(s, NS, values)
    _setup(s, NM, token)
    m = p.factory.simulation_manager(s)
    m.run()
    assert not m.errored and len(m.deadended) == 1
    x = m.deadended[0]
    return [Endpoint(**native_registers(x, NS), tilemap=_tilemap(x, NM), constraints=tuple(x.solver.constraints))]


@pytest.mark.skipif(not ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMS.exists(), reason="run red")
def test_place_string_paragraph_pathwise_equivalence() -> None:
    values = symbolic_registers("place_string_paragraph")
    values["h"] = claripy.BVV(DESTINATION >> 8, 8)
    values["l"] = claripy.BVV(DESTINATION & 0xFF, 8)
    values["d"] = claripy.BVV(SOURCE >> 8, 8)
    values["e"] = claripy.BVV(SOURCE & 0xFF, 8)
    assert_pathwise_equivalent(_assembly(values, 0x51, 4, 0xC4B9), _native(values, 0x51), (*REGISTERS, "tilemap"))


def test_place_string_page_pathwise_equivalence() -> None:
    values = symbolic_registers("place_string_page")
    values["h"] = claripy.BVV(DESTINATION >> 8, 8)
    values["l"] = claripy.BVV(DESTINATION & 0xFF, 8)
    values["d"] = claripy.BVV(SOURCE >> 8, 8)
    values["e"] = claripy.BVV(SOURCE & 0xFF, 8)
    assert_pathwise_equivalent(_assembly(values, 0x49, 7, 0xC47D), _native(values, 0x49), (*REGISTERS, "tilemap"))
