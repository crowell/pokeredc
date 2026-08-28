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
from verification.harness.sm83_shims import Sm83CpImmediate, Sm83LoadAImmediate, Sm83StoreAImmediate

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
ARROW = 0xC4F2
W_LINKSTATE = 0xD12B
DONE_PREV = 0x1AB2


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
    arrow: claripy.ast.BV
    link: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class ReturnPlaceString(angr.SimProcedure):
    def run(self) -> None:
        ret = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp = self.state.regs.sp + 2
        self.jump(ret)


class ProtectedDelay3(angr.SimProcedure):
    def run(self) -> None:
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0xC0, 8))
        self.jump(self.state.addr + 3)


class ManualTextScroll(angr.SimProcedure):
    def run(self) -> None:
        link = self.state.memory.load(W_LINKSTATE, 1)
        self.inhibit_autoret = True
        normal = self.state.copy()
        normal.solver.add(link != 4)
        normal.regs.a = claripy.BVV(0x90, 8)
        normal.regs.f = sm83_flags_to_z80(claripy.BVV(0xC0, 8))
        normal.regs.ip = claripy.BVV(self.state.addr + 3, 16)
        battle = self.state.copy()
        battle.solver.add(link == 4)
        battle.regs.a = claripy.BVV(4, 8)
        battle.regs.c = claripy.BVV(65, 8)
        battle.regs.f = sm83_flags_to_z80(claripy.BVV(0xC0, 8))
        battle.regs.ip = claripy.BVV(self.state.addr + 3, 16)
        self.successors.add_successor(normal, self.state.addr + 3, link != 4, "Ijk_Boring")
        self.successors.add_successor(battle, self.state.addr + 3, link == 4, "Ijk_Boring")


class BranchZ(angr.SimProcedure):
    def __init__(self, taken: int, fallthrough: int) -> None:
        super().__init__()
        self.taken = taken
        self.fallthrough = fallthrough

    def run(self) -> None:
        z = (self.state.regs.f >> 6) & 1
        self.inhibit_autoret = True
        taken = self.state.copy()
        taken.solver.add(z == 1)
        taken.regs.ip = claripy.BVV(self.taken, 16)
        fall = self.state.copy()
        fall.solver.add(z == 0)
        fall.regs.ip = claripy.BVV(self.fallthrough, 16)
        self.successors.add_successor(taken, self.taken, z == 1, "Ijk_Boring")
        self.successors.add_successor(fall, self.fallthrough, z == 0, "Ijk_Boring")


def _setup(state: angr.SimState, base: int, link: claripy.ast.BV, arrow: claripy.ast.BV) -> None:
    state.memory.store(base + SOURCE, claripy.BVV(0x58, 8))
    state.memory.store(base + ARROW, arrow)
    state.memory.store(base + W_LINKSTATE, link)


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMS, "PlaceString")
    project = angr.Project(rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0, "entry_point": location.address})
    project.hook(0x1A95, Sm83LoadAImmediate(W_LINKSTATE, 0x1A98), length=3)
    project.hook(0x1A98, Sm83CpImmediate(4, 0x1A9A), length=2)
    project.hook(0x1A9A, BranchZ(0x1AA2, 0x1A9D), length=3)
    project.hook(0x1A9F, Sm83StoreAImmediate(ARROW, 0x1AA2), length=3)
    project.hook(0x1AA2, ProtectedDelay3(), length=3)
    project.hook(0x1AA5, ManualTextScroll(), length=3)
    project.hook(0x1AAA, Sm83StoreAImmediate(ARROW, 0x1AAD), length=3)
    project.hook(0x1AB2, ReturnPlaceString(), length=1)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    state.memory.store(STACK - 2, claripy.BVV(0xC400, 16), endness="Iend_LE")
    _setup(state, 0, values["link"], values["arrow"])
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    return [Endpoint(**assembly_registers(end), arrow=end.memory.load(ARROW, 1), link=end.memory.load(W_LINKSTATE, 1), constraints=tuple(end.solver.constraints)) for end in collect_returns(project, state, RETURN)]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_place_string")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NS, NM)
    store_native_registers(state, NS, values)
    _setup(state, NM, values["link"], values["arrow"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 2
    return [Endpoint(**native_registers(end, NS), arrow=end.memory.load(NM + ARROW, 1), link=end.memory.load(NM + W_LINKSTATE, 1), constraints=tuple(end.solver.constraints)) for end in manager.deadended]


@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMS.exists(), reason="run red")
def test_place_string_prompt_pathwise_equivalence() -> None:
    values = symbolic_registers("place_string_prompt")
    values["h"] = claripy.BVV(DESTINATION >> 8, 8)
    values["l"] = claripy.BVV(DESTINATION & 0xFF, 8)
    values["d"] = claripy.BVV(SOURCE >> 8, 8)
    values["e"] = claripy.BVV(SOURCE & 0xFF, 8)
    values["link"] = claripy.BVS("place_string_prompt_link", 8)
    values["arrow"] = claripy.BVS("place_string_prompt_arrow", 8)
    assert_pathwise_equivalent(_assembly(values), _native(values), (*REGISTERS, "arrow", "link"))
