from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
    REGISTERS,
    assembly_registers,
    native_registers,
    set_assembly_registers,
    store_native_registers,
    symbolic_registers,
)
from verification.harness.rom import (
    collect_returns,
    linked_bytes,
    rom_window,
    sm83_flags_to_z80,
    symbol_location,
)
from verification.harness.sm83_shims import Sm83LoadAImmediate

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
RETURN = 0xEFFF
STACK = 0xD000
W_ENTERING_CABLE_CLUB = 0xCC47


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
    memory: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class BranchNZ(angr.SimProcedure):
    def __init__(self, taken: int, fallthrough: int) -> None:
        super().__init__()
        self.taken = taken
        self.fallthrough = fallthrough

    def run(self) -> None:  # type: ignore[override]
        # The p-code Z80 register uses the Z flag's bit-6 position.
        condition = (self.state.regs.f & 0x40) == 0
        self.inhibit_autoret = True
        self.successors.add_successor(
            self.state.copy(), self.taken, condition, "Ijk_Boring"
        )
        self.successors.add_successor(
            self.state.copy(), self.fallthrough, claripy.Not(condition), "Ijk_Boring"
        )


class AndA(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.f = sm83_flags_to_z80(claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0xA0, 8),
            claripy.BVV(0x20, 8),
        ))
        self.jump(self.state.addr + 1)


class WaitBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(0xFF8B, 1)
        self.inhibit_autoret = True
        self.jump(self.state.addr + 3)


class ContinuationBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.sp = STACK + 2
        self.inhibit_autoret = True
        self.jump(RETURN)


def _setup(state: angr.SimState, base: int, *, entering: int,
           arrow1: claripy.ast.BV, arrow2: claripy.ast.BV,
           joy5: claripy.ast.BV) -> None:
    state.memory.store(base + W_ENTERING_CABLE_CLUB, claripy.BVV(entering, 8))
    state.memory.store(base + 0xFF8B, arrow1)
    state.memory.store(base + 0xFF8C, arrow2)
    state.memory.store(base + 0xFFB5, joy5)


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        state.memory.load(base + W_ENTERING_CABLE_CLUB, 1),
        state.memory.load(base + 0xFF8B, 1),
        state.memory.load(base + 0xFF8C, 1),
        state.memory.load(base + 0xFFB5, 1),
    )


def _assembly(values: dict[str, claripy.ast.BV], *, entering: int,
              arrow1: claripy.ast.BV, arrow2: claripy.ast.BV,
              joy5: claripy.ast.BV) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "AfterDisplayingTextID")
    hold = symbol_location(SYMBOLS, "HoldTextDisplayOpen")
    assert hold.address == location.address + 9
    assert linked_bytes(ROM, location, 9) == bytes.fromhex("fa47cca72003cd6538")
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    q = location.address
    project.hook(q, Sm83LoadAImmediate(W_ENTERING_CABLE_CLUB, q + 3), length=3)
    project.hook(q + 3, AndA(), length=1)
    project.hook(q + 4, BranchNZ(hold.address, q + 6), length=2)
    project.hook(q + 6, WaitBoundary(), length=3)
    project.hook(hold.address, ContinuationBoundary(), length=3)
    state = project.factory.blank_state(addr=q)
    set_assembly_registers(state, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    _setup(state, 0, entering=entering, arrow1=arrow1, arrow2=arrow2, joy5=joy5)
    state.solver.add((joy5 & 0x03) != 0)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    endpoints = collect_returns(project, state, RETURN)
    return [Endpoint(**assembly_registers(end), memory=_memory(end, 0),
                     constraints=tuple(end.solver.constraints)) for end in endpoints]


def _native(values: dict[str, claripy.ast.BV], *, entering: int,
            arrow1: claripy.ast.BV, arrow2: claripy.ast.BV,
            joy5: claripy.ast.BV) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_after_displaying_text_id")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE,
                                       NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, NATIVE_MEMORY, entering=entering, arrow1=arrow1,
           arrow2=arrow2, joy5=joy5)
    state.solver.add((joy5 & 0x03) != 0)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    end = manager.deadended[0]
    return [Endpoint(**native_registers(end, NATIVE_STATE),
                     memory=_memory(end, NATIVE_MEMORY),
                     constraints=tuple(end.solver.constraints))]


@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("entering", (0, 1))
def test_after_displaying_text_id_pathwise_equivalence(entering: int) -> None:
    values = symbolic_registers(f"after_displaying_text_id_{entering}")
    arrow1 = claripy.BVS(f"after_arrow1_{entering}", 8)
    arrow2 = claripy.BVS(f"after_arrow2_{entering}", 8)
    joy5 = claripy.BVS(f"after_joy5_{entering}", 8)
    assert_pathwise_equivalent(
        _assembly(values, entering=entering, arrow1=arrow1,
                  arrow2=arrow2, joy5=joy5),
        _native(values, entering=entering, arrow1=arrow1,
                arrow2=arrow2, joy5=joy5),
        (*REGISTERS, "memory"),
    )
