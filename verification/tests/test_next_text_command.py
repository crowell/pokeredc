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
    rom_window,
    sm83_flags_to_z80,
    symbol_location,
)
from verification.harness.sm83_shims import (
    Sm83CpImmediate,
    Sm83LoadAAtHlIncrement,
    Sm83StoreAImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
RETURN = 0xEFFF
STACK = 0xD000
TEXT_PTR = 0xD360
W_LETTER_PRINTING_DELAY_FLAGS = 0xD358
TX_END = 0x50


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


class PopAF(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        sp = self.state.regs.sp
        self.state.regs.f = self.state.memory.load(sp, 1)
        self.state.regs.a = self.state.memory.load(sp + 1, 1)
        self.state.regs.sp = sp + 2
        self.jump(self.state.addr + 1)


class Return(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        ret = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp = self.state.regs.sp + 2
        self.jump(ret)


class BranchNZ(angr.SimProcedure):
    def __init__(self, taken: int, fallthrough: int) -> None:
        super().__init__()
        self.taken = taken
        self.fallthrough = fallthrough

    def run(self) -> None:  # type: ignore[override]
        nz = ((self.state.regs.f >> 6) & 1) == 0
        taken = self.state.copy()
        fallthrough = self.state.copy()
        taken.solver.add(nz)
        fallthrough.solver.add(claripy.Not(nz))
        self.inhibit_autoret = True
        self.successors.add_successor(taken, self.taken, nz, "Ijk_Boring")
        self.successors.add_successor(
            fallthrough, self.fallthrough, claripy.Not(nz), "Ijk_Boring"
        )


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["saved_a"] = claripy.BVS(f"{prefix}_saved_a", 8)
    values["saved_f"] = claripy.Concat(
        claripy.BVS(f"{prefix}_saved_flags", 4), claripy.BVV(0, 4)
    )
    values["ldf"] = claripy.BVS(f"{prefix}_ldf", 8)
    return values


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        state.memory.load(base + W_LETTER_PRINTING_DELAY_FLAGS, 1),
        state.memory.load(base + TEXT_PTR, 1),
        state.memory.load(base + TEXT_PTR + 1, 1),
    )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "NextTextCommand")
    project = angr.Project(
        rom_window(ROM, location.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": location.address,
        },
    )
    base = location.address
    project.hook(base, Sm83LoadAAtHlIncrement(base + 1), length=1)
    project.hook(base + 1, Sm83CpImmediate(TX_END, base + 3), length=2)
    project.hook(base + 3, BranchNZ(base + 5, base + 5), length=2)
    project.hook(base + 5, PopAF(), length=1)
    project.hook(
        base + 6,
        Sm83StoreAImmediate(W_LETTER_PRINTING_DELAY_FLAGS, base + 9),
        length=3,
    )
    project.hook(base + 9, Return(), length=1)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.regs.sp = STACK
    state.memory.store(
        STACK, sm83_flags_to_z80(values["saved_f"]), endness="Iend_LE"
    )
    state.memory.store(STACK + 1, values["saved_a"], endness="Iend_LE")
    state.memory.store(STACK + 2, claripy.BVV(RETURN, 16), endness="Iend_LE")
    state.memory.store(TEXT_PTR, claripy.BVV(TX_END, 8))
    state.memory.store(TEXT_PTR + 1, claripy.BVV(0x7F, 8))
    state.memory.store(W_LETTER_PRINTING_DELAY_FLAGS, values["ldf"])
    ends = collect_returns(project, state, RETURN)
    return [
        Endpoint(
            **assembly_registers(end),
            memory=_memory(end, 0),
            constraints=tuple(end.solver.constraints),
        )
        for end in ends
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_next_text_command")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, values["saved_a"])
    state.memory.store(NATIVE_STATE + 9, values["saved_f"])
    state.memory.store(NATIVE_MEMORY + TEXT_PTR, claripy.BVV(TX_END, 8))
    state.memory.store(NATIVE_MEMORY + TEXT_PTR + 1, claripy.BVV(0x7F, 8))
    state.memory.store(
        NATIVE_MEMORY + W_LETTER_PRINTING_DELAY_FLAGS, values["ldf"]
    )
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=_memory(end, NATIVE_MEMORY),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_next_text_command_pathwise_equivalence() -> None:
    values = _inputs("next_text_command")
    values["h"] = claripy.BVV(TEXT_PTR >> 8, 8)
    values["l"] = claripy.BVV(TEXT_PTR & 0xFF, 8)
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "memory"),
    )
