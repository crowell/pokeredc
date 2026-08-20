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
from verification.harness.rom import rom_window, symbol_location
from verification.harness.sm83_shims import Sm83IncRegister, Sm83StoreAImmediate, Sm83XorImmediate

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
DONE = 0xEFFF
GAIN = 0xD058
FOUGHT = 0xCCF5
ACTION = 0xCD6A
FIRST = 0xD11D


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
    gain: claripy.ast.BV
    fought: claripy.ast.BV
    action: claripy.ast.BV
    first: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class XorA(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0, 8)
        self.jump(self.state.addr + 1)


class LoadHL(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = claripy.BVV(0xD8, 8)
        self.state.regs.l = claripy.BVV(0xA5, 8)
        self.jump(self.state.addr + 3)


class LoadBC(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.b = claripy.BVV(0, 8)
        self.state.regs.c = claripy.BVV(0, 8)
        self.jump(self.state.addr + 3)


class LoadD3(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.d = claripy.BVV(3, 8)
        self.jump(self.state.addr + 2)


class Boundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.successors.add_successor(
            self.state.copy(), DONE, claripy.BoolV(True), "Ijk_Boring"
        )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "StartBattle")
    base = location.address
    project = angr.Project(
        rom_window(ROM, location.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": base,
        },
    )
    project.hook(base, XorA(), length=1)
    project.hook(base + 1, Sm83StoreAImmediate(GAIN, base + 4), length=3)
    project.hook(base + 4, Sm83StoreAImmediate(FOUGHT, base + 7), length=3)
    project.hook(base + 7, Sm83StoreAImmediate(ACTION, base + 10), length=3)
    project.hook(base + 10, Sm83IncRegister("a", base + 11), length=1)
    project.hook(base + 11, Sm83StoreAImmediate(FIRST, base + 14), length=3)
    project.hook(base + 14, LoadHL(), length=3)
    project.hook(base + 17, LoadBC(), length=3)
    project.hook(base + 20, LoadD3(), length=2)
    project.hook(base + 22, Boundary(), length=1)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    for address in (GAIN, FOUGHT, ACTION, FIRST):
        state.memory.store(address, claripy.BVV(0, 8))
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored
    return [
        Endpoint(
            **assembly_registers(end),
            gain=end.memory.load(GAIN, 1),
            fought=end.memory.load(FOUGHT, 1),
            action=end.memory.load(ACTION, 1),
            first=end.memory.load(FIRST, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_start_battle")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    for offset, name in ((8, "gain"), (9, "fought"), (10, "action"), (11, "first")):
        state.memory.store(NATIVE_STATE + offset, values[name])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            gain=end.memory.load(NATIVE_STATE + 8, 1),
            fought=end.memory.load(NATIVE_STATE + 9, 1),
            action=end.memory.load(NATIVE_STATE + 10, 1),
            first=end.memory.load(NATIVE_STATE + 11, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_start_battle_initialization_pathwise_equivalence() -> None:
    values = symbolic_registers("start_battle")
    for name in ("gain", "fought", "action", "first"):
        values[name] = claripy.BVS(f"start_battle_{name}", 8)
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "gain", "fought", "action", "first"),
    )
