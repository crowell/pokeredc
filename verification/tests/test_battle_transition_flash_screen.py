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
from verification.harness.sm83_shims import Sm83CpImmediate, Sm83StoreAHighImmediate

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
DONE = 0xEFFF
H_BGP = 0xFF47


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
    bgp: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class SetupHL(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = claripy.BVV(0x4B, 8)
        self.state.regs.l = claripy.BVV(0x72, 8)
        self.jump(self.state.addr + 3)


class LoadFirstPalette(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(3, 8)
        self.state.regs.hl = self.state.regs.hl + 1
        self.jump(self.state.addr + 1)


class Jump(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(self.state.addr + 2)


class LoadC2PreserveFlags(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.c = claripy.BVV(2, 8)
        self.jump(self.state.addr + 2)


class Boundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.successors.add_successor(
            self.state.copy(), DONE, claripy.BoolV(True), "Ijk_Boring"
        )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "BattleTransition_FlashScreen_")
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
    project.hook(base, SetupHL(), length=3)
    project.hook(base + 3, LoadFirstPalette(), length=1)
    project.hook(base + 4, Sm83CpImmediate(1, base + 6), length=2)
    project.hook(base + 6, Jump(), length=2)
    project.hook(base + 8, Sm83StoreAHighImmediate(0x47, base + 10), length=2)
    project.hook(base + 10, LoadC2PreserveFlags(), length=2)
    project.hook(base + 12, Boundary(), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.memory.store(H_BGP, values["bgp"])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored
    return [
        Endpoint(
            **assembly_registers(end),
            bgp=end.memory.load(H_BGP, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_battle_transition_flash_screen")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, values["bgp"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            bgp=end.memory.load(NATIVE_STATE + 8, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_battle_transition_flash_screen_prefix_pathwise_equivalence() -> None:
    values = symbolic_registers("battle_transition_flash_screen")
    values["bgp"] = claripy.BVS("battle_transition_flash_screen_bgp", 8)
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "bgp"),
    )
