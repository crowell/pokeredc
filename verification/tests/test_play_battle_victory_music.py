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
from verification.harness.sm83_shims import Sm83StoreAImmediate

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
DONE = 0xEFFF
W_NEW_SOUND_ID = 0xC0EE


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
    new_sound_id: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]

class SkipPush(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.globals["saved_a"] = self.state.regs.a
        self.state.globals["saved_f"] = self.state.regs.f
        self.jump(self.state.addr + 1)


class LoadAStopMusic(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0xFF, 8)
        self.jump(self.state.addr + 2)


class SkipCallee(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(self.state.addr + 3)


class LoadC8(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.c = claripy.BVV(8, 8)
        self.jump(self.state.addr + 2)


class PopAF(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals["saved_a"]
        self.state.regs.f = self.state.globals["saved_f"]
        self.jump(self.state.addr + 1)


class Boundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.successors.add_successor(
            self.state.copy(), DONE, claripy.BoolV(True), "Ijk_Boring"
        )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "PlayBattleVictoryMusic")
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
    project.hook(base, SkipPush(), length=1)
    project.hook(base + 1, LoadAStopMusic(), length=2)
    project.hook(base + 3, Sm83StoreAImmediate(W_NEW_SOUND_ID, base + 6), length=3)
    project.hook(base + 6, SkipCallee(), length=3)
    project.hook(base + 9, LoadC8(), length=2)
    project.hook(base + 11, PopAF(), length=1)
    project.hook(base + 12, Boundary(), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.memory.store(W_NEW_SOUND_ID, values["new_sound_id"])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored
    return [
        Endpoint(
            **assembly_registers(end),
            new_sound_id=end.memory.load(W_NEW_SOUND_ID, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_play_battle_victory_music")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, values["new_sound_id"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            new_sound_id=end.memory.load(NATIVE_STATE + 8, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_play_battle_victory_music_pathwise_equivalence() -> None:
    values = symbolic_registers("play_battle_victory_music")
    values["new_sound_id"] = claripy.BVS("play_battle_victory_music_new_sound_id", 8)
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "new_sound_id"),
    )
