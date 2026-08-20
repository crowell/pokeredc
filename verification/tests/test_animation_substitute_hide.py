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
from verification.harness.sm83_shims import Sm83LoadAHighImmediate, Sm83LoadAImmediate

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF
H_WHOSE_TURN = 0xFFF3
W_PLAYER_BATTLE_STATUS2 = 0xD063
W_ENEMY_BATTLE_STATUS2 = 0xD068
W_PLAYER_MON_MINIMIZED = 0xCCF7
W_ENEMY_MON_MINIMIZED = 0xCCF3


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
    whose_turn: claripy.ast.BV
    player_status: claripy.ast.BV
    enemy_status: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class AndA(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:
        self.state.regs.f = claripy.BVV(0x10, 8) | claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x40, 8),
            claripy.BVV(0, 8),
        )
        self.jump(self._next_address)


class Bit4(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:
        self.state.regs.f = claripy.BVV(0x10, 8) | claripy.If(
            (self.state.regs.a & 0x10) == 0,
            claripy.BVV(0x40, 8),
            claripy.BVV(0, 8),
        )
        self.jump(self._next_address)


class ContinuationBoundary(angr.SimProcedure):
    def run(self) -> None:
        self.inhibit_autoret = True
        self.successors.add_successor(
            self.state.copy(), DONE, claripy.BoolV(True), "Ijk_Boring"
        )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "HideSubstituteShowMonAnim")
    slide_down = symbol_location(SYMBOLS, "AnimationSlideMonDown")
    slide_off = symbol_location(SYMBOLS, "AnimationSlideMonOff")
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
    project.hook(location.address, Sm83LoadAHighImmediate(0xF3, location.address + 2), length=2)
    project.hook(location.address + 2, AndA(location.address + 3), length=1)
    project.hook(location.address + 6, Sm83LoadAImmediate(W_PLAYER_BATTLE_STATUS2, location.address + 9), length=3)
    project.hook(location.address + 14, Sm83LoadAImmediate(W_ENEMY_BATTLE_STATUS2, location.address + 17), length=3)
    project.hook(location.address + 18, Bit4(location.address + 20), length=1)
    project.hook(slide_down.address, ContinuationBoundary(), length=1)
    project.hook(slide_off.address, ContinuationBoundary(), length=1)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.memory.store(H_WHOSE_TURN, values["whose_turn"])
    state.memory.store(W_PLAYER_BATTLE_STATUS2, values["player_status"])
    state.memory.store(W_ENEMY_BATTLE_STATUS2, values["enemy_status"])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=2)
    assert not manager.errored
    return [
        Endpoint(
            **assembly_registers(end),
            whose_turn=end.memory.load(H_WHOSE_TURN, 1),
            player_status=end.memory.load(W_PLAYER_BATTLE_STATUS2, 1),
            enemy_status=end.memory.load(W_ENEMY_BATTLE_STATUS2, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_hide_substitute_show_mon_anim")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_MEMORY + H_WHOSE_TURN, values["whose_turn"])
    state.memory.store(NATIVE_MEMORY + W_PLAYER_BATTLE_STATUS2, values["player_status"])
    state.memory.store(NATIVE_MEMORY + W_ENEMY_BATTLE_STATUS2, values["enemy_status"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            whose_turn=end.memory.load(NATIVE_MEMORY + H_WHOSE_TURN, 1),
            player_status=end.memory.load(NATIVE_MEMORY + W_PLAYER_BATTLE_STATUS2, 1),
            enemy_status=end.memory.load(NATIVE_MEMORY + W_ENEMY_BATTLE_STATUS2, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_hide_substitute_show_mon_anim_pathwise_equivalence() -> None:
    values = symbolic_registers("hide_substitute_show_mon_anim")
    values["whose_turn"] = claripy.BVS("hide_substitute_show_mon_anim_whose_turn", 8)
    values["player_status"] = claripy.BVS("hide_substitute_show_mon_anim_player_status", 8)
    values["enemy_status"] = claripy.BVS("hide_substitute_show_mon_anim_enemy_status", 8)
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "whose_turn", "player_status", "enemy_status"),
    )
