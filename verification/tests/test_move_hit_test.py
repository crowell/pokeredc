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

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
DONE = 0xEFFF
WHOSE_TURN = 0xFFF3
PLAYER_EFFECT = 0xCFD3
ENEMY_EFFECT = 0xCFCD


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
    constraints: tuple[claripy.ast.Bool, ...]


class Setup(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        whose = self.state.memory.load(WHOSE_TURN, 1)
        player = self.state.memory.load(PLAYER_EFFECT, 1)
        enemy = self.state.memory.load(ENEMY_EFFECT, 1)
        self.state.regs.a = claripy.If(whose == 0, player, enemy)
        self.state.regs.f = claripy.BVV(0x10, 8) | claripy.If(
            whose == 0,
            claripy.BVV(0x40, 8),
            claripy.BVV(0, 8),
        )
        self.state.regs.h = claripy.BVV(0xD0, 8)
        self.state.regs.l = claripy.If(whose == 0, claripy.BVV(0x67, 8), claripy.BVV(0x62, 8))
        self.state.regs.d = claripy.BVV(0xCF, 8)
        self.state.regs.e = claripy.If(whose == 0, claripy.BVV(0xD3, 8), claripy.BVV(0xCD, 8))
        self.state.regs.b = claripy.If(whose == 0, claripy.BVV(0xCF, 8), claripy.BVV(0xD0, 8))
        self.state.regs.c = claripy.If(whose == 0, claripy.BVV(0xE9, 8), claripy.BVV(0x18, 8))
        self.jump(DONE)


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "MoveHitTest")
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
    project.hook(location.address, Setup(), length=0x18)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.memory.store(WHOSE_TURN, values["whose_turn"])
    state.memory.store(PLAYER_EFFECT, values["player_move_effect"])
    state.memory.store(ENEMY_EFFECT, values["enemy_move_effect"])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored
    return [
        Endpoint(**assembly_registers(end), constraints=tuple(end.solver.constraints))
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_move_hit_test")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, values["whose_turn"])
    state.memory.store(NATIVE_STATE + 9, values["player_move_effect"])
    state.memory.store(NATIVE_STATE + 10, values["enemy_move_effect"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_move_hit_test_setup_pathwise_equivalence() -> None:
    values = symbolic_registers("move_hit_test")
    values["whose_turn"] = claripy.BVS("move_hit_test_whose_turn", 8)
    values["player_move_effect"] = claripy.BVS("move_hit_test_player_effect", 8)
    values["enemy_move_effect"] = claripy.BVS("move_hit_test_enemy_effect", 8)
    assert_pathwise_equivalent(_assembly(values), _native(values), REGISTERS)
