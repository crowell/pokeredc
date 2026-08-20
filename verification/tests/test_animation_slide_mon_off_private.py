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
from verification.harness.sm83_shims import Sm83LoadAHighImmediate
from verification.harness.rom import rom_window, symbol_location

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF
H_WHOSE_TURN = 0xFFF3


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
    constraints: tuple[claripy.ast.Bool, ...]


class ContinuationBoundary(angr.SimProcedure):
    def run(self) -> None:
        self.inhibit_autoret = True
        self.successors.add_successor(
            self.state.copy(), DONE, claripy.BoolV(True), "Ijk_Boring"
        )

class Sm83AndA(angr.SimProcedure):
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


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "_AnimationSlideMonOff")
    player = symbol_location(SYMBOLS, "_AnimationSlideMonOff.PlayerNextTile")
    enemy = symbol_location(SYMBOLS, "_AnimationSlideMonOff.EnemyNextTile")
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
    project.hook(location.address + 2, Sm83AndA(location.address + 3), length=1)
    project.hook(location.address + 20, Sm83LoadAHighImmediate(0xF3, location.address + 22), length=2)
    project.hook(location.address + 22, Sm83AndA(location.address + 23), length=1)
    project.hook(player.address, ContinuationBoundary(), length=1)
    project.hook(enemy.address, ContinuationBoundary(), length=1)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.memory.store(H_WHOSE_TURN, values["whose_turn"])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=2)
    assert not manager.errored
    return [
        Endpoint(
            **assembly_registers(end),
            whose_turn=end.memory.load(H_WHOSE_TURN, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_animation_slide_mon_off_private")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_MEMORY + H_WHOSE_TURN, values["whose_turn"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            whose_turn=end.memory.load(NATIVE_MEMORY + H_WHOSE_TURN, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_animation_slide_mon_off_private_pathwise_equivalence() -> None:
    values = symbolic_registers("animation_slide_mon_off_private")
    values["whose_turn"] = claripy.BVS("animation_slide_mon_off_private_whose_turn", 8)
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "whose_turn"),
    )
