from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
    assembly_registers,
    native_registers,
    set_assembly_registers,
    store_native_registers,
    symbolic_registers,
)
from verification.harness.rom import linked_bytes, rom_window, sm83_flags_to_z80, symbol_location

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
DONE = 0xEFFF


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


class NoOpInstruction(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(self.state.addr + 1)


class LoadAnimationType(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(8, 8)
        self.jump(self.state.addr + 2)


class MoveAnimationSummary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals["move_animation_a"]
        self.state.regs.f = sm83_flags_to_z80(self.state.globals["move_animation_f"])
        self.jump(self.state.addr + 3)


class Boundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(DONE)


def _assembly(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    loc = symbol_location(SYMBOLS, "PlayBattleAnimationGotID")
    base = loc.address
    project = angr.Project(
        rom_window(ROM, loc.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": base,
        },
    )
    project.hook(base, NoOpInstruction(), length=1)
    project.hook(base + 1, NoOpInstruction(), length=1)
    project.hook(base + 2, NoOpInstruction(), length=1)
    project.hook(base + 3, LoadAnimationType(), length=2)
    project.hook(base + 5, MoveAnimationSummary(), length=3)
    project.hook(base + 8, NoOpInstruction(), length=1)
    project.hook(base + 9, NoOpInstruction(), length=1)
    project.hook(base + 10, NoOpInstruction(), length=1)
    project.hook(base + 11, Boundary(), length=1)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, inputs)
    state.globals["move_animation_a"] = inputs["move_animation_a"]
    state.globals["move_animation_f"] = inputs["move_animation_f"]
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert len(manager.found) == 1
    end = manager.found[0]
    return [Endpoint(**assembly_registers(end), constraints=tuple(end.solver.constraints))]


def _native(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_play_battle_animation_got_id")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["move_animation_a"])
    state.memory.store(NATIVE_STATE + 9, inputs["move_animation_f"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    end = manager.deadended[0]
    return [Endpoint(**native_registers(end, NATIVE_STATE), constraints=tuple(end.solver.constraints))]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_play_battle_animation_got_id_compositional_pathwise_equivalence() -> None:
    inputs = symbolic_registers("pbag")
    inputs["move_animation_a"] = claripy.BVS("pbag_move_animation_a", 8)
    inputs["move_animation_f"] = claripy.Concat(claripy.BVS("pbag_move_animation_flags", 4), claripy.BVV(0, 4))
    assert_pathwise_equivalent(
        _assembly(inputs),
        _native(inputs),
        ("a", "f", "b", "c", "d", "e", "h", "l"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_play_battle_animation_got_id_exact_linked_body() -> None:
    loc = symbol_location(SYMBOLS, "PlayBattleAnimationGotID")
    assert linked_bytes(ROM, loc, 12) == bytes.fromhex("e5d5c53e08cd6d3ec1d1e1c9")
