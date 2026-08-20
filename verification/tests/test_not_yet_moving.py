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
from verification.harness.rom import linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import Sm83AddImmediate

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
    sprite_offset: claripy.ast.BV
    anim_frame: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class LoadHImmediate(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = claripy.BVV(0xc1, 8)
        self.jump(self.state.addr + 2)


class LoadSpriteOffset(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals["sprite_offset"]
        self.jump(self.state.addr + 2)


class CopyAToL(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.l = self.state.regs.a
        self.jump(self.state.addr + 1)


class ClearAnimFrame(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.globals["anim_frame"] = claripy.BVV(0, 8)
        self.jump(self.state.addr + 2)


class Boundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(DONE)


def _assembly(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    loc = symbol_location(SYMBOLS, "NotYetMoving")
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
    project.hook(base, LoadHImmediate(), length=2)
    project.hook(base + 2, LoadSpriteOffset(), length=2)
    project.hook(base + 4, Sm83AddImmediate(8, base + 6), length=2)
    project.hook(base + 6, CopyAToL(), length=1)
    project.hook(base + 7, ClearAnimFrame(), length=2)
    project.hook(base + 9, Boundary(), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, inputs)
    state.globals["sprite_offset"] = inputs["sprite_offset"]
    state.globals["anim_frame"] = inputs["anim_frame"]
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert len(manager.found) == 1
    end = manager.found[0]
    return [
        Endpoint(
            **assembly_registers(end),
            sprite_offset=end.globals["sprite_offset"],
            anim_frame=end.globals["anim_frame"],
            constraints=tuple(end.solver.constraints),
        )
    ]


def _native(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_not_yet_moving")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["sprite_offset"])
    state.memory.store(NATIVE_STATE + 9, inputs["anim_frame"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    end = manager.deadended[0]
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            sprite_offset=end.memory.load(NATIVE_STATE + 8, 1),
            anim_frame=end.memory.load(NATIVE_STATE + 9, 1),
            constraints=tuple(end.solver.constraints),
        )
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_not_yet_moving_pathwise_equivalence() -> None:
    inputs = symbolic_registers("nym")
    inputs["sprite_offset"] = claripy.BVS("nym_sprite_offset", 8)
    inputs["anim_frame"] = claripy.BVS("nym_anim_frame", 8)
    assert_pathwise_equivalent(
        _assembly(inputs),
        _native(inputs),
        ("a", "f", "b", "c", "d", "e", "h", "l", "sprite_offset", "anim_frame"),
    )


def test_not_yet_moving_exact_linked_body() -> None:
    loc = symbol_location(SYMBOLS, "NotYetMoving")
    assert linked_bytes(ROM, loc, 12) == bytes.fromhex("26c1f0dac6086f3600c35751")
