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
from verification.harness.rom import collect_returns, rom_window, symbol_location

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
STACK = 0xD000
RETURN = 0xFFFF
SHADOW_OAM = 0xC300
OAM_SIZE = 160


class DelayFrame(angr.SimProcedure):
    """Terminal transition of the independently proven DelayFrame port."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x50, 8)
        self.jump(self._next_address)


class ClearSprites(angr.SimProcedure):
    """Terminal transition of the independently proven ClearSprites loop."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(
            SHADOW_OAM,
            claripy.BVV(0, OAM_SIZE * 8),
            endness="Iend_BE",
        )
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.b = claripy.BVV(0, 8)
        self.state.regs.h = claripy.BVV(0xC3, 8)
        self.state.regs.l = claripy.BVV(0xA0, 8)
        self.state.regs.f = claripy.BVV(0x42, 8)
        self.jump(self._next_address)


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


def _assembly(
    values: dict[str, claripy.ast.BV], initial_oam: claripy.ast.BV
) -> Endpoint:
    location = symbol_location(SYMBOLS, "AnimationCleanOAM")
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
    project.hook(base + 4, DelayFrame(base + 7), length=3)
    project.hook(base + 7, ClearSprites(base + 10), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.regs.sp = claripy.BVV(STACK, 16)
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    state.memory.store(SHADOW_OAM, initial_oam, endness="Iend_BE")
    returned = collect_returns(project, state, RETURN)
    assert len(returned) == 1
    end = returned[0]
    return Endpoint(
        **assembly_registers(end),
        memory=end.memory.load(SHADOW_OAM, OAM_SIZE),
        constraints=tuple(end.solver.constraints),
    )


def _native(
    values: dict[str, claripy.ast.BV], initial_oam: claripy.ast.BV
) -> Endpoint:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_animation_clean_oam")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, initial_oam, endness="Iend_BE")
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    end = manager.deadended[0]
    return Endpoint(
        **native_registers(end, NATIVE_STATE),
        memory=end.memory.load(NATIVE_STATE + 8, OAM_SIZE),
        constraints=tuple(end.solver.constraints),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_animation_clean_oam_pathwise_equivalence() -> None:
    values = symbolic_registers("animation_clean_oam")
    initial_oam = claripy.BVS("animation_clean_oam_bytes", OAM_SIZE * 8)
    assert_pathwise_equivalent(
        [_assembly(values, initial_oam)],
        [_native(values, initial_oam)],
        (*REGISTERS, "memory"),
    )
