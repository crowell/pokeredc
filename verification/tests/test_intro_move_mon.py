"""Proof for IntroMoveMon's three movement modes and cleanup."""

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
)
from verification.harness.rom import collect_returns, linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import (
    Sm83CpImmediate,
    Sm83IncRegister,
    Sm83LoadAFromRegister,
    Sm83LoadAHighImmediate,
    Sm83StoreAHighImmediate,
    Sm83StoreAImmediate,
    Sm83XorA,
)
ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF
H_JOY7 = 0xFFB2
H_JOY6 = 0xFFB3
H_JOY_HELD = 0xFFB4
H_JOY_PRESSED = 0xFFB5
H_JOY5 = 0xFFB6
H_FRAMECOUNTER = 0xFFD5
H_SCX = 0xFFAE
H_VBLANK_OCCURRED = 0xFFD6
W_BASE_COORD_X = 0xD081
W_BASE_COORD_Y = 0xD082
W_INTRO_NIDORINO_BASE_TILE = 0xD09F
W_SHADOW_OAM = 0xC300
OAM_SIZE = 144
MOVE_NIDORINO_RIGHT = 0xFF
MOVE_GENGAR_LEFT = 0x01
STACK = 0x9000
EXPECTED = bytes.fromhex(
    "7bfeff280afe012816f0ae3d3d1814d53e02ea81d0afea82d00e24cdae57d1f0ae3c3ce0aed50e02cdf812d1d81520d0c9"
)



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
    scx: claripy.ast.BV
    base_x: claripy.ast.BV
    base_y: claripy.ast.BV
    joy5: claripy.ast.BV
    frame_counter: claripy.ast.BV
    oam: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]

def return_from_call(state: angr.SimState) -> int:
    stack = state.solver.eval(state.regs.sp)
    target = state.solver.eval(state.memory.load(stack, 2, endness="Iend_LE"))
    state.regs.sp = claripy.BVV((stack + 2) & 0xFFFF, 16)
    return target



class UpdateIntroNidorinoOAM(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        state = self.state
        base_tile = state.memory.load(W_INTRO_NIDORINO_BASE_TILE, 1)
        for index in range(36):
            offset = W_SHADOW_OAM + index * 4
            state.memory.store(offset, state.memory.load(offset, 1))
            state.memory.store(offset + 1, state.memory.load(offset + 1, 1) + 2)
            state.memory.store(offset + 2, base_tile + index)
        state.regs.a = base_tile + 35
        state.regs.f = claripy.BVV(0xC0, 8)
        state.regs.c = claripy.BVV(0, 8)
        state.regs.d = base_tile + 36
        state.regs.h = claripy.BVV(0xC3, 8)
        state.regs.l = claripy.BVV(0x90, 8)
        self.jump(return_from_call(state))


class CheckForUserInterruption(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        state = self.state
        state.memory.store(H_JOY5, claripy.BVV(0, 8))
        state.memory.store(H_FRAMECOUNTER, claripy.BVV(5, 8))
        state.regs.a = claripy.BVV(0, 8)
        state.regs.f = claripy.BVV(0x50, 8)
        state.regs.c = claripy.BVV(0, 8)
        self.jump(return_from_call(state))


class Branch(angr.SimProcedure):
    def __init__(
        self,
        *,
        flag: int,
        taken: int,
        fallthrough: int,
        when_set: bool = True,
        value: int | None = None,
        register: str | None = None,
    ) -> None:
        super().__init__()
        self.flag = flag
        self.taken = taken
        self.fallthrough = fallthrough
        self.when_set = when_set
        self.value = value
        self.register = register

    def run(self) -> None:  # type: ignore[override]
        if self.value is not None:
            condition = self.state.solver.is_true(
                getattr(self.state.regs, self.register or "a") == self.value
            )
        else:
            condition = self.state.solver.is_true(
                (self.state.regs.f & self.flag) != 0
            )
        self.jump(self.taken if condition == self.when_set else self.fallthrough)

class Jump(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__()
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.jump(self.target)


class Return(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(DONE)


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    addresses = (H_SCX, W_BASE_COORD_X, W_BASE_COORD_Y, H_JOY5, H_FRAMECOUNTER)
    return claripy.Concat(
        *(state.memory.load(base + address, 1) for address in addresses),
        state.memory.load(base + W_SHADOW_OAM, OAM_SIZE),
    )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "IntroMoveMon")
    project = angr.Project(
        rom_window(ROM, location.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0, "entry_point": location.address},
    )
    base = location.address
    direction = int(values["e"].args[0])
    project.hook(base + 0x00, Sm83LoadAFromRegister("e", base + 0x01), length=1)
    project.hook(base + 0x01, Sm83CpImmediate(MOVE_NIDORINO_RIGHT, base + 0x03), length=2)
    project.hook(base + 0x03, Jump(base + (0x0F if direction == MOVE_NIDORINO_RIGHT else 0x05)), length=2)
    project.hook(base + 0x05, Sm83CpImmediate(MOVE_GENGAR_LEFT, base + 0x07), length=2)
    project.hook(base + 0x07, Jump(base + (0x1F if direction == MOVE_GENGAR_LEFT else 0x09)), length=2)
    project.hook(base + 0x09, Sm83LoadAHighImmediate(H_SCX & 0xFF, base + 0x0B), length=2)
    project.hook(base + 0x0D, Jump(base + 0x23), length=2)
    project.hook(base + 0x12, Sm83StoreAImmediate(W_BASE_COORD_X, base + 0x15), length=3)
    project.hook(base + 0x15, Sm83XorA(base + 0x16), length=1)
    project.hook(base + 0x16, Sm83StoreAImmediate(W_BASE_COORD_Y, base + 0x19), length=3)
    project.hook(base + 0x1F, Sm83LoadAHighImmediate(H_SCX & 0xFF, base + 0x21), length=2)
    project.hook(base + 0x21, Sm83IncRegister("a", base + 0x22), length=1)
    project.hook(base + 0x22, Sm83IncRegister("a", base + 0x23), length=1)
    project.hook(base + 0x23, Sm83StoreAHighImmediate(H_SCX & 0xFF, base + 0x25), length=2)
    project.hook(0x57AE, UpdateIntroNidorinoOAM(), length=1)
    project.hook(0x12F8, CheckForUserInterruption(), length=1)
    project.hook(0x2322, CheckForUserInterruption(), length=1)
    project.hook(base + 0x2E, Branch(flag=0x40, taken=base + 0x30, fallthrough=base), length=2)
    project.hook(base + 0x30, Return(), length=1)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.memory.store(H_SCX, values["scx"])
    state.memory.store(W_INTRO_NIDORINO_BASE_TILE, values["base_tile"])
    state.memory.store(W_SHADOW_OAM, claripy.BVV(0, OAM_SIZE * 8), endness="Iend_BE")
    for address in (H_VBLANK_OCCURRED, H_JOY7, H_JOY6, H_JOY_HELD, H_JOY_PRESSED, H_JOY5, H_FRAMECOUNTER):
        state.memory.store(address, claripy.BVV(0, 8))
    state.regs.sp = STACK
    state.memory.store(W_BASE_COORD_X, claripy.BVV(0, 8))
    state.memory.store(W_BASE_COORD_Y, claripy.BVV(0, 8))
    returned = collect_returns(project, state, DONE)
    return [
        Endpoint(
            **assembly_registers(end),
            scx=end.memory.load(H_SCX, 1),
            base_x=end.memory.load(W_BASE_COORD_X, 1),
            base_y=end.memory.load(W_BASE_COORD_Y, 1),
            joy5=end.memory.load(H_JOY5, 1),
            frame_counter=end.memory.load(H_FRAMECOUNTER, 1),
            oam=end.memory.load(W_SHADOW_OAM, OAM_SIZE),
            constraints=tuple(end.solver.constraints),
        )
        for end in returned
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_intro_move_mon")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_MEMORY + H_SCX, values["scx"])
    state.memory.store(NATIVE_MEMORY + W_INTRO_NIDORINO_BASE_TILE, values["base_tile"])
    state.memory.store(NATIVE_MEMORY + W_SHADOW_OAM, claripy.BVV(0, OAM_SIZE * 8), endness="Iend_BE")
    state.memory.store(NATIVE_MEMORY + W_BASE_COORD_X, claripy.BVV(0, 8))
    state.memory.store(NATIVE_MEMORY + W_BASE_COORD_Y, claripy.BVV(0, 8))
    for address in (H_VBLANK_OCCURRED, H_JOY7, H_JOY6, H_JOY_HELD, H_JOY_PRESSED, H_JOY5, H_FRAMECOUNTER):
        state.memory.store(NATIVE_MEMORY + address, claripy.BVV(0, 8))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            scx=end.memory.load(NATIVE_MEMORY + H_SCX, 1),
            base_x=end.memory.load(NATIVE_MEMORY + W_BASE_COORD_X, 1),
            base_y=end.memory.load(NATIVE_MEMORY + W_BASE_COORD_Y, 1),
            joy5=end.memory.load(NATIVE_MEMORY + H_JOY5, 1),
            frame_counter=end.memory.load(NATIVE_MEMORY + H_FRAMECOUNTER, 1),
            oam=end.memory.load(NATIVE_MEMORY + W_SHADOW_OAM, OAM_SIZE),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


def _inputs(direction: int) -> dict[str, claripy.ast.BV]:
    return {
        "a": claripy.BVV(0x12, 8),
        "f": claripy.BVV(0x10, 8),
        "b": claripy.BVV(0x34, 8),
        "c": claripy.BVV(0x56, 8),
        "d": claripy.BVV(1, 8),
        "e": claripy.BVV(direction, 8),
        "h": claripy.BVV(0x78, 8),
        "l": claripy.BVV(0x9A, 8),
        "scx": claripy.BVV(0x20, 8),
        "base_tile": claripy.BVV(0x40, 8),
    }


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
@pytest.mark.parametrize("direction", [MOVE_NIDORINO_RIGHT, MOVE_GENGAR_LEFT, 0x02])
def test_intro_move_mon_pathwise_equivalence(direction: int) -> None:
    values = _inputs(direction)
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        ("a", "f", "b", "c", "d", "e", "h", "l", "scx", "base_x", "base_y", "joy5", "frame_counter", "oam"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_intro_move_mon_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "IntroMoveMon")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
