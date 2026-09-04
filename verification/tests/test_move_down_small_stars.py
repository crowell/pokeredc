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
from verification.harness.rom import linked_bytes, rom_window, symbol_location

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
DONE = 0xEFFF
H_MOVE_COUNT = 0xCD3D
H_JOYPRESSED = 0xFFB3
H_JOYHELD = 0xFFB4
H_JOY5 = 0xFFB5
H_JOY6 = 0xFFB6
H_JOY7 = 0xFFB7
H_FRAMECOUNTER = 0xFFD5
H_VBLANK_OCCURRED = 0xFFD6
R_OBP1 = 0xFF49
W_SHADOW_OAM = 0xC300
W_SHADOW_OAM_SPRITE23 = W_SHADOW_OAM + 23 * 4
EXPECTED = bytes.fromhex("0608215cc3fa3dcd11fcff4f34190d20fbf049eea0e0490e03cdf812d80520e2c9")


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


class SetRegisterImmediate(angr.SimProcedure):
    def __init__(self, register: str, value: int, next_address: int) -> None:
        super().__init__()
        self.register = register
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.register, claripy.BVV(self.value, 8))
        self.jump(self.next_address)


class SetPairImmediate(angr.SimProcedure):
    def __init__(self, pair: str, value: int, next_address: int) -> None:
        super().__init__()
        self.pair = pair
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.pair, claripy.BVV(self.value, 16))
        self.jump(self.next_address)


class LoadMemoryA(angr.SimProcedure):
    def __init__(self, address: int, next_address: int) -> None:
        super().__init__()
        self.address = address
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self.address, 1)
        self.jump(self.next_address)


class StoreMemoryA(angr.SimProcedure):
    def __init__(self, address: int, next_address: int) -> None:
        super().__init__()
        self.address = address
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(self.address, self.state.regs.a)
        self.jump(self.next_address)


class XorImmediate(angr.SimProcedure):
    def __init__(self, value: int, next_address: int) -> None:
        super().__init__()
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.regs.a ^ self.value
        self.state.regs.f = claripy.If(self.state.regs.a == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        self.jump(self.next_address)


class SetCFromA(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.c = self.state.regs.a
        self.jump(self.next_address)


class CheckInterruptionSummary(angr.SimProcedure):
    def __init__(self, next_address: int, mode: str) -> None:
        super().__init__()
        self.next_address = next_address
        self.mode = mode

    def run(self) -> None:  # type: ignore[override]
        state = self.state
        state.memory.store(H_VBLANK_OCCURRED, claripy.BVV(0, 8))
        if self.mode == "held":
            state.memory.store(H_JOY5, claripy.BVV(0x46, 8))
            state.memory.store(H_FRAMECOUNTER, claripy.BVV(5, 8))
            state.regs.a = claripy.BVV(0x46, 8)
            state.regs.f = claripy.BVV(0x41, 8)
            self.jump(DONE)
            return
        if self.mode == "button":
            state.memory.store(H_JOY5, claripy.BVV(1, 8))
            state.memory.store(H_FRAMECOUNTER, claripy.BVV(30, 8))
            state.regs.a = claripy.BVV(1, 8)
            state.regs.f = claripy.BVV(0x01, 8)
            self.jump(DONE)
            return
        state.memory.store(H_JOY5, claripy.BVV(0, 8))
        state.memory.store(H_FRAMECOUNTER, claripy.BVV(5, 8))
        state.regs.a = claripy.BVV(0, 8)
        state.regs.f = claripy.BVV(0x50, 8)
        self.jump(self.next_address)


class ReturnCarry(angr.SimProcedure):
    def __init__(self, next_address: int, carry_f: int) -> None:
        super().__init__()
        self.next_address = next_address
        self.carry_f = carry_f

    def run(self) -> None:  # type: ignore[override]
        carry = int(self.state.solver.eval(self.state.regs.f & 0x01)) != 0
        if carry:
            self.state.regs.f = claripy.BVV(self.carry_f, 8)
        self.jump(DONE if carry else self.next_address)

class ReturnDone(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(DONE)


def _inputs(count: int, mode: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(f"move_down_{count}_{mode}")
    values["count"] = claripy.BVV(count, 8)
    values["obp1"] = claripy.BVS(f"move_down_obp1_{count}_{mode}", 8)
    values["oam"] = claripy.BVS(f"move_down_oam_{count}_{mode}", 0x100 * 8)
    inputs = {
        "held": (0, 0x46, 0, 1, 1),
        "button": (1, 0, 0, 1, 0),
        "timeout": (0, 0, 0, 1, 1),
    }
    pressed, held, joy5, joy6, joy7 = inputs[mode]
    values["joy_pressed"] = claripy.BVV(pressed, 8)
    values["joy_held"] = claripy.BVV(held, 8)
    values["joy5"] = claripy.BVV(joy5, 8)
    values["joy6"] = claripy.BVV(joy6, 8)
    values["joy7"] = claripy.BVV(joy7, 8)
    values["frame"] = claripy.BVV(0, 8)
    values["vblank"] = claripy.BVV(0, 8)
    return values


def _setup(state: angr.SimState, base: int, values: dict[str, claripy.ast.BV]) -> None:
    state.memory.store(base + H_MOVE_COUNT, values["count"])
    state.memory.store(base + R_OBP1, values["obp1"])
    state.memory.store(base + H_JOYPRESSED, values["joy_pressed"])
    state.memory.store(base + H_JOYHELD, values["joy_held"])
    state.memory.store(base + H_JOY5, values["joy5"])
    state.memory.store(base + H_JOY6, values["joy6"])
    state.memory.store(base + H_JOY7, values["joy7"])
    state.memory.store(base + H_FRAMECOUNTER, values["frame"])
    state.memory.store(base + H_VBLANK_OCCURRED, values["vblank"])
    state.memory.store(base + W_SHADOW_OAM, values["oam"])


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        state.memory.load(base + R_OBP1, 1),
        state.memory.load(base + H_JOY5, 1),
        state.memory.load(base + H_FRAMECOUNTER, 1),
        state.memory.load(base + H_VBLANK_OCCURRED, 1),
        state.memory.load(base + W_SHADOW_OAM, 0x100),
    )


def _assembly(values: dict[str, claripy.ast.BV], mode: str) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "MoveDownSmallStars")
    continuation = symbol_location(SYMBOLS, "GameFreakLogoOAMData")
    assert linked_bytes(ROM, location, continuation.address - location.address) == EXPECTED
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
    project.hook(base + 0x00, SetRegisterImmediate("b", 8, base + 0x02), length=2)
    project.hook(base + 0x02, SetPairImmediate("hl", W_SHADOW_OAM_SPRITE23, base + 0x05), length=3)
    project.hook(base + 0x05, LoadMemoryA(H_MOVE_COUNT, base + 0x08), length=3)
    project.hook(base + 0x08, SetPairImmediate("de", 0xFFFC, base + 0x0B), length=3)
    project.hook(base + 0x0B, SetCFromA(base + 0x0C), length=1)
    project.hook(base + 0x11, LoadMemoryA(R_OBP1, base + 0x13), length=2)
    project.hook(base + 0x13, XorImmediate(0xA0, base + 0x15), length=2)
    project.hook(base + 0x15, StoreMemoryA(R_OBP1, base + 0x17), length=2)
    project.hook(base + 0x17, SetRegisterImmediate("c", 3, base + 0x19), length=2)
    project.hook(base + 0x19, CheckInterruptionSummary(base + 0x1C, mode), length=3)
    carry_flags = {"held": 0x41, "button": 0x01, "timeout": 0x50}
    project.hook(base + 0x1C, ReturnCarry(base + 0x1D, carry_flags[mode]), length=1)
    project.hook(base + 0x20, ReturnDone(), length=1)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _setup(state, 0, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(DONE, 16), endness="Iend_LE")
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=16)
    assert not manager.errored
    return [
        Endpoint(
            **assembly_registers(end),
            memory=_memory(end, 0),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_move_down_small_stars")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, NATIVE_MEMORY, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=_memory(end, NATIVE_MEMORY),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("count", (1, 2))
@pytest.mark.parametrize("mode", ("held", "button", "timeout"))
def test_move_down_small_stars_pathwise_equivalence(count: int, mode: str) -> None:
    values = _inputs(count, mode)
    assert_pathwise_equivalent(_assembly(values, mode), _native(values), (*REGISTERS, "memory"))
