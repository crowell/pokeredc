from __future__ import annotations

from dataclasses import dataclass
from functools import cache
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
from verification.harness.rom import (
    collect_returns,
    linked_bytes,
    rom_window,
    symbol_location,
)
from verification.harness.sm83_shims import (
    Sm83DecRegister,
    Sm83LoadAAtHlIncrement,
    Sm83OrRegister,
    Sm83SwapRegister,
)


ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xE000
RETURN = 0xFFFF
W_PLAYER_SELECTED_MOVE = 0xCCDC
W_BATTLE_MON_PP = 0xD02D
W_PLAYER_DISABLED_MOVE = 0xD06D
W_TEXT_BOX_ID = 0xD125
H_VBLANK_OCCURRED = 0xFFD6
EXPECTED = bytes.fromhex(
    "3ea5eadcccfa6dd0a7212dd0200b2ab623b623b6e63fc01815cb37e60f47"
    "1605af1528084e230528f8b118f5a7c0213054cd493c0e3ccd3937afc9"
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
    memory: claripy.ast.BV
    print_call: claripy.ast.BV
    delay_call: claripy.ast.BV
    trace: claripy.ast.BV
    iterations: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _register_bytes(state: angr.SimState) -> claripy.ast.BV:
    registers = assembly_registers(state)
    return claripy.Concat(*(registers[name] for name in REGISTERS))


def _memory(state: angr.SimState, base: int, native: bool) -> claripy.ast.BV:
    vblank = (
        state.memory.load(NATIVE_STATE + 8, 1)
        if native
        else state.memory.load(H_VBLANK_OCCURRED, 1)
    )
    return claripy.Concat(
        state.memory.load(base + W_PLAYER_SELECTED_MOVE, 1),
        state.memory.load(base + W_PLAYER_DISABLED_MOVE, 1),
        state.memory.load(base + W_BATTLE_MON_PP, 4),
        state.memory.load(base + W_TEXT_BOX_ID, 1),
        vblank,
    )


class LoadAbsolute(angr.SimProcedure):
    def __init__(self, address: int, continuation: int) -> None:
        super().__init__()
        self.address = address
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self.address, 1)
        self.jump(self.continuation)


class StoreAbsolute(angr.SimProcedure):
    def __init__(self, address: int, continuation: int) -> None:
        super().__init__()
        self.address = address
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(self.address, self.state.regs.a)
        self.jump(self.continuation)


class AndImmediate(angr.SimProcedure):
    def __init__(self, value: int, continuation: int) -> None:
        super().__init__()
        self.value = value
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a &= self.value
        self.state.regs.f = claripy.BVV(0x10, 8) | claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x40, 8),
            claripy.BVV(0, 8),
        )
        self.jump(self.continuation)


class OrAtHL(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a |= self.state.memory.load(self.state.regs.hl, 1)
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x40, 8),
            claripy.BVV(0, 8),
        )
        self.jump(self.continuation)


class IncHL(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.hl += 1
        self.jump(self.continuation)


class LoadCAtHL(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.c = self.state.memory.load(self.state.regs.hl, 1)
        self.jump(self.continuation)


class XorA(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = 0
        self.state.regs.f = 0x40
        self.jump(self.continuation)


class AssemblyPrint(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["print_call"] = _register_bytes(self.state)
        self.state.globals["trace"] = self.state.globals["trace"] * 16 + 1
        self.state.memory.store(W_TEXT_BOX_ID, claripy.BVV(1, 8))
        self.state.regs.b = 0xC4
        self.state.regs.c = 0xB9
        self.jump(self.continuation)


class NativePrint(angr.SimProcedure):
    def run(
        self, address: claripy.ast.BV, memory: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        assert not memory.symbolic and self.state.solver.eval(memory) == NATIVE_MEMORY
        self.state.globals["print_call"] = self.state.memory.load(address, 8)
        self.state.globals["trace"] = self.state.globals["trace"] * 16 + 1
        self.state.memory.store(address + 2, claripy.BVV(0xC4B9, 16))
        self.state.memory.store(memory + W_TEXT_BOX_ID, claripy.BVV(1, 8))


class AssemblyDelayFrames(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["delay_call"] = _register_bytes(self.state)
        self.state.globals["trace"] = self.state.globals["trace"] * 16 + 2
        self.state.globals["iterations"] = claripy.BVV(60, 16)
        self.state.regs.a = 0
        self.state.regs.c = 0
        self.state.regs.f = 0x42
        self.state.memory.store(H_VBLANK_OCCURRED, claripy.BVV(0, 8))
        self.jump(self.continuation)


class NativeDelayFramesStep(angr.SimProcedure):
    def run(
        self, address: claripy.ast.BV, observations: claripy.ast.BV
    ) -> claripy.ast.BV:  # type: ignore[override]
        del observations
        if self.state.solver.eval(self.state.globals["iterations"]) == 0:
            self.state.globals["delay_call"] = self.state.memory.load(address, 8)
            self.state.globals["trace"] = self.state.globals["trace"] * 16 + 2
        self.state.globals["iterations"] += 1
        before = self.state.memory.load(address + 3, 1)
        result = before - 1
        flags = claripy.BVV(0x40, 8)
        flags |= claripy.If(result == 0, claripy.BVV(0x80, 8), claripy.BVV(0, 8))
        flags |= claripy.If(
            (before & 0x0F) == 0,
            claripy.BVV(0x20, 8),
            claripy.BVV(0, 8),
        )
        self.state.memory.store(address, claripy.BVV(0, 8))
        self.state.memory.store(address + 1, flags)
        self.state.memory.store(address + 3, result)
        self.state.memory.store(address + 8, claripy.BVV(0, 8))
        self.state.memory.store(address + 9, claripy.BVV(0, 8))
        return claripy.If(
            result != 0, claripy.BVV(1, 64), claripy.BVV(0, 64)
        )


def _inputs() -> dict[str, claripy.ast.BV]:
    values = symbolic_registers("any_move_to_select")
    for name in ("selected", "disabled", "textbox", "vblank"):
        values[name] = claripy.BVS(f"any_move_to_select_{name}", 8)
    for offset in range(4):
        values[f"pp_{offset}"] = claripy.BVS(
            f"any_move_to_select_pp_{offset}", 8
        )
    return values


def _setup(
    state: angr.SimState, values: dict[str, claripy.ast.BV], native: bool
) -> None:
    base = NATIVE_MEMORY if native else 0
    state.memory.store(base + W_PLAYER_SELECTED_MOVE, values["selected"])
    state.memory.store(base + W_PLAYER_DISABLED_MOVE, values["disabled"])
    for offset in range(4):
        state.memory.store(base + W_BATTLE_MON_PP + offset, values[f"pp_{offset}"])
    state.memory.store(base + W_TEXT_BOX_ID, values["textbox"])
    if native:
        state.memory.store(NATIVE_STATE + 8, values["vblank"])
    else:
        state.memory.store(H_VBLANK_OCCURRED, values["vblank"])
    state.globals["print_call"] = claripy.BVV(0, 64)
    state.globals["delay_call"] = claripy.BVV(0, 64)
    state.globals["trace"] = claripy.BVV(0, 16)
    state.globals["iterations"] = claripy.BVV(0, 16)


def _endpoint(state: angr.SimState, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    registers = (
        native_registers(state, NATIVE_STATE)
        if native
        else assembly_registers(state)
    )
    return Endpoint(
        **registers,
        memory=_memory(state, base, native),
        print_call=state.globals["print_call"],
        delay_call=state.globals["delay_call"],
        trace=state.globals["trace"],
        iterations=state.globals["iterations"],
        constraints=tuple(state.solver.constraints),
    )


@cache
def _assembly_project() -> tuple[angr.Project, int]:
    location = symbol_location(SYMS, "AnyMoveToSelect")
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
    project.hook(base + 2, StoreAbsolute(W_PLAYER_SELECTED_MOVE, base + 5), length=3)
    project.hook(base + 5, LoadAbsolute(W_PLAYER_DISABLED_MOVE, base + 8), length=3)
    project.hook(base + 8, AndImmediate(0xFF, base + 9), length=1)
    project.hook(base + 14, Sm83LoadAAtHlIncrement(base + 15), length=1)
    project.hook(base + 15, OrAtHL(base + 16), length=1)
    project.hook(base + 16, IncHL(base + 17), length=1)
    project.hook(base + 17, OrAtHL(base + 18), length=1)
    project.hook(base + 18, IncHL(base + 19), length=1)
    project.hook(base + 19, OrAtHL(base + 20), length=1)
    project.hook(base + 20, AndImmediate(0x3F, base + 22), length=2)
    project.hook(base + 25, Sm83SwapRegister("a", base + 27), length=2)
    project.hook(base + 27, AndImmediate(0x0F, base + 29), length=2)
    project.hook(base + 32, XorA(base + 33), length=1)
    project.hook(base + 33, Sm83DecRegister("d", base + 34), length=1)
    project.hook(base + 36, LoadCAtHL(base + 37), length=1)
    project.hook(base + 37, IncHL(base + 38), length=1)
    project.hook(base + 38, Sm83DecRegister("b", base + 39), length=1)
    project.hook(base + 41, Sm83OrRegister("c", base + 42), length=1)
    project.hook(base + 44, AndImmediate(0xFF, base + 45), length=1)
    project.hook(base + 49, AssemblyPrint(base + 52), length=3)
    project.hook(base + 54, AssemblyDelayFrames(base + 57), length=3)
    project.hook(base + 57, XorA(base + 58), length=1)
    return project, base


@cache
def _native_project() -> tuple[angr.Project, int]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_any_move_to_select")
    print_text = project.loader.find_symbol("port_print_text")
    delay_step = project.loader.find_symbol("port_delay_frames_step")
    assert function is not None and print_text is not None and delay_step is not None
    project.hook(print_text.rebased_addr, NativePrint())
    project.hook(delay_step.rebased_addr, NativeDelayFramesStep())
    return project, function.rebased_addr


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, base = _assembly_project()
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _setup(state, values, False)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    return [_endpoint(end, False) for end in collect_returns(project, state, RETURN)]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, function = _native_project()
    state = project.factory.call_state(function, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, values, True)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [_endpoint(end, True) for end in manager.deadended]


@pytest.mark.skipif(
    not ELF.exists() or not ROM.exists() or not SYMS.exists(), reason="build"
)
def test_any_move_to_select_pathwise_equivalence() -> None:
    location = symbol_location(SYMS, "AnyMoveToSelect")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    values = _inputs()
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (
            *REGISTERS,
            "memory",
            "print_call",
            "delay_call",
            "trace",
            "iterations",
        ),
    )
