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
from verification.harness.rom import (
    collect_returns,
    linked_bytes,
    rom_window,
    sm83_flags_to_z80,
    symbol_location,
)
from verification.harness.sm83_shims import (
    Sm83AddHlRegisterPair,
    Sm83AddRegister,
    Sm83AndImmediate,
    Sm83DecRegister,
)


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_CALLBACK = 0x100100
NATIVE_GLOBALS = 0x100200
STACK = 0xD000
RETURN = 0xFFFF
WHOSE_TURN = 0xFFF3
PLAYER_EFFECT = 0xCFD3
ENEMY_EFFECT = 0xCFCD
STATE_KEYS = (
    "whose_turn",
    "player_move_effect",
    "enemy_move_effect",
    "fetched_low",
    "fetched_high",
    "dispatched",
)
CALLBACK_KEYS = ("whose_turn", "player_move_effect", "enemy_move_effect")


class ReadGlobal(angr.SimProcedure):
    def __init__(self, key: str, next_address: int) -> None:
        super().__init__()
        self.key = key
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals[self.key]
        self.jump(self.next_address)


class FetchLow(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals["fetched_low"]
        self.state.regs.hl = self.state.regs.hl + 1
        self.jump(self.next_address)


class FetchHigh(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = self.state.globals["fetched_high"]
        self.jump(self.next_address)


class TailBoundary(angr.SimProcedure):
    def __init__(self, full: bool) -> None:
        super().__init__()
        self.full = full

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["dispatched"] = claripy.BVV(1, 8)
        if self.full:
            callback = self.state.globals["callback"]
            for register in REGISTERS:
                value = callback[register]
                if register == "f":
                    value = sm83_flags_to_z80(value)
                setattr(self.state.regs, register, value)
            for key in CALLBACK_KEYS:
                self.state.globals[key] = callback[key]
        self.jump(RETURN)


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


def inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for key in STATE_KEYS:
        values[key] = claripy.BVS(f"{prefix}_{key}", 8)
    callback = symbolic_registers(f"{prefix}_callback")
    for register, value in callback.items():
        values[f"callback_{register}"] = value
    for key in CALLBACK_KEYS:
        values[f"callback_{key}"] = claripy.BVS(f"{prefix}_callback_{key}", 8)
    return values


def assembly(values: dict[str, claripy.ast.BV], full: bool) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "_JumpMoveEffect")
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
    q = location.address
    project.hook(q, ReadGlobal("whose_turn", q + 2), length=2)
    project.hook(q + 2, Sm83AndImmediate(0xFF, q + 3), length=1)
    project.hook(q + 3, ReadGlobal("player_move_effect", q + 6), length=3)
    project.hook(q + 8, ReadGlobal("enemy_move_effect", q + 11), length=3)
    project.hook(q + 11, Sm83DecRegister("a", q + 12), length=1)
    project.hook(q + 12, Sm83AddRegister("a", q + 13), length=1)
    project.hook(q + 19, Sm83AddHlRegisterPair("bc", q + 20), length=1)
    project.hook(q + 20, FetchLow(q + 21), length=1)
    project.hook(q + 21, FetchHigh(q + 22), length=1)
    project.hook(q + 23, TailBoundary(full), length=1)

    state = project.factory.blank_state(addr=q)
    set_assembly_registers(state, values)
    for key in STATE_KEYS[:-1]:
        state.globals[key] = values[key]
    state.globals["dispatched"] = claripy.BVV(0, 8)
    state.globals["callback"] = {
        register: values[f"callback_{register}"] for register in REGISTERS
    } | {key: values[f"callback_{key}"] for key in CALLBACK_KEYS}
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    endpoints = []
    for end in collect_returns(project, state, RETURN):
        memory = [end.globals[key] for key in STATE_KEYS]
        if full:
            memory.extend(end.globals["callback"][register] for register in REGISTERS)
            memory.extend(end.globals["callback"][key] for key in CALLBACK_KEYS)
        endpoints.append(
            Endpoint(
                **assembly_registers(end),
                memory=claripy.Concat(*memory),
                constraints=tuple(end.solver.constraints),
            )
        )
    return endpoints


def native(values: dict[str, claripy.ast.BV], full: bool) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    symbol = "port_jump_move_effect" if full else "port_jump_move_effect_begin"
    function = project.loader.find_symbol(symbol)
    assert function
    if full:
        state = project.factory.call_state(
            function.rebased_addr, NATIVE_STATE, NATIVE_CALLBACK, NATIVE_GLOBALS
        )
    else:
        state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(
        NATIVE_STATE + 8, claripy.Concat(*(values[key] for key in STATE_KEYS))
    )
    if full:
        callback_registers = {
            register: values[f"callback_{register}"] for register in REGISTERS
        }
        store_native_registers(state, NATIVE_CALLBACK, callback_registers)
        state.memory.store(
            NATIVE_GLOBALS,
            claripy.Concat(*(values[f"callback_{key}"] for key in CALLBACK_KEYS)),
        )
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    endpoints = []
    for end in manager.deadended:
        memory = [end.memory.load(NATIVE_STATE + 8, len(STATE_KEYS))]
        if full:
            memory.append(end.memory.load(NATIVE_CALLBACK, len(REGISTERS)))
            memory.append(end.memory.load(NATIVE_GLOBALS, len(CALLBACK_KEYS)))
        endpoints.append(
            Endpoint(
                **native_registers(end, NATIVE_STATE),
                memory=claripy.Concat(*memory),
                constraints=tuple(end.solver.constraints),
            )
        )
    return endpoints


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native")
@pytest.mark.parametrize("full", (False, True))
def test_equivalence(full: bool) -> None:
    values = inputs(f"jump_move_effect_{full}")
    assert_pathwise_equivalent(
        assembly(values, full), native(values, full), (*REGISTERS, "memory")
    )


def test_exact_body() -> None:
    location = symbol_location(SYMBOLS, "_JumpMoveEffect")
    assert linked_bytes(ROM, location, 24) == bytes.fromhex(
        "f0f3a7fad3cf2803facdcf3d8721507106004f092a666fe9"
    )
    assert symbol_location(SYMBOLS, "MoveEffectPointerTable").address == 0x7150
    assert symbol_location(SYMBOLS, "hWhoseTurn").address == WHOSE_TURN
    assert symbol_location(SYMBOLS, "wPlayerMoveEffect").address == PLAYER_EFFECT
    assert symbol_location(SYMBOLS, "wEnemyMoveEffect").address == ENEMY_EFFECT
