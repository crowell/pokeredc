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
from verification.harness.sm83_shims import Sm83BitRegister


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_CALLBACK = 0x100100
NATIVE_GLOBALS = 0x100200
STACK = 0xD000
RETURN = 0xFFFF
KEYS = ("status_flags4", "last_music_sound_id", "dispatched")


class ReadGlobal(angr.SimProcedure):
    def __init__(self, key: str, next_address: int) -> None:
        super().__init__()
        self.key = key
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals[self.key]
        self.jump(self.next_address)


class StoreGlobal(angr.SimProcedure):
    def __init__(self, key: str, next_address: int) -> None:
        super().__init__()
        self.key = key
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.globals[self.key] = self.state.regs.a
        self.jump(self.next_address)


class XorA(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x40, 8)
        self.jump(self.next_address)


class CommonBoundary(angr.SimProcedure):
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
            self.state.globals["status_flags4"] = callback["status_flags4"]
            self.state.globals["last_music_sound_id"] = callback[
                "last_music_sound_id"
            ]
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
    for key in KEYS:
        values[key] = claripy.BVS(f"{prefix}_{key}", 8)
    callback = symbolic_registers(f"{prefix}_callback")
    for register, value in callback.items():
        values[f"callback_{register}"] = value
    for key in KEYS[:2]:
        values[f"callback_{key}"] = claripy.BVS(f"{prefix}_callback_{key}", 8)
    return values


def assembly(values: dict[str, claripy.ast.BV], full: bool) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "PlayDefaultMusicFadeOutCurrent")
    common = symbol_location(SYMBOLS, "PlayDefaultMusicCommon").address
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
    project.hook(q + 4, ReadGlobal("status_flags4", q + 7), length=3)
    project.hook(q + 7, Sm83BitRegister(5, "a", q + 9), length=2)
    project.hook(q + 11, XorA(q + 12), length=1)
    project.hook(q + 12, StoreGlobal("last_music_sound_id", q + 15), length=3)
    project.hook(common, CommonBoundary(full))

    state = project.factory.blank_state(addr=q)
    set_assembly_registers(state, values)
    state.globals["status_flags4"] = values["status_flags4"]
    state.globals["last_music_sound_id"] = values["last_music_sound_id"]
    state.globals["dispatched"] = values["dispatched"]
    state.globals["callback"] = {
        register: values[f"callback_{register}"] for register in REGISTERS
    } | {key: values[f"callback_{key}"] for key in KEYS[:2]}
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    return [
        Endpoint(
            **assembly_registers(end),
            memory=claripy.Concat(*(end.globals[key] for key in KEYS)),
            constraints=tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, RETURN)
    ]


def native(values: dict[str, claripy.ast.BV], full: bool) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    symbol = (
        "port_play_default_music_fade_out_current"
        if full
        else "port_play_default_music_fade_out_current_begin"
    )
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
        NATIVE_STATE + 8, claripy.Concat(*(values[key] for key in KEYS))
    )
    if full:
        callback = {
            register: values[f"callback_{register}"] for register in REGISTERS
        }
        store_native_registers(state, NATIVE_CALLBACK, callback)
        state.memory.store(
            NATIVE_GLOBALS,
            claripy.Concat(*(values[f"callback_{key}"] for key in KEYS[:2])),
        )
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=end.memory.load(NATIVE_STATE + 8, len(KEYS)),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native")
@pytest.mark.parametrize("full", (False, True))
def test_equivalence(full: bool) -> None:
    values = inputs(f"default_music_fade_{full}")
    assert_pathwise_equivalent(
        assembly(values, full), native(values, full), (*REGISTERS, "memory")
    )


def test_exact_entry() -> None:
    location = symbol_location(SYMBOLS, "PlayDefaultMusicFadeOutCurrent")
    assert linked_bytes(ROM, location, 18) == bytes.fromhex(
        "0e0a1600fa2ed7cb6f2807afeacacf0e0851"
    )
    assert symbol_location(SYMBOLS, "wStatusFlags4").address == 0xD72E
    assert symbol_location(SYMBOLS, "wLastMusicSoundID").address == 0xCFCA
