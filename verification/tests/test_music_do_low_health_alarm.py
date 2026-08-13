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
    symbol_location,
)
from verification.harness.sm83_shims import (
    Sm83AndImmediate,
    Sm83BitRegister,
    Sm83CpImmediate,
    Sm83DecRegister,
)


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
STACK = 0xD000
RETURN = 0xFFFF
ALARM = 0xD083
CHANNEL5 = 0xC02A
AUDIO1 = 0xFF10
KEYS = (
    "low_health_alarm",
    "channel5_sound_id",
    "audio0",
    "audio1",
    "audio2",
    "audio3",
    "audio4",
)


class ReadFixed(angr.SimProcedure):
    def __init__(self, key: str, next_address: int) -> None:
        super().__init__()
        self.key = key
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals[self.key]
        self.jump(self.next_address)


class StoreFixed(angr.SimProcedure):
    def __init__(self, key: str, next_address: int) -> None:
        super().__init__()
        self.key = key
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.globals[self.key] = self.state.regs.a
        self.jump(self.next_address)


class SetBit(angr.SimProcedure):
    def __init__(self, bit: int, next_address: int) -> None:
        super().__init__()
        self.bit = bit
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.regs.a | (1 << self.bit)
        self.jump(self.next_address)


class XorA(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x40, 8)
        self.jump(self.next_address)


class StoreAudioIncrement(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        target = self.state.regs.hl
        audio = self.state.globals["audio"]
        self.state.globals["audio"] = [
            claripy.If(target == AUDIO1 + index, self.state.regs.a, audio[index])
            for index in range(5)
        ]
        self.state.regs.hl = target + 1
        self.jump(self.next_address)


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
    return values


def assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "Music_DoLowHealthAlarm")
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
    project.hook(q, ReadFixed("low_health_alarm", q + 3), length=3)
    project.hook(q + 3, Sm83CpImmediate(0xFF, q + 5), length=2)
    project.hook(q + 7, Sm83BitRegister(7, "a", q + 9), length=2)
    project.hook(q + 10, Sm83AndImmediate(0x7F, q + 12), length=2)
    project.hook(q + 21, Sm83CpImmediate(20, q + 23), length=2)
    project.hook(q + 30, StoreFixed("channel5_sound_id", q + 33), length=3)
    project.hook(q + 33, ReadFixed("low_health_alarm", q + 36), length=3)
    project.hook(q + 36, Sm83AndImmediate(0x7F, q + 38), length=2)
    project.hook(q + 38, Sm83DecRegister("a", q + 39), length=1)
    project.hook(q + 39, SetBit(7, q + 41), length=2)
    project.hook(q + 41, StoreFixed("low_health_alarm", q + 44), length=3)
    project.hook(q + 45, XorA(q + 46), length=1)
    project.hook(q + 46, StoreFixed("low_health_alarm", q + 49), length=3)
    project.hook(q + 49, StoreFixed("channel5_sound_id", q + 52), length=3)
    project.hook(q + 70, XorA(q + 71), length=1)
    project.hook(q + 71, StoreAudioIncrement(q + 72), length=1)
    project.hook(q + 74, Sm83DecRegister("c", q + 75), length=1)

    state = project.factory.blank_state(addr=q)
    set_assembly_registers(state, values)
    state.globals["low_health_alarm"] = values["low_health_alarm"]
    state.globals["channel5_sound_id"] = values["channel5_sound_id"]
    state.globals["audio"] = [values[f"audio{index}"] for index in range(5)]
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    return [
        Endpoint(
            **assembly_registers(end),
            memory=claripy.Concat(
                end.globals["low_health_alarm"],
                end.globals["channel5_sound_id"],
                *end.globals["audio"],
            ),
            constraints=tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, RETURN)
    ]


def native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_music_do_low_health_alarm")
    assert function
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(
        NATIVE_STATE + 8, claripy.Concat(*(values[key] for key in KEYS))
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
def test_equivalence() -> None:
    values = inputs("music_low_health_alarm")
    assert_pathwise_equivalent(
        assembly(values), native(values), (*REGISTERS, "memory")
    )


def test_exact_body_and_tone_overreads() -> None:
    location = symbol_location(SYMBOLS, "Music_DoLowHealthAlarm")
    tone = symbol_location(SYMBOLS, "Music_DoLowHealthAlarm.toneDataHi")
    assert linked_bytes(ROM, location, 78) == bytes.fromhex(
        "fa83d0feff2826cb7fc8e67f2007cda7533e1e1812fe142003cdac533e86"
        "ea2ac0fa83d0e67f3dcbffea83d0c9afea83d0ea2ac011c453180811bc53"
        "180311c0532110ff0e05af221a130d20fac9"
    )
    assert linked_bytes(ROM, tone, 13) == bytes.fromhex(
        "a0e25087b0e2ee8600000080af"
    )
    assert symbol_location(SYMBOLS, "wLowHealthAlarm").address == ALARM
    assert symbol_location(SYMBOLS, "wChannelSoundIDs").address + 4 == CHANNEL5
