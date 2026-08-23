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
from verification.harness.rom import rom_window, sm83_flags_to_z80, symbol_location

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_CALLBACK = 0x100100
NATIVE_GLOBALS = 0x100200
RETURN = 0xFFFF

STATE_FIELDS = (
    "status_flags4",
    "last_music_sound_id",
    "dispatched",
    "low_health_alarm",
    "channel_0",
    "channel_1",
    "channel_2",
)


class WaitForSoundToFinish(angr.SimProcedure):
    """Both terminal paths of the independently proven sound wait."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        alarm = self.state.globals["low_health_alarm"]
        alarm_set = alarm & 0x80 != 0

        early = self.state.copy()
        early.regs.a = alarm & 0x80
        early.regs.f = claripy.BVV(0x10, 8)
        early.add_constraints(alarm_set)
        self.successors.add_successor(
            early, self._next_address, claripy.BoolV(True), "Ijk_Boring"
        )

        waited = self.state.copy()
        waited.regs.a = claripy.BVV(0, 8)
        waited.regs.f = claripy.BVV(0x40, 8)
        for index in range(3):
            waited.globals[f"channel_{index}"] = claripy.BVV(0, 8)
        waited.add_constraints(~alarm_set)
        self.successors.add_successor(
            waited, self._next_address, claripy.BoolV(True), "Ijk_Boring"
        )


class StoreLastMusicSoundId(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["last_music_sound_id"] = self.state.regs.a
        self.jump(self._next_address)


class PlayDefaultMusicCommon(angr.SimProcedure):
    """Arbitrary post-state of the separately proven common continuation."""

    def run(self) -> None:  # type: ignore[override]
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
        self.state.globals["dispatched"] = claripy.BVV(1, 8)
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


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for field in STATE_FIELDS:
        values[field] = claripy.BVS(f"{prefix}_{field}", 8)
    for register, value in symbolic_registers(f"{prefix}_callback").items():
        values[f"callback_{register}"] = value
    values["callback_status_flags4"] = claripy.BVS(
        f"{prefix}_callback_status_flags4", 8
    )
    values["callback_last_music_sound_id"] = claripy.BVS(
        f"{prefix}_callback_last_music_sound_id", 8
    )
    return values


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "PlayDefaultMusic")
    common = symbol_location(SYMBOLS, "PlayDefaultMusicCommon")
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
    project.hook(base, WaitForSoundToFinish(base + 3), length=3)
    project.hook(base + 6, StoreLastMusicSoundId(base + 9), length=3)
    project.hook(common.address, PlayDefaultMusicCommon(), length=1)

    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    for field in STATE_FIELDS:
        state.globals[field] = values[field]
    state.globals["callback"] = {
        register: values[f"callback_{register}"] for register in REGISTERS
    } | {
        "status_flags4": values["callback_status_flags4"],
        "last_music_sound_id": values["callback_last_music_sound_id"],
    }
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN, num_find=2)
    assert not manager.errored
    assert len(manager.found) == 2
    return [
        Endpoint(
            **assembly_registers(end),
            memory=claripy.Concat(*(end.globals[field] for field in STATE_FIELDS)),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_play_default_music")
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_CALLBACK, NATIVE_GLOBALS
    )
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(
        NATIVE_STATE + 8,
        claripy.Concat(*(values[field] for field in STATE_FIELDS)),
    )
    store_native_registers(
        state,
        NATIVE_CALLBACK,
        {register: values[f"callback_{register}"] for register in REGISTERS},
    )
    state.memory.store(
        NATIVE_GLOBALS,
        claripy.Concat(
            values["callback_status_flags4"],
            values["callback_last_music_sound_id"],
        ),
    )
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=end.memory.load(NATIVE_STATE + 8, len(STATE_FIELDS)),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_play_default_music_pathwise_equivalence() -> None:
    values = _inputs("play_default_music")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "memory"),
    )
