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
from verification.harness.rom import rom_window, symbol_location

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
STACK = 0xD000
RETURN = 0xFFFF

STATE_FIELDS = (
    "new_sound_id",
    "audio_rom_bank",
    "fade_control",
    "fade_reload",
    "fade_counter",
    "last_music_sound_id",
    "channel_0",
    "channel_1",
    "channel_2",
    "channel_3",
    "saved_rom_bank",
    "loaded_rom_bank",
    "rom_bank",
    "dispatch_called",
    "low_health_alarm",
)


class WaitForSoundToFinish(angr.SimProcedure):
    """Both terminal paths of the independently proven sound wait."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        alarm_set = self.state.globals["low_health_alarm"] & 0x80 != 0

        early = self.state.copy()
        early.add_constraints(alarm_set)
        self.successors.add_successor(
            early, self._next_address, claripy.BoolV(True), "Ijk_Boring"
        )

        waited = self.state.copy()
        for index in (0, 1, 3):
            waited.globals[f"channel_{index}"] = claripy.BVV(0, 8)
        waited.add_constraints(~alarm_set)
        self.successors.add_successor(
            waited, self._next_address, claripy.BoolV(True), "Ijk_Boring"
        )


class PlaySound(angr.SimProcedure):
    """Four terminal paths of the independently proven PlaySound port."""

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        new_sound = self.state.globals["new_sound_id"]
        fade = self.state.globals["fade_control"]
        last_music = self.state.globals["last_music_sound_id"]
        sound = self.state.regs.a

        def emit(condition: claripy.ast.Bool, kind: str) -> None:
            end = self.state.copy()
            for index in range(4):
                end.globals[f"channel_{index}"] = claripy.If(
                    new_sound != 0,
                    claripy.BVV(0, 8),
                    end.globals[f"channel_{index}"],
                )
            if kind == "queue":
                end.globals["new_sound_id"] = claripy.BVV(0, 8)
                end.globals["last_music_sound_id"] = sound
                end.globals["fade_reload"] = fade
                end.globals["fade_counter"] = fade
                end.globals["fade_control"] = sound
            elif kind in ("start", "immediate"):
                end.globals["new_sound_id"] = claripy.BVV(0, 8)
                end.globals["saved_rom_bank"] = end.globals["loaded_rom_bank"]
                end.globals["loaded_rom_bank"] = end.globals["audio_rom_bank"]
                end.globals["rom_bank"] = end.globals["audio_rom_bank"]
                end.globals["dispatch_called"] = claripy.BVV(1, 8)
                end.globals["loaded_rom_bank"] = end.globals["saved_rom_bank"]
                end.globals["rom_bank"] = end.globals["saved_rom_bank"]
                if kind == "immediate":
                    end.globals["fade_control"] = claripy.BVV(0, 8)
            end.add_constraints(condition)
            self.successors.add_successor(
                end, RETURN, claripy.BoolV(True), "Ijk_Boring"
            )

        emit(claripy.And(fade != 0, new_sound == 0), "return")
        emit(
            claripy.And(fade != 0, new_sound != 0, last_music != 0xFF),
            "queue",
        )
        emit(
            claripy.And(fade != 0, new_sound != 0, last_music == 0xFF),
            "immediate",
        )
        emit(fade == 0, "start")


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
    return values


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "PlaySoundWaitForCurrent")
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
    project.hook(base + 1, WaitForSoundToFinish(base + 4), length=3)
    project.hook(base + 5, PlaySound(), length=3)

    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.regs.sp = claripy.BVV(STACK, 16)
    for field in STATE_FIELDS:
        state.globals[field] = values[field]
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN, num_find=8)
    assert not manager.errored
    assert len(manager.found) == 8
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
    function = project.loader.find_symbol("port_play_sound_wait_for_current")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(
        NATIVE_STATE + 8,
        claripy.Concat(*(values[field] for field in STATE_FIELDS)),
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
def test_play_sound_wait_for_current_pathwise_equivalence() -> None:
    values = _inputs("play_sound_wait")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "memory"),
    )
