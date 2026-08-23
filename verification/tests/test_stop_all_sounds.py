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
DONE = 0xEFFF

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
    "audio_saved_rom_bank",
)


class StoreField(angr.SimProcedure):
    def __init__(self, field: str, next_address: int) -> None:
        super().__init__()
        self._field = field
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.globals[self._field] = self.state.regs.a
        self.jump(self._next_address)


class XorA(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x40, 8)
        self.jump(self._next_address)


class DecA(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a -= 1
        self.state.regs.f = claripy.BVV(0x12, 8)
        self.jump(self._next_address)


class PlaySoundStart(angr.SimProcedure):
    """Concrete no-fade path of the independently proven PlaySound port."""

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["new_sound_id"] = claripy.BVV(0, 8)
        self.state.globals["saved_rom_bank"] = self.state.globals[
            "loaded_rom_bank"
        ]
        self.state.globals["loaded_rom_bank"] = self.state.globals[
            "audio_rom_bank"
        ]
        self.state.globals["rom_bank"] = self.state.globals["audio_rom_bank"]
        self.state.globals["dispatch_called"] = claripy.BVV(1, 8)
        self.state.globals["loaded_rom_bank"] = self.state.globals[
            "saved_rom_bank"
        ]
        self.state.globals["rom_bank"] = self.state.globals["saved_rom_bank"]
        self.jump(DONE)


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


def _assembly(values: dict[str, claripy.ast.BV]) -> Endpoint:
    location = symbol_location(SYMBOLS, "StopAllSounds")
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
    project.hook(base + 2, StoreField("audio_rom_bank", base + 5), length=3)
    project.hook(
        base + 5,
        StoreField("audio_saved_rom_bank", base + 8),
        length=3,
    )
    project.hook(base + 8, XorA(base + 9), length=1)
    project.hook(base + 9, StoreField("fade_control", base + 12), length=3)
    project.hook(base + 12, StoreField("new_sound_id", base + 15), length=3)
    project.hook(
        base + 15,
        StoreField("last_music_sound_id", base + 18),
        length=3,
    )
    project.hook(base + 18, DecA(base + 19), length=1)
    project.hook(base + 19, PlaySoundStart(), length=3)

    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    for field in STATE_FIELDS:
        state.globals[field] = values[field]
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored
    assert len(manager.found) == 1
    end = manager.found[0]
    return Endpoint(
        **assembly_registers(end),
        memory=claripy.Concat(*(end.globals[field] for field in STATE_FIELDS)),
        constraints=tuple(end.solver.constraints),
    )


def _native(values: dict[str, claripy.ast.BV]) -> Endpoint:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_stop_all_sounds")
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
    assert len(manager.deadended) == 1
    end = manager.deadended[0]
    return Endpoint(
        **native_registers(end, NATIVE_STATE),
        memory=end.memory.load(NATIVE_STATE + 8, len(STATE_FIELDS)),
        constraints=tuple(end.solver.constraints),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_stop_all_sounds_pathwise_equivalence() -> None:
    values = _inputs("stop_all_sounds")
    assert_pathwise_equivalent(
        [_assembly(values)],
        [_native(values)],
        (*REGISTERS, "memory"),
    )
