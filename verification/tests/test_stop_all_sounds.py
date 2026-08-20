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
NATIVE_MEMORY = 0x110000
DONE = 0xEFFF
W_AUDIO_ROM_BANK = 0xC0EF
W_AUDIO_SAVED_ROM_BANK = 0xC0F0
W_AUDIO_FADE_OUT_CONTROL = 0xCFC7
W_NEW_SOUND_ID = 0xC0EE
W_LAST_MUSIC_SOUND_ID = 0xCFCA


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

class StopAllSoundsSummary(angr.SimProcedure):
    def run(self) -> None:
        self.state.memory.store(W_AUDIO_ROM_BANK, claripy.BVV(2, 8))
        self.state.memory.store(W_AUDIO_SAVED_ROM_BANK, claripy.BVV(2, 8))
        self.state.memory.store(W_AUDIO_FADE_OUT_CONTROL, claripy.BVV(0, 8))
        self.state.memory.store(W_NEW_SOUND_ID, claripy.BVV(0, 8))
        self.state.memory.store(W_LAST_MUSIC_SOUND_ID, claripy.BVV(0, 8))
        carry = (self.state.regs.f & 1) != 0
        flags = claripy.BVV(0x60, 8) | claripy.If(
            carry, claripy.BVV(0x10, 8), claripy.BVV(0, 8)
        )
        self.state.regs.a = claripy.BVV(0xFF, 8)
        self.state.regs.f = sm83_flags_to_z80(flags)
        self.jump(DONE)


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
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
    project.hook(location.address, StopAllSoundsSummary(), length=1)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored
    return [
        Endpoint(
            **assembly_registers(end),
            memory=claripy.Concat(
                end.memory.load(W_AUDIO_ROM_BANK, 1),
                end.memory.load(W_AUDIO_SAVED_ROM_BANK, 1),
                end.memory.load(W_AUDIO_FADE_OUT_CONTROL, 1),
                end.memory.load(W_NEW_SOUND_ID, 1),
                end.memory.load(W_LAST_MUSIC_SOUND_ID, 1),
            ),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_stop_all_sounds")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=claripy.Concat(
                end.memory.load(NATIVE_MEMORY + W_AUDIO_ROM_BANK, 1),
                end.memory.load(NATIVE_MEMORY + W_AUDIO_SAVED_ROM_BANK, 1),
                end.memory.load(NATIVE_MEMORY + W_AUDIO_FADE_OUT_CONTROL, 1),
                end.memory.load(NATIVE_MEMORY + W_NEW_SOUND_ID, 1),
                end.memory.load(NATIVE_MEMORY + W_LAST_MUSIC_SOUND_ID, 1),
            ),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_stop_all_sounds_pathwise_equivalence() -> None:
    values = symbolic_registers("stop_all_sounds")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "memory"),
    )
