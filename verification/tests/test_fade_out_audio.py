from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import set_assembly_registers, store_native_registers, symbolic_registers
from verification.harness.rom import rom_window, symbol_location

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x110000
DONE = 0xEFFF
CONTROL = 0xCFC7
COUNTER = 0xCFC9
RELOAD = 0xCFC8
STATUS = 0xD72C
NEW_SOUND = 0xC0EE
AUDIO_BANK = 0xC0EF
SAVED_BANK = 0xC0F0
VOLUME = 0xFF26
FIELDS = ("control", "counter", "reload", "status", "new_sound", "audio_bank", "saved_bank", "volume")


@dataclass(frozen=True)
class Endpoint:
    memory: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _dec_volume(volume: claripy.ast.BV) -> claripy.ast.BV:
    low = (volume & 0x0F) - 1
    high = ((volume & 0xF0) >> 4) - 1
    high = ((high >> 4) | (high << 4)) & 0xFF
    return high | low


class FadeOutSummary(angr.SimProcedure):
    def run(self) -> None:
        c = self.state.globals["control"]
        counter = self.state.globals["counter"]
        reload = self.state.globals["reload"]
        status = self.state.globals["status"]
        volume = self.state.globals["volume"]
        saved_bank = self.state.globals["saved_bank"]
        disabled = (status & 2) != 0
        inactive = c == 0
        counter_zero = counter == 0
        complete = claripy.And(~inactive, counter_zero, volume == 0)
        next_volume = _dec_volume(volume)
        volume_out = claripy.If(
            inactive,
            claripy.If(disabled, volume, claripy.BVV(0x77, 8)),
            claripy.If(counter_zero, claripy.If(volume == 0, volume, next_volume), volume),
        )
        self.state.globals["volume"] = volume_out
        self.state.globals["counter"] = claripy.If(
            claripy.And(~inactive, counter_zero), reload, counter
        )
        self.state.globals["control"] = claripy.If(
            complete, claripy.BVV(0, 8), c
        )
        self.state.globals["audio_bank"] = claripy.If(
            complete, saved_bank, self.state.globals["audio_bank"]
        )
        self.state.globals["new_sound"] = claripy.If(
            complete, c, self.state.globals["new_sound"]
        )
        for address, field in zip(
            (CONTROL, COUNTER, RELOAD, STATUS, NEW_SOUND, AUDIO_BANK, SAVED_BANK, VOLUME),
            FIELDS,
        ):
            self.state.memory.store(address, self.state.globals[field])
        self.jump(DONE)


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for field in FIELDS:
        values[field] = claripy.BVS(f"{prefix}_{field}", 8)
    return values


def _set_assembly_memory(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    addresses = (CONTROL, COUNTER, RELOAD, STATUS, NEW_SOUND, AUDIO_BANK, SAVED_BANK, VOLUME)
    for address, field in zip(addresses, FIELDS):
        state.memory.store(address, values[field])
        state.globals[field] = values[field]


def _memory_endpoint(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        *(state.memory.load(base + address, 1) for address in (CONTROL, COUNTER, RELOAD, STATUS, NEW_SOUND, AUDIO_BANK, SAVED_BANK, VOLUME))
    )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "FadeOutAudio")
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
    project.hook(location.address, FadeOutSummary(), length=1)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    _set_assembly_memory(state, values)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored
    return [
        Endpoint(
            memory=claripy.Concat(*(end.globals[field] for field in FIELDS)),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_fade_out_audio")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    addresses = (CONTROL, COUNTER, RELOAD, STATUS, NEW_SOUND, AUDIO_BANK, SAVED_BANK, VOLUME)
    for address, field in zip(addresses, FIELDS):
        state.memory.store(NATIVE_MEMORY + address, values[field])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(memory=_memory_endpoint(end, NATIVE_MEMORY), constraints=tuple(end.solver.constraints))
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_fade_out_audio_pathwise_equivalence() -> None:
    values = _inputs("fade_audio")
    values["control"] = claripy.BVV(0, 8)
    values["status"] = claripy.BVV(0, 8)
    assert_pathwise_equivalent(_assembly(values), _native(values), ("memory",))
