from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
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
    linked_bytes,
    rom_window,
    sm83_flags_to_z80,
    symbol_location,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x400000
DONE = 0xEFFF

CRY_DATA = 0x5446
CRY_DATA_BANK = 0x0E
CRY_DATA_SIZE = 570
W_FREQUENCY_MODIFIER = 0xC0F1
W_TEMPO_MODIFIER = 0xC0F2
W_BANKSWITCH_HOME_SAVED_ROM_BANK = 0xCF08
W_BANKSWITCH_HOME_TEMP = 0xCF09
H_LOADED_ROM_BANK = 0xFFB8
R_ROMB = 0x2000

EXPECTED = bytes.fromhex("cdd913cdb123c34837")
CRY_DATA_SHA256 = "62329ff48c608b529e0c031ab215662a6975c2ff00835713ddd38d2af6b47562"

AUDIO_FIELDS = (
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
PLAY_SOUND_OUTPUT_FIELDS = AUDIO_FIELDS[:14]
EXTRA_FIELDS = ("home_temp", "home_saved", "frequency", "tempo")


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
    audio: claripy.ast.BV
    extra: claripy.ast.BV
    cry_data: claripy.ast.BV
    calls: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _assembly_set_registers(state: angr.SimState, prefix: str) -> None:
    for register in REGISTERS:
        value = state.globals[f"{prefix}_{register}"]
        if register == "f":
            value = sm83_flags_to_z80(value)
        setattr(state.regs, register, value)


class GetCryDataBoundary(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        registers = assembly_registers(self.state)
        self.state.globals["get_cry_call"] = claripy.Concat(
            *(registers[register] for register in REGISTERS),
            self.state.memory.load(W_BANKSWITCH_HOME_TEMP, 1),
            self.state.memory.load(H_LOADED_ROM_BANK, 1),
            self.state.memory.load(W_BANKSWITCH_HOME_SAVED_ROM_BANK, 1),
            self.state.memory.load(R_ROMB, 1),
            self.state.memory.load(W_FREQUENCY_MODIFIER, 1),
            self.state.memory.load(W_TEMPO_MODIFIER, 1),
            self.state.memory.load(CRY_DATA, CRY_DATA_SIZE),
        )
        self.state.globals["get_cry_count"] += 1
        _assembly_set_registers(self.state, "get_cry_out")
        outputs = (
            (W_BANKSWITCH_HOME_TEMP, "home_temp"),
            (H_LOADED_ROM_BANK, "loaded_rom_bank"),
            (W_BANKSWITCH_HOME_SAVED_ROM_BANK, "home_saved"),
            (R_ROMB, "rom_bank"),
            (W_FREQUENCY_MODIFIER, "frequency"),
            (W_TEMPO_MODIFIER, "tempo"),
        )
        for address, field in outputs:
            self.state.memory.store(address, self.state.globals[f"get_cry_out_{field}"])
        self.state.globals["loaded_rom_bank"] = self.state.globals[
            "get_cry_out_loaded_rom_bank"
        ]
        self.state.globals["rom_bank"] = self.state.globals["get_cry_out_rom_bank"]
        self.jump(self.next_address)


class PlaySoundBoundary(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        registers = assembly_registers(self.state)
        self.state.globals["play_sound_call"] = claripy.Concat(
            *(registers[register] for register in REGISTERS),
            *(self.state.globals[field] for field in AUDIO_FIELDS),
        )
        self.state.globals["play_sound_count"] += 1
        self.state.regs.a = self.state.globals["play_sound_out_a"]
        self.state.regs.f = sm83_flags_to_z80(self.state.globals["play_sound_out_f"])
        for field in PLAY_SOUND_OUTPUT_FIELDS:
            self.state.globals[field] = self.state.globals[f"play_sound_out_{field}"]
        self.state.memory.store(
            H_LOADED_ROM_BANK, self.state.globals["loaded_rom_bank"]
        )
        self.state.memory.store(R_ROMB, self.state.globals["rom_bank"])
        self.jump(self.next_address)


class WaitForSoundBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        registers = assembly_registers(self.state)
        self.state.globals["wait_call"] = claripy.Concat(
            *(registers[register] for register in REGISTERS),
            self.state.globals["low_health_alarm"],
            self.state.globals["channel_0"],
            self.state.globals["channel_1"],
            self.state.globals["channel_3"],
        )
        self.state.globals["wait_count"] += 1
        _assembly_set_registers(self.state, "wait_out")
        for index in (0, 1, 3):
            self.state.globals[f"channel_{index}"] = self.state.globals[
                f"wait_out_channel_{index}"
            ]
        self.jump(DONE)


class NativeGetCryDataBoundary(angr.SimProcedure):
    def run(self, registers: claripy.ast.BV, memory: claripy.ast.BV) -> None:  # type: ignore[override]
        self.state.globals["get_cry_call"] = claripy.Concat(
            self.state.memory.load(registers, 8),
            self.state.memory.load(memory + W_BANKSWITCH_HOME_TEMP, 1),
            self.state.memory.load(memory + H_LOADED_ROM_BANK, 1),
            self.state.memory.load(memory + W_BANKSWITCH_HOME_SAVED_ROM_BANK, 1),
            self.state.memory.load(memory + R_ROMB, 1),
            self.state.memory.load(memory + W_FREQUENCY_MODIFIER, 1),
            self.state.memory.load(memory + W_TEMPO_MODIFIER, 1),
            self.state.memory.load(memory + CRY_DATA, CRY_DATA_SIZE),
        )
        self.state.globals["get_cry_count"] += 1
        for offset, register in enumerate(REGISTERS):
            self.state.memory.store(
                registers + offset, self.state.globals[f"get_cry_out_{register}"]
            )
        outputs = (
            (W_BANKSWITCH_HOME_TEMP, "home_temp"),
            (H_LOADED_ROM_BANK, "loaded_rom_bank"),
            (W_BANKSWITCH_HOME_SAVED_ROM_BANK, "home_saved"),
            (R_ROMB, "rom_bank"),
            (W_FREQUENCY_MODIFIER, "frequency"),
            (W_TEMPO_MODIFIER, "tempo"),
        )
        for address, field in outputs:
            self.state.memory.store(
                memory + address, self.state.globals[f"get_cry_out_{field}"]
            )


class NativePlaySoundBoundary(angr.SimProcedure):
    def run(self, state: claripy.ast.BV) -> None:  # type: ignore[override]
        self.state.globals["play_sound_call"] = self.state.memory.load(state, 24)
        self.state.globals["play_sound_count"] += 1
        self.state.memory.store(state, self.state.globals["play_sound_out_a"])
        self.state.memory.store(state + 1, self.state.globals["play_sound_out_f"])
        for offset, field in enumerate(PLAY_SOUND_OUTPUT_FIELDS, 8):
            self.state.memory.store(state + offset, self.state.globals[f"play_sound_out_{field}"])


class NativeWaitForSoundBoundary(angr.SimProcedure):
    def run(self, state: claripy.ast.BV) -> None:  # type: ignore[override]
        self.state.globals["wait_call"] = self.state.memory.load(state, 12)
        self.state.globals["wait_count"] += 1
        for offset, register in enumerate(REGISTERS):
            self.state.memory.store(state + offset, self.state.globals[f"wait_out_{register}"])
        self.state.memory.store(state + 9, self.state.globals["wait_out_channel_0"])
        self.state.memory.store(state + 10, self.state.globals["wait_out_channel_1"])
        self.state.memory.store(state + 11, self.state.globals["wait_out_channel_3"])


def inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for field in AUDIO_FIELDS + EXTRA_FIELDS:
        values[field] = claripy.BVS(f"{prefix}_{field}", 8)
    for register in REGISTERS:
        values[f"get_cry_out_{register}"] = (
            claripy.Concat(claripy.BVS(f"{prefix}_get_cry_out_flags", 4), claripy.BVV(0, 4))
            if register == "f"
            else claripy.BVS(f"{prefix}_get_cry_out_{register}", 8)
        )
        values[f"wait_out_{register}"] = (
            claripy.Concat(claripy.BVS(f"{prefix}_wait_out_flags", 4), claripy.BVV(0, 4))
            if register == "f"
            else claripy.BVS(f"{prefix}_wait_out_{register}", 8)
        )
    for field in ("home_temp", "loaded_rom_bank", "home_saved", "rom_bank", "frequency", "tempo"):
        values[f"get_cry_out_{field}"] = claripy.BVS(
            f"{prefix}_get_cry_out_{field}", 8
        )
    values["play_sound_out_a"] = claripy.BVS(f"{prefix}_play_sound_out_a", 8)
    values["play_sound_out_f"] = claripy.Concat(
        claripy.BVS(f"{prefix}_play_sound_out_flags", 4), claripy.BVV(0, 4)
    )
    for field in PLAY_SOUND_OUTPUT_FIELDS:
        values[f"play_sound_out_{field}"] = claripy.BVS(
            f"{prefix}_play_sound_out_{field}", 8
        )
    for index in (0, 1, 3):
        values[f"wait_out_channel_{index}"] = claripy.BVS(
            f"{prefix}_wait_out_channel_{index}", 8
        )
    return values


def setup_globals(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    for key, value in values.items():
        state.globals[key] = value
    state.globals["get_cry_call"] = claripy.BVV(0, (8 + 6 + CRY_DATA_SIZE) * 8)
    state.globals["play_sound_call"] = claripy.BVV(0, 24 * 8)
    state.globals["wait_call"] = claripy.BVV(0, 12 * 8)
    state.globals["get_cry_count"] = claripy.BVV(0, 8)
    state.globals["play_sound_count"] = claripy.BVV(0, 8)
    state.globals["wait_count"] = claripy.BVV(0, 8)


def setup_memory(
    state: angr.SimState,
    values: dict[str, claripy.ast.BV],
    cry_data: bytes,
    base: int = 0,
) -> None:
    for address, value in (
        (W_BANKSWITCH_HOME_TEMP, values["home_temp"]),
        (H_LOADED_ROM_BANK, values["loaded_rom_bank"]),
        (W_BANKSWITCH_HOME_SAVED_ROM_BANK, values["home_saved"]),
        (R_ROMB, values["rom_bank"]),
        (W_FREQUENCY_MODIFIER, values["frequency"]),
        (W_TEMPO_MODIFIER, values["tempo"]),
    ):
        state.memory.store(base + address, value)
    state.memory.store(base + CRY_DATA, cry_data)


def endpoint(state: angr.SimState, native: bool) -> Endpoint:
    memory_base = NATIVE_MEMORY if native else 0
    registers = native_registers(state, NATIVE_STATE) if native else assembly_registers(state)
    if native:
        audio = state.memory.load(NATIVE_STATE + 8, len(AUDIO_FIELDS))
    else:
        audio = claripy.Concat(*(state.globals[field] for field in AUDIO_FIELDS))
    extra = claripy.Concat(
        *(state.memory.load(memory_base + address, 1) for address in (
            W_BANKSWITCH_HOME_TEMP,
            H_LOADED_ROM_BANK,
            W_BANKSWITCH_HOME_SAVED_ROM_BANK,
            R_ROMB,
            W_FREQUENCY_MODIFIER,
            W_TEMPO_MODIFIER,
        ))
    )
    return Endpoint(
        **registers,
        audio=audio,
        extra=extra,
        cry_data=state.memory.load(memory_base + CRY_DATA, CRY_DATA_SIZE),
        calls=claripy.Concat(
            state.globals["get_cry_call"],
            state.globals["play_sound_call"],
            state.globals["wait_call"],
            state.globals["get_cry_count"],
            state.globals["play_sound_count"],
            state.globals["wait_count"],
        ),
        constraints=tuple(state.solver.constraints),
    )


def assembly(values: dict[str, claripy.ast.BV], cry_data: bytes) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "PlayCry")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    project = angr.Project(
        rom_window(ROM, CRY_DATA_BANK),
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
    project.hook(base, GetCryDataBoundary(base + 3), length=3)
    project.hook(base + 3, PlaySoundBoundary(base + 6), length=3)
    project.hook(base + 6, WaitForSoundBoundary(), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    setup_globals(state, values)
    setup_memory(state, values, cry_data)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE)
    assert not manager.errored and len(manager.found) == 1
    return [endpoint(end, False) for end in manager.found]


def native(values: dict[str, claripy.ast.BV], cry_data: bytes) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_play_cry")
    get_cry = project.loader.find_symbol("port_get_cry_data")
    play_sound = project.loader.find_symbol("port_play_sound")
    wait = project.loader.find_symbol("port_wait_for_sound_to_finish")
    assert function is not None and get_cry is not None and play_sound is not None and wait is not None
    project.hook(get_cry.rebased_addr, NativeGetCryDataBoundary())
    project.hook(play_sound.rebased_addr, NativePlaySoundBoundary())
    project.hook(wait.rebased_addr, NativeWaitForSoundBoundary())
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(
        NATIVE_STATE + 8,
        claripy.Concat(*(values[field] for field in AUDIO_FIELDS)),
    )
    setup_globals(state, values)
    setup_memory(state, values, cry_data, NATIVE_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [endpoint(end, True) for end in manager.deadended]


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(), reason="build")
def test_play_cry_pathwise_equivalence() -> None:
    cry_location = symbol_location(SYMBOLS, "CryData")
    cry_data = linked_bytes(ROM, cry_location, CRY_DATA_SIZE)
    assert (cry_location.bank, cry_location.address) == (CRY_DATA_BANK, CRY_DATA)
    assert sha256(cry_data).hexdigest() == CRY_DATA_SHA256
    values = inputs("play_cry")
    assert_pathwise_equivalent(
        assembly(values, cry_data),
        native(values, cry_data),
        (*REGISTERS, "audio", "extra", "cry_data", "calls"),
    )
