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
from verification.harness.sm83_shims import (
    Sm83CpImmediate,
    Sm83CpRegister,
    Sm83LoadAAtHlIncrement,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x400000
STACK = 0xD000
TEXT = 0xD360
CONTINUE = 0x1B55

TEXT_COMMAND_SOUNDS = 0x1C64
CRY_DATA = 0x5446
CRY_DATA_BANK = 0x0E
CRY_DATA_SIZE = 570
W_FREQUENCY_MODIFIER = 0xC0F1
W_TEMPO_MODIFIER = 0xC0F2
W_BANKSWITCH_HOME_SAVED_ROM_BANK = 0xCF08
W_BANKSWITCH_HOME_TEMP = 0xCF09
H_LOADED_ROM_BANK = 0xFFB8
R_ROMB = 0x2000

EXPECTED = bytes.fromhex(
    "e1c52b2a47e521641c2ab828032318f9fe142814fe152810fe16280c7ecdb123"
    "cd4837e1c1c3551bd57ecdd013d1e1c1c3551b"
)
SOUND_TABLE = bytes.fromhex("0b86129a0e910f8610891194139814a815971678")
CRY_DATA_SHA256 = "62329ff48c608b529e0c031ab215662a6975c2ff00835713ddd38d2af6b47562"
COMMANDS = tuple(SOUND_TABLE[index] for index in range(0, len(SOUND_TABLE), 2))

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
    command: claripy.ast.BV
    audio: claripy.ast.BV
    extra: claripy.ast.BV
    cry_data: claripy.ast.BV
    calls: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class PushPair(angr.SimProcedure):
    def __init__(self, high: str, low: str, next_address: int):
        super().__init__()
        self.high = high
        self.low = low
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.sp -= 1
        self.state.memory.store(self.state.regs.sp, getattr(self.state.regs, self.high))
        self.state.regs.sp -= 1
        self.state.memory.store(self.state.regs.sp, getattr(self.state.regs, self.low))
        self.jump(self.next_address)


class PopPair(angr.SimProcedure):
    def __init__(self, high: str, low: str, next_address: int):
        super().__init__()
        self.high = high
        self.low = low
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.low, self.state.memory.load(self.state.regs.sp, 1))
        setattr(
            self.state.regs,
            self.high,
            self.state.memory.load(self.state.regs.sp + 1, 1),
        )
        self.state.regs.sp += 2
        self.jump(self.next_address)


class IncrementHl(angr.SimProcedure):
    def __init__(self, amount: int, next_address: int):
        super().__init__()
        self.amount = amount
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.hl += self.amount
        self.jump(self.next_address)


class CopyRegister(angr.SimProcedure):
    def __init__(self, destination: str, source: str, next_address: int):
        super().__init__()
        self.destination = destination
        self.source = source
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.destination, getattr(self.state.regs, self.source))
        self.jump(self.next_address)


class LoadHlImmediate(angr.SimProcedure):
    def __init__(self, value: int, next_address: int):
        super().__init__()
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = claripy.BVV(self.value >> 8, 8)
        self.state.regs.l = claripy.BVV(self.value & 0xFF, 8)
        self.jump(self.next_address)


class LoadAAtHl(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self.state.regs.hl, 1)
        self.jump(self.next_address)


def assembly_set_registers(state: angr.SimState, prefix: str) -> None:
    for register in REGISTERS:
        value = state.globals[f"{prefix}_{register}"]
        if register == "f":
            value = sm83_flags_to_z80(value)
        setattr(state.regs, register, value)


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
        self.state.memory.store(H_LOADED_ROM_BANK, self.state.globals["loaded_rom_bank"])
        self.state.memory.store(R_ROMB, self.state.globals["rom_bank"])
        self.jump(self.next_address)


class WaitBoundary(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__()
        self.next_address = next_address

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
        assembly_set_registers(self.state, "wait_out")
        for index in (0, 1, 3):
            self.state.globals[f"channel_{index}"] = self.state.globals[
                f"wait_out_channel_{index}"
            ]
        self.jump(self.next_address)


class PlayCryBoundary(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        registers = assembly_registers(self.state)
        self.state.globals["play_cry_call"] = claripy.Concat(
            *(registers[register] for register in REGISTERS),
            *(self.state.globals[field] for field in AUDIO_FIELDS),
            self.state.memory.load(W_BANKSWITCH_HOME_TEMP, 1),
            self.state.memory.load(H_LOADED_ROM_BANK, 1),
            self.state.memory.load(W_BANKSWITCH_HOME_SAVED_ROM_BANK, 1),
            self.state.memory.load(R_ROMB, 1),
            self.state.memory.load(W_FREQUENCY_MODIFIER, 1),
            self.state.memory.load(W_TEMPO_MODIFIER, 1),
            self.state.memory.load(CRY_DATA, CRY_DATA_SIZE),
        )
        self.state.globals["play_cry_count"] += 1
        assembly_set_registers(self.state, "play_cry_out")
        for field in AUDIO_FIELDS:
            self.state.globals[field] = self.state.globals[f"play_cry_out_{field}"]
        for address, field in (
            (W_BANKSWITCH_HOME_TEMP, "home_temp"),
            (H_LOADED_ROM_BANK, "loaded_rom_bank"),
            (W_BANKSWITCH_HOME_SAVED_ROM_BANK, "home_saved"),
            (R_ROMB, "rom_bank"),
            (W_FREQUENCY_MODIFIER, "frequency"),
            (W_TEMPO_MODIFIER, "tempo"),
        ):
            self.state.memory.store(address, self.state.globals[f"play_cry_out_{field}"])
        self.jump(self.next_address)


class NativePlaySoundBoundary(angr.SimProcedure):
    def run(self, state: claripy.ast.BV) -> None:  # type: ignore[override]
        self.state.globals["play_sound_call"] = self.state.memory.load(state, 24)
        self.state.globals["play_sound_count"] += 1
        self.state.memory.store(state, self.state.globals["play_sound_out_a"])
        self.state.memory.store(state + 1, self.state.globals["play_sound_out_f"])
        for offset, field in enumerate(PLAY_SOUND_OUTPUT_FIELDS, 8):
            self.state.memory.store(state + offset, self.state.globals[f"play_sound_out_{field}"])


class NativeWaitBoundary(angr.SimProcedure):
    def run(self, state: claripy.ast.BV) -> None:  # type: ignore[override]
        self.state.globals["wait_call"] = self.state.memory.load(state, 12)
        self.state.globals["wait_count"] += 1
        for offset, register in enumerate(REGISTERS):
            self.state.memory.store(state + offset, self.state.globals[f"wait_out_{register}"])
        self.state.memory.store(state + 9, self.state.globals["wait_out_channel_0"])
        self.state.memory.store(state + 10, self.state.globals["wait_out_channel_1"])
        self.state.memory.store(state + 11, self.state.globals["wait_out_channel_3"])


class NativePlayCryBoundary(angr.SimProcedure):
    def run(self, state: claripy.ast.BV, memory: claripy.ast.BV) -> None:  # type: ignore[override]
        self.state.globals["play_cry_call"] = claripy.Concat(
            self.state.memory.load(state, 24),
            self.state.memory.load(memory + W_BANKSWITCH_HOME_TEMP, 1),
            self.state.memory.load(memory + H_LOADED_ROM_BANK, 1),
            self.state.memory.load(memory + W_BANKSWITCH_HOME_SAVED_ROM_BANK, 1),
            self.state.memory.load(memory + R_ROMB, 1),
            self.state.memory.load(memory + W_FREQUENCY_MODIFIER, 1),
            self.state.memory.load(memory + W_TEMPO_MODIFIER, 1),
            self.state.memory.load(memory + CRY_DATA, CRY_DATA_SIZE),
        )
        self.state.globals["play_cry_count"] += 1
        for offset, register in enumerate(REGISTERS):
            self.state.memory.store(state + offset, self.state.globals[f"play_cry_out_{register}"])
        for offset, field in enumerate(AUDIO_FIELDS, 8):
            self.state.memory.store(state + offset, self.state.globals[f"play_cry_out_{field}"])
        for address, field in (
            (W_BANKSWITCH_HOME_TEMP, "home_temp"),
            (H_LOADED_ROM_BANK, "loaded_rom_bank"),
            (W_BANKSWITCH_HOME_SAVED_ROM_BANK, "home_saved"),
            (R_ROMB, "rom_bank"),
            (W_FREQUENCY_MODIFIER, "frequency"),
            (W_TEMPO_MODIFIER, "tempo"),
        ):
            self.state.memory.store(
                memory + address, self.state.globals[f"play_cry_out_{field}"]
            )


class Continue(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(CONTINUE)


def inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["h"] = claripy.BVV(TEXT >> 8, 8)
    values["l"] = claripy.BVV(TEXT & 0xFF, 8)
    for field in AUDIO_FIELDS + EXTRA_FIELDS:
        values[field] = claripy.BVS(f"{prefix}_{field}", 8)
    for register in REGISTERS:
        for callee in ("wait_out", "play_cry_out"):
            values[f"{callee}_{register}"] = (
                claripy.Concat(
                    claripy.BVS(f"{prefix}_{callee}_flags", 4), claripy.BVV(0, 4)
                )
                if register == "f"
                else claripy.BVS(f"{prefix}_{callee}_{register}", 8)
            )
    values["play_sound_out_a"] = claripy.BVS(f"{prefix}_play_sound_out_a", 8)
    values["play_sound_out_f"] = claripy.Concat(
        claripy.BVS(f"{prefix}_play_sound_out_flags", 4), claripy.BVV(0, 4)
    )
    for field in PLAY_SOUND_OUTPUT_FIELDS:
        values[f"play_sound_out_{field}"] = claripy.BVS(
            f"{prefix}_play_sound_out_{field}", 8
        )
    for field in AUDIO_FIELDS + EXTRA_FIELDS:
        values[f"play_cry_out_{field}"] = claripy.BVS(
            f"{prefix}_play_cry_out_{field}", 8
        )
    for index in (0, 1, 3):
        values[f"wait_out_channel_{index}"] = claripy.BVS(
            f"{prefix}_wait_out_channel_{index}", 8
        )
    return values


def setup_globals(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    for key, value in values.items():
        state.globals[key] = value
    state.globals["play_sound_call"] = claripy.BVV(0, 24 * 8)
    state.globals["wait_call"] = claripy.BVV(0, 12 * 8)
    state.globals["play_cry_call"] = claripy.BVV(
        0, (24 + 6 + CRY_DATA_SIZE) * 8
    )
    for callee in ("play_sound", "wait", "play_cry"):
        state.globals[f"{callee}_count"] = claripy.BVV(0, 8)


def setup_memory(
    state: angr.SimState,
    values: dict[str, claripy.ast.BV],
    command: int,
    cry_data: bytes,
    base: int = 0,
) -> None:
    state.memory.store(base + TEXT - 1, claripy.BVV(command, 8))
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
    audio = (
        state.memory.load(NATIVE_STATE + 8, len(AUDIO_FIELDS))
        if native
        else claripy.Concat(*(state.globals[field] for field in AUDIO_FIELDS))
    )
    return Endpoint(
        **registers,
        command=state.memory.load(memory_base + TEXT - 1, 1),
        audio=audio,
        extra=claripy.Concat(
            *(state.memory.load(memory_base + address, 1) for address in (
                W_BANKSWITCH_HOME_TEMP,
                H_LOADED_ROM_BANK,
                W_BANKSWITCH_HOME_SAVED_ROM_BANK,
                R_ROMB,
                W_FREQUENCY_MODIFIER,
                W_TEMPO_MODIFIER,
            ))
        ),
        cry_data=state.memory.load(memory_base + CRY_DATA, CRY_DATA_SIZE),
        calls=claripy.Concat(
            state.globals["play_sound_call"],
            state.globals["wait_call"],
            state.globals["play_cry_call"],
            state.globals["play_sound_count"],
            state.globals["wait_count"],
            state.globals["play_cry_count"],
        ),
        constraints=tuple(state.solver.constraints),
    )


def assembly(
    values: dict[str, claripy.ast.BV], command: int, cry_data: bytes
) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "TextCommand_SOUND")
    table_location = symbol_location(SYMBOLS, "TextCommandSounds")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    assert (table_location.bank, table_location.address) == (0, TEXT_COMMAND_SOUNDS)
    assert linked_bytes(ROM, table_location, len(SOUND_TABLE)) == SOUND_TABLE
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
    project.hook(base, PopPair("h", "l", base + 1), length=1)
    project.hook(base + 1, PushPair("b", "c", base + 2), length=1)
    project.hook(base + 2, IncrementHl(-1, base + 3), length=1)
    project.hook(base + 3, Sm83LoadAAtHlIncrement(base + 4), length=1)
    project.hook(base + 4, CopyRegister("b", "a", base + 5), length=1)
    project.hook(base + 5, PushPair("h", "l", base + 6), length=1)
    project.hook(base + 6, LoadHlImmediate(TEXT_COMMAND_SOUNDS, base + 9), length=3)
    project.hook(base + 9, Sm83LoadAAtHlIncrement(base + 10), length=1)
    project.hook(base + 10, Sm83CpRegister("b", base + 11), length=1)
    project.hook(base + 13, IncrementHl(1, base + 14), length=1)
    project.hook(base + 16, Sm83CpImmediate(0x14, base + 18), length=2)
    project.hook(base + 20, Sm83CpImmediate(0x15, base + 22), length=2)
    project.hook(base + 24, Sm83CpImmediate(0x16, base + 26), length=2)
    project.hook(base + 28, LoadAAtHl(base + 29), length=1)
    project.hook(base + 29, PlaySoundBoundary(base + 32), length=3)
    project.hook(base + 32, WaitBoundary(base + 35), length=3)
    project.hook(base + 35, PopPair("h", "l", base + 36), length=1)
    project.hook(base + 36, PopPair("b", "c", base + 37), length=1)
    project.hook(base + 37, Continue(), length=3)
    project.hook(base + 40, PushPair("d", "e", base + 41), length=1)
    project.hook(base + 41, LoadAAtHl(base + 42), length=1)
    project.hook(base + 42, PlayCryBoundary(base + 45), length=3)
    project.hook(base + 45, PopPair("d", "e", base + 46), length=1)
    project.hook(base + 46, PopPair("h", "l", base + 47), length=1)
    project.hook(base + 47, PopPair("b", "c", base + 48), length=1)
    project.hook(base + 48, Continue(), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.regs.sp = STACK - 2
    state.memory.store(STACK - 2, claripy.BVV(TEXT & 0xFF, 8))
    state.memory.store(STACK - 1, claripy.BVV(TEXT >> 8, 8))
    setup_globals(state, values)
    setup_memory(state, values, command, cry_data)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=CONTINUE)
    assert not manager.errored and len(manager.found) == 1
    return [endpoint(end, False) for end in manager.found]


def native(
    values: dict[str, claripy.ast.BV], command: int, cry_data: bytes
) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_text_command_sound")
    play_sound = project.loader.find_symbol("port_play_sound")
    wait = project.loader.find_symbol("port_wait_for_sound_to_finish")
    play_cry = project.loader.find_symbol("port_play_cry")
    assert function is not None and play_sound is not None and wait is not None and play_cry is not None
    project.hook(play_sound.rebased_addr, NativePlaySoundBoundary())
    project.hook(wait.rebased_addr, NativeWaitBoundary())
    project.hook(play_cry.rebased_addr, NativePlayCryBoundary())
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(
        NATIVE_STATE + 8,
        claripy.Concat(*(values[field] for field in AUDIO_FIELDS)),
    )
    setup_globals(state, values)
    setup_memory(state, values, command, cry_data, NATIVE_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [endpoint(end, True) for end in manager.deadended]


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(), reason="build")
@pytest.mark.parametrize("command", COMMANDS, ids=lambda value: f"{value:02x}")
def test_text_command_sound_pathwise_equivalence(command: int) -> None:
    cry_location = symbol_location(SYMBOLS, "CryData")
    cry_data = linked_bytes(ROM, cry_location, CRY_DATA_SIZE)
    assert (cry_location.bank, cry_location.address) == (CRY_DATA_BANK, CRY_DATA)
    assert sha256(cry_data).hexdigest() == CRY_DATA_SHA256
    values = inputs(f"text_command_sound_{command:02x}")
    assert_pathwise_equivalent(
        assembly(values, command, cry_data),
        native(values, command, cry_data),
        (*REGISTERS, "command", "audio", "extra", "cry_data", "calls"),
    )
