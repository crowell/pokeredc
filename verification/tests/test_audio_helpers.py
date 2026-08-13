from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import hashlib
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
    Sm83AndImmediate,
    Sm83AdcRegister,
    Sm83AddAtHl,
    Sm83AddImmediate,
    Sm83AddHlRegisterPair,
    Sm83AddRegister,
    Sm83BitRegister,
    Sm83BitAtHl,
    Sm83CpAtHl,
    Sm83CpImmediate,
    Sm83CpRegister,
    Sm83DecRegister,
    Sm83DecAtHl,
    Sm83IncRegister,
    Sm83LoadAHighImmediate,
    Sm83LoadAAtHlDecrement,
    Sm83LoadAAtHlIncrement,
    Sm83LoadAImmediate,
    Sm83RlRegister,
    Sm83Rlca,
    Sm83ResAtHl,
    Sm83RrRegister,
    Sm83Rrca,
    Sm83SbcImmediate,
    Sm83SbcRegister,
    Sm83SlaRegister,
    Sm83SraRegister,
    Sm83SrlRegister,
    Sm83SwapRegister,
    Sm83SwapAtHl,
    Sm83SetAtHl,
    Sm83StoreAImmediate,
    Sm83StoreAHighImmediate,
    Sm83StoreAAtHlIncrement,
    Sm83SubImmediate,
    Sm83SubAtHl,
    Sm83SubRegister,
)


ROOT = Path(__file__).resolve().parents[2]
VERIFY = ROOT / "verification"
NATIVE_ELF = VERIFY / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
GB_STACK = 0xD000
GB_RETURN = 0xFFFF
NATIVE_STATE = 0x100000


class Sm83LoadSymbolicCommandByte(angr.SimProcedure):
    """Load the arbitrary byte at a caller-valid banked-ROM command pointer."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals["command_byte"]
        self.jump(self._next_address)


class Sm83LoadSequentialCommandByte(angr.SimProcedure):
    """Load successive arbitrary parameter bytes for a command."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        index = self.state.globals["command_byte_index"]
        self.state.regs.a = self.state.globals["command_bytes"][index]
        self.state.globals["command_byte_index"] = index + 1
        self.jump(self._next_address)


class HandlerFallthroughBoundary(angr.SimProcedure):
    """Redirect a fallthrough callee entry to an explicit proof boundary."""

    def __init__(self, boundary: int) -> None:
        super().__init__()
        self._boundary = boundary

    def run(self) -> None:  # type: ignore[override]
        self.jump(self._boundary)


class Sm83PushAf(angr.SimProcedure):
    """Push AF using the SM83 flag-byte layout rather than generic Z80 F."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        z80_f = self.state.regs.f
        sm83_f = claripy.Concat(
            z80_f[6], z80_f[1], z80_f[4], z80_f[0], claripy.BVV(0, 4)
        )
        self.state.regs.sp = self.state.regs.sp - 2
        self.state.memory.store(self.state.regs.sp, sm83_f)
        self.state.memory.store(self.state.regs.sp + 1, self.state.regs.a)
        self.jump(self._next_address)


class Sm83PopHl(angr.SimProcedure):
    """Pop a little-endian SM83 register pair into HL."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.l = self.state.memory.load(self.state.regs.sp, 1)
        self.state.regs.h = self.state.memory.load(self.state.regs.sp + 1, 1)
        self.state.regs.sp = self.state.regs.sp + 2
        self.jump(self._next_address)


class Sm83PopAf(angr.SimProcedure):
    """Pop canonical SM83 AF from the emulated stack into Z80 p-code flags."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        sm83_f = self.state.memory.load(self.state.regs.sp, 1)
        self.state.regs.a = self.state.memory.load(self.state.regs.sp + 1, 1)
        self.state.regs.f = sm83_flags_to_z80(sm83_f)
        self.state.regs.sp = self.state.regs.sp + 2
        self.jump(self._next_address)


class NoteLengthMultiplyAddSummary(angr.SimProcedure):
    """Verified MultiplyAdd summary specialized to note_length's live outputs."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        multiplier = claripy.ZeroExt(8, self.state.regs.a)
        multiplicand = claripy.Concat(self.state.regs.d, self.state.regs.e)
        initial = claripy.ZeroExt(8, self.state.regs.l)
        result = multiplier * multiplicand + initial
        self.state.regs.h = result[15:8]
        self.state.regs.l = result[7:0]
        self.jump(self._next_address)


class NoteLengthSetSfxTempoSummary(angr.SimProcedure):
    """Apply the already-proven engine-specific SetSfxTempo behavior."""

    def __init__(
        self, variant: int, sfx_tempo_address: int, next_address: int
    ) -> None:
        super().__init__()
        self._variant = variant
        self._sfx_tempo_address = sfx_tempo_address
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        sound5 = self.state.globals["note_length_sound5"]
        sound8 = self.state.globals["note_length_sound8"]
        modifier = self.state.globals["note_length_tempo_modifier"]
        is_cry = claripy.And(sound5.UGE(0x14), sound5.ULT(0x86))
        if self._variant == 2:
            combined = sound5 | sound8
            is_cry = claripy.Or(
                is_cry, claripy.And(combined.UGE(0x9D), combined.ULT(0xEA))
            )
        adjusted = claripy.ZeroExt(8, modifier) + 0x80
        high = claripy.If(is_cry, adjusted[15:8], claripy.BVV(1, 8))
        low = claripy.If(is_cry, adjusted[7:0], claripy.BVV(0, 8))
        self.state.memory.store(self._sfx_tempo_address, high)
        self.state.memory.store(self._sfx_tempo_address + 1, low)
        self.jump(self._next_address)


class NativeNoteDelayArithmeticSummary(angr.SimProcedure):
    """Closed form of the separately proved native note-delay arithmetic leaf."""

    def run(self, factor: claripy.ast.BV, tempo: claripy.ast.BV, fractional: claripy.ast.BV) -> claripy.ast.BV:  # type: ignore[override]
        product = claripy.ZeroExt(8, factor[7:0]) * tempo[15:0]
        result = product + claripy.ZeroExt(8, fractional[7:0])
        return claripy.ZeroExt(48, result[15:0])


def _summary_add_flags(left: claripy.ast.BV, right: claripy.ast.BV) -> claripy.ast.BV:
    wide = claripy.ZeroExt(1, left) + claripy.ZeroExt(1, right)
    result = wide[7:0]
    flags = claripy.If(result == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
    flags |= claripy.If(
        (left & 0x0F) + (right & 0x0F) > 0x0F,
        claripy.BVV(0x10, 8),
        claripy.BVV(0, 8),
    )
    return flags | claripy.ZeroExt(7, wide[8])


def _summary_cp_flags(left: claripy.ast.BV, right: int) -> claripy.ast.BV:
    flags = claripy.BVV(0x02, 8)
    flags |= claripy.If(left == right, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
    flags |= claripy.If(
        (left & 0x0F).ULT(right & 0x0F),
        claripy.BVV(0x10, 8),
        claripy.BVV(0, 8),
    )
    return flags | claripy.If(
        left.ULT(right), claripy.BVV(1, 8), claripy.BVV(0, 8)
    )


class NotePitchGetRegisterPointerSummary(angr.SimProcedure):
    """Composition summary of the already-proven GetRegisterPointer leaf."""

    def __init__(self, channel: int, next_address: int) -> None:
        super().__init__()
        self._channel = channel
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        base = (0x10, 0x15, 0x1A, 0x1F)[self._channel & 3]
        offset = self.state.regs.b
        self.state.regs.a = claripy.BVV(base, 8) + offset
        self.state.regs.f = _summary_add_flags(claripy.BVV(base, 8), offset)
        self.state.regs.h = 0xFF
        self.state.regs.l = self.state.regs.a
        self.jump(self._next_address)


class ApplyMusicDutyPatternSummary(angr.SimProcedure):
    """Composition summary of the already-proven duty-pattern leaf."""

    def __init__(
        self,
        channel: int,
        duty_patterns_address: int,
        hardware_addresses: tuple[int, ...],
        next_address: int,
    ) -> None:
        super().__init__()
        self._channel = channel
        self._duty_patterns_address = duty_patterns_address
        self._hardware_addresses = hardware_addresses
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        pattern_address = self._duty_patterns_address + self._channel
        pattern = self.state.memory.load(pattern_address, 1)
        rotated = (pattern << 2) | claripy.LShR(pattern, 6)
        hardware_address = self._hardware_addresses[self._channel & 3]
        hardware = self.state.memory.load(hardware_address, 1)
        base = (0x10, 0x15, 0x1A, 0x1F)[self._channel & 3]

        self.state.memory.store(pattern_address, rotated)
        self.state.regs.d = rotated & 0xC0
        self.state.regs.b = 1
        self.state.regs.a = (hardware & 0x3F) | self.state.regs.d
        self.state.memory.store(hardware_address, self.state.regs.a)
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x40, 8),
            claripy.BVV(0, 8),
        )
        self.state.regs.h = 0xFF
        self.state.regs.l = base + 1
        self.jump(self._next_address)


class NotePitchCalculateFrequencySummary(angr.SimProcedure):
    """Composition summary of the already-proven CalculateFrequency leaf."""

    def __init__(self, pitches_address: int, next_address: int) -> None:
        super().__init__()
        self._pitches_address = pitches_address
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        pitches = (
            0xF82C, 0xF89D, 0xF907, 0xF96B, 0xF9CA, 0xFA23,
            0xFA77, 0xFAC7, 0xFB12, 0xFB58, 0xFB9B, 0xFBDA,
        )
        note = self.state.regs.a
        octave = self.state.regs.b
        frequency = claripy.BVV(pitches[-1], 16)
        for note_index in reversed(range(11)):
            frequency = claripy.If(
                note == note_index, claripy.BVV(pitches[note_index], 16), frequency
            )
        for encoded_octave in range(7):
            shifted = claripy.LShR(frequency, 1) | 0x8000
            frequency = claripy.If(octave == encoded_octave, shifted, frequency)
            octave = claripy.If(octave == encoded_octave, octave + 1, octave)
        high = frequency[15:8]
        self.state.regs.a = high + 8
        self.state.regs.f = _summary_add_flags(claripy.BVV(8, 8), high)
        self.state.regs.d = self.state.regs.a
        self.state.regs.e = frequency[7:0]
        address = claripy.BVV(self._pitches_address + 1, 16) + claripy.ZeroExt(8, note) * 2
        self.state.regs.h = address[15:8]
        self.state.regs.l = address[7:0]
        self.jump(self._next_address)


class NotePitchInitSlideSummary(angr.SimProcedure):
    """Composition summary of the already-proven InitPitchSlideVars leaf."""

    def __init__(self, addresses: dict[str, int], channel: int, next_address: int) -> None:
        super().__init__()
        self._addresses = addresses
        self._channel = channel
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        channel = self._channel
        address = self._addresses
        outputs = self.state.globals["note_pitch_slide_outputs"]
        for register in ("a", "b", "d", "e", "h", "l"):
            setattr(self.state.regs, register, outputs[register])
        self.state.regs.f = sm83_flags_to_z80(outputs["f"])
        for name in (
            "flags1", "length_modifiers", "frequency_steps",
            "frequency_steps_fractional", "current_frequency_fractional",
            "current_frequency_high", "current_frequency_low",
        ):
            self.state.memory.store(address[name] + channel, outputs[name])
        self.jump(self._next_address)


class NativeNotePitchInitSlideSummary(angr.SimProcedure):
    """Native-ABI form of the independently proven pitch-slide initializer."""

    def __init__(self, channel: int) -> None:
        super().__init__()
        self._channel = channel

    def run(self, pointer: claripy.ast.BV) -> None:  # type: ignore[override]
        channel = self._channel
        outputs = self.state.globals["note_pitch_slide_outputs"]
        register_offsets = {"a": 0, "f": 1, "b": 2, "d": 4, "e": 5, "h": 6, "l": 7}
        for name, offset in register_offsets.items():
            self.state.memory.store(pointer + offset, outputs[name])
        array_offsets = {
            "flags1": 8, "length_modifiers": 24, "frequency_steps": 32,
            "frequency_steps_fractional": 40,
            "current_frequency_fractional": 48,
            "current_frequency_high": 56, "current_frequency_low": 64,
        }
        for name, offset in array_offsets.items():
            self.state.memory.store(pointer + offset + channel, outputs[name])


class SoundRetGoBackSummary(angr.SimProcedure):
    """Composition summary of the already-proven cry command rewind leaf."""

    def __init__(self, pointer_address: int, channel: int, next_address: int) -> None:
        super().__init__()
        self._pointer_address = pointer_address
        self._channel = channel
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        offset = self._channel * 2
        low = self.state.memory.load(self._pointer_address + offset, 1)
        high = self.state.memory.load(self._pointer_address + offset + 1, 1)
        pointer = claripy.Concat(high, low) - 1
        self.state.memory.store(self._pointer_address + offset, pointer[7:0])
        self.state.memory.store(self._pointer_address + offset + 1, pointer[15:8])
        self.state.regs.a = pointer[15:8]
        self.state.regs.f = claripy.BVV(1, 8) | claripy.If(
            pointer[15:8] == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)
        )
        self.state.regs.d = 0
        self.state.regs.e = offset
        self.state.regs.h = 0xC0
        self.state.regs.l = 0x07 + offset
        self.jump(self._next_address)


class SfxNoteLengthSummary(angr.SimProcedure):
    """Assembly-memory form of the independently proven note_length post-state."""

    def __init__(self, addresses: dict[str, int], next_address: int) -> None:
        super().__init__()
        self._addresses = addresses
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        outputs = self.state.globals["sfx_note_length_outputs"]
        for register in REGISTERS:
            value = outputs[register]
            if register == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, register, value)
        for name in (
            "note_speeds", "music_tempo", "sfx_tempo",
            "fractional_note_delays", "note_delays", "flags2", "flags1",
        ):
            self.state.memory.store(self._addresses[name], outputs[name])
        self.state.memory.store(
            self._addresses["sound_ids"] + 4, outputs["sound5"]
        )
        self.state.memory.store(
            self._addresses["sound_ids"] + 7, outputs["sound8"]
        )
        self.state.memory.store(
            self._addresses["tempo_modifier"], outputs["tempo_modifier"]
        )
        self.jump(self._next_address)


class NativeSfxNoteLengthSummary(angr.SimProcedure):
    """Native-ABI form of the independently proven note_length post-state."""

    def run(self, pointer: claripy.ast.BV) -> None:  # type: ignore[override]
        outputs = self.state.globals["sfx_note_length_outputs"]
        for offset, register in enumerate(REGISTERS):
            self.state.memory.store(pointer + offset, outputs[register])
        offsets = {
            "note_speeds": 8, "music_tempo": 16, "sfx_tempo": 18,
            "fractional_note_delays": 20, "note_delays": 28,
            "flags2": 36, "flags1": 44, "sound5": 52, "sound8": 53,
            "tempo_modifier": 54,
        }
        for name, offset in offsets.items():
            self.state.memory.store(pointer + offset, outputs[name])


class UnknownEfPlaySoundSummary(angr.SimProcedure):
    """Assembly-memory form of the independently proven PlaySound result."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        outputs = self.state.globals["unknown_ef_play_outputs"]
        for register in REGISTERS:
            value = outputs[register]
            if register == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, register, value)
        self.state.memory.store(0xC000, outputs["audio_ram"])
        self.state.memory.store(0xFF10, outputs["hardware_audio"])
        self.jump(self._next_address)


class NativeUnknownEfPlaySoundSummary(angr.SimProcedure):
    """Native-ABI form of the independently proven PlaySound result."""

    def run(self, pointer: claripy.ast.BV) -> None:  # type: ignore[override]
        outputs = self.state.globals["unknown_ef_play_outputs"]
        for offset, register in enumerate(REGISTERS):
            self.state.memory.store(pointer + offset, outputs[register])
        self.state.memory.store(pointer + 8, outputs["audio_ram"])
        self.state.memory.store(pointer + 251, outputs["hardware_audio"])


class NativeNotePlaySoundSummary(angr.SimProcedure):
    """Native adapter form of the independently proven PlaySound result."""

    def run(
        self, pointer: claripy.ast.BV, _variant: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        outputs = self.state.globals["unknown_ef_play_outputs"]
        for offset, register in enumerate(REGISTERS):
            self.state.memory.store(pointer + offset, outputs[register])
        self.state.memory.store(pointer + 8, outputs["audio_ram"])
        self.state.memory.store(pointer + 251, outputs["hardware_audio"])


class NotePitchDutyLengthSummary(angr.SimProcedure):
    """Composition summary of ApplyDutyCycleAndSoundLength."""

    def __init__(self, addresses: dict[str, int], channel: int, next_address: int) -> None:
        super().__init__()
        self._addresses = addresses
        self._channel = channel
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        channel = self._channel
        base = (0x10, 0x15, 0x1A, 0x1F)[channel & 3]
        length = self.state.memory.load(self._addresses["note_delays"] + channel, 1)
        if channel not in (2, 6):
            duty = self.state.memory.load(self._addresses["duty_cycles"] + channel, 1)
            length = (length & 0x3F) | duty
        self.state.regs.b = 1
        self.state.regs.d = length
        self.state.regs.a = base + 1
        self.state.regs.f = _summary_add_flags(claripy.BVV(base, 8), claripy.BVV(1, 8))
        self.state.regs.h = 0xFF
        self.state.regs.l = base + 1
        self.state.memory.store(self._addresses["hardware_duty"][channel & 3], length)
        self.jump(self._next_address)


class NotePitchEnableOutputSummary(angr.SimProcedure):
    """Composition summary of the already-proven EnableChannelOutput leaf."""

    def __init__(self, addresses: dict[str, int], channel: int, variant: int, next_address: int) -> None:
        super().__init__()
        self._addresses = addresses
        self._channel = channel
        self._variant = variant
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        channel = self._channel
        enable = (0x11, 0x22, 0x44, 0x88)[channel & 3]
        disable = (0xEE, 0xDD, 0xBB, 0x77)[channel & 3]
        terminal = self.state.memory.load(0xFF25, 1)
        output = terminal | enable
        apply_panning = channel == 7
        enable_base = {1: 0x5B27, 2: 0x62E6, 3: 0x5B9B}[self._variant]
        self.state.regs.b = 0
        self.state.regs.d = output
        self.state.regs.a = channel
        self.state.regs.h = (enable_base + channel) >> 8
        self.state.regs.l = (enable_base + channel) & 0xFF
        if channel < 4:
            self.state.regs.h = 0xC0
            self.state.regs.l = 0x2A + channel
            self.state.regs.a = self.state.memory.load(self._addresses["sound_ids"] + 4 + channel, 1)
            apply_panning = self.state.regs.a == 0
        if channel >= 4 and channel != 7:
            self.state.regs.f = 0x42 if channel == 4 else 0x02
        if isinstance(apply_panning, bool):
            apply_expr = claripy.BoolV(apply_panning)
        else:
            apply_expr = apply_panning
        panned = (terminal & disable) | (
            self.state.memory.load(self._addresses["stereo"], 1) & enable
        )
        output = claripy.If(apply_expr, panned, output)
        self.state.regs.d = output
        if channel < 4:
            self.state.regs.f = claripy.If(
                apply_expr,
                claripy.If(output == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)),
                claripy.BVV(0x10, 8),
            )
        elif channel == 7:
            self.state.regs.f = claripy.If(
                output == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)
            )
        mask_base = {1: 0x5B1F, 2: 0x62DE, 3: 0x5B93}[self._variant]
        self.state.regs.h = claripy.If(
            apply_expr, claripy.BVV(mask_base >> 8, 8), self.state.regs.h
        )
        self.state.regs.l = claripy.If(
            apply_expr, claripy.BVV((mask_base + channel) & 0xFF, 8), self.state.regs.l
        )
        self.state.regs.a = output
        self.state.memory.store(0xFF25, output)
        self.jump(self._next_address)


class NotePitchWaveFrequencySummary(angr.SimProcedure):
    """Composition summary of ApplyWavePatternAndFrequency and its modifier leaf."""

    def __init__(
        self,
        addresses: dict[str, int],
        channel: int,
        variant: int,
        patterns: tuple[bytes, ...],
        next_address: int,
    ) -> None:
        super().__init__()
        self._addresses = addresses
        self._channel = channel
        self._variant = variant
        self._patterns = patterns
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        channel = self._channel
        base = (0x10, 0x15, 0x1A, 0x1F)[channel & 3]
        if channel in (2, 6):
            instrument_address = (
                self._addresses["music_instrument"]
                if channel == 2
                else self._addresses["sfx_instrument"]
            )
            instrument = self.state.memory.load(instrument_address, 1)
            index = claripy.If(instrument.UGT(5), claripy.BVV(5, 8), instrument)
            for byte_index in range(16):
                value = claripy.BVV(self._patterns[5][byte_index], 8)
                for pattern_index in reversed(range(5)):
                    value = claripy.If(
                        index == pattern_index,
                        claripy.BVV(self._patterns[pattern_index][byte_index], 8),
                        value,
                    )
                self.state.memory.store(0xFF30 + byte_index, value)
            self.state.memory.store(0xFF1A, claripy.BVV(0x80, 8))

        self.state.regs.a = (self.state.regs.d | 0x80) & 0xC7
        self.state.regs.d = self.state.regs.a
        self.state.regs.b = 3
        self.state.regs.a = base + 3
        self.state.regs.f = _summary_add_flags(claripy.BVV(base, 8), claripy.BVV(3, 8))
        self.state.regs.h = 0xFF
        self.state.regs.l = base + 4
        low_address, high_address = self._addresses["hardware_frequency"][channel & 3]
        self.state.memory.store(low_address, self.state.regs.e)
        self.state.memory.store(high_address, self.state.regs.d)

        if self._variant == 2 and channel < 4:
            self.state.regs.a = channel
            self.state.regs.f = _summary_cp_flags(claripy.BVV(channel, 8), 4)
            self.jump(self._next_address)
            return

        sound5 = self.state.memory.load(self._addresses["sound_ids"] + 4, 1)
        sound8 = self.state.memory.load(self._addresses["sound_ids"] + 7, 1)
        cry = claripy.And(sound5.UGE(0x14), sound5.ULT(0x86))
        cry_flags = claripy.If(
            cry,
            claripy.BVV(1, 8),
            claripy.If(sound5 == 0x86, claripy.BVV(0x40, 8), claripy.BVV(0, 8)),
        )
        applies = cry
        final_a = sound5
        final_b = self.state.regs.b
        final_flags = cry_flags
        if self._variant == 2:
            combined = sound5 | sound8
            battle = claripy.And(combined.UGE(0x9D), combined.ULT(0xEA))
            battle_flags = claripy.If(
                battle,
                claripy.BVV(1, 8),
                claripy.If(
                    combined == 0xEA,
                    claripy.BVV(0x40, 8),
                    claripy.BVV(0, 8),
                ),
            )
            applies = claripy.Or(cry, battle)
            final_a = claripy.If(cry, sound5, combined)
            final_b = claripy.If(cry, self.state.regs.b, sound8)
            final_flags = claripy.If(cry, cry_flags, battle_flags)

        modifier = self.state.memory.load(self._addresses["frequency_modifier"], 1)
        original_e = self.state.regs.e
        original_d = self.state.regs.d
        result = modifier + original_e
        add_flags = _summary_add_flags(modifier, original_e)
        carry = (add_flags & 1) != 0
        incremented_d = original_d + 1
        increment_flags = (add_flags & 1) | claripy.If(
            incremented_d == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)
        ) | claripy.If(
            (original_d & 0x0F) == 0x0F,
            claripy.BVV(0x10, 8),
            claripy.BVV(0, 8),
        )
        modified_d = claripy.If(carry, incremented_d, original_d)
        modified_flags = claripy.If(carry, increment_flags, add_flags)
        self.state.regs.a = claripy.If(applies, result, final_a)
        self.state.regs.b = final_b
        self.state.regs.d = claripy.If(applies, modified_d, original_d)
        self.state.regs.e = claripy.If(applies, result, original_e)
        self.state.regs.f = claripy.If(applies, modified_flags, final_flags)
        self.state.memory.store(
            low_address, claripy.If(applies, result, original_e)
        )
        self.state.memory.store(
            high_address, claripy.If(applies, modified_d, original_d)
        )
        self.jump(self._next_address)


class PitchSlideDivideLoopSummary(angr.SimProcedure):
    """Closed form of InitPitchSlideVars' repeated-subtraction division loop."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        divisor = self.state.memory.load(self.state.regs.hl, 1)
        divisor16 = claripy.ZeroExt(8, divisor)
        difference = claripy.Concat(self.state.regs.d, self.state.regs.e)
        quotient = difference // divisor16
        remainder = difference % divisor16
        self.state.regs.a = 0
        self.state.regs.b = (quotient + 1)[7:0]
        self.state.regs.d = 0
        self.state.regs.e = remainder[7:0] - divisor
        self.state.regs.f = 0x40  # Z80 Z from the final AND A with A = 0
        self.jump(self._next_address)


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
    sound_id: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class BattleSfxEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    sound5: claripy.ast.BV
    sound8: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class ChannelOutputEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    audio_terminal: claripy.ast.BV
    stereo_panning: claripy.ast.BV
    sfx_sound_ids: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class RegisterEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class DutyPatternEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    duty_patterns: claripy.ast.BV
    hardware_registers: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class DutyLengthEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    note_delays: claripy.ast.BV
    duty_cycles: claripy.ast.BV
    hardware_registers: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class CryModifiersEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    low_health_alarm: claripy.ast.BV
    frequency_modifier: claripy.ast.BV
    tempo_modifier: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class SfxTempoEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    sound5: claripy.ast.BV
    sound8: claripy.ast.BV
    tempo_modifier: claripy.ast.BV
    sfx_tempo_high: claripy.ast.BV
    sfx_tempo_low: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class FrequencyModifierEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    sound5: claripy.ast.BV
    sound8: claripy.ast.BV
    frequency_modifier: claripy.ast.BV
    hardware_registers: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class WaveFrequencyEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    music_instrument: claripy.ast.BV
    sfx_instrument: claripy.ast.BV
    sound5: claripy.ast.BV
    sound8: claripy.ast.BV
    frequency_modifier: claripy.ast.BV
    audio3_enable: claripy.ast.BV
    wave_ram: claripy.ast.BV
    hardware_registers: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class CommandRewindEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    sound5: claripy.ast.BV
    command_pointers: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class NextMusicByteEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    command_pointers: claripy.ast.BV
    command_byte: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class PitchSlideEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    flags1: claripy.ast.BV
    frequency_steps: claripy.ast.BV
    frequency_steps_fractional: claripy.ast.BV
    current_frequency_fractional: claripy.ast.BV
    current_frequency_high: claripy.ast.BV
    current_frequency_low: claripy.ast.BV
    target_frequency_high: claripy.ast.BV
    target_frequency_low: claripy.ast.BV
    hardware_registers: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class InitPitchSlideEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    flags1: claripy.ast.BV
    note_delays: claripy.ast.BV
    length_modifiers: claripy.ast.BV
    frequency_steps: claripy.ast.BV
    frequency_steps_fractional: claripy.ast.BV
    current_frequency_fractional: claripy.ast.BV
    current_frequency_high: claripy.ast.BV
    current_frequency_low: claripy.ast.BV
    target_frequency_high: claripy.ast.BV
    target_frequency_low: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class ExecuteMusicEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    flags2: claripy.ast.BV
    continuation: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class OctaveEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    octaves: claripy.ast.BV
    continuation: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class DutyCommandEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    command_pointers: claripy.ast.BV
    command_byte: claripy.ast.BV
    duty_cycles: claripy.ast.BV
    continuation: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class ByteCommandEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    command_pointers: claripy.ast.BV
    command_byte: claripy.ast.BV
    value: claripy.ast.BV
    continuation: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class DutyPatternCommandEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    command_pointers: claripy.ast.BV
    command_byte: claripy.ast.BV
    duty_patterns: claripy.ast.BV
    duty_cycles: claripy.ast.BV
    flags1: claripy.ast.BV
    continuation: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class TempoCommandEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    command_pointers: claripy.ast.BV
    command_bytes: claripy.ast.BV
    music_tempo: claripy.ast.BV
    sfx_tempo: claripy.ast.BV
    fractional_note_delays: claripy.ast.BV
    continuation: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class TogglePerfectPitchEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    flags1: claripy.ast.BV
    continuation: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class VibratoCommandEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    command_pointers: claripy.ast.BV
    command_bytes: claripy.ast.BV
    delay_counters: claripy.ast.BV
    delay_reloads: claripy.ast.BV
    extents: claripy.ast.BV
    rates: claripy.ast.BV
    continuation: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class PitchSweepEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    command_pointers: claripy.ast.BV
    command_byte: claripy.ast.BV
    flags2: claripy.ast.BV
    sweep: claripy.ast.BV
    continuation: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class PitchSlideCommandEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    command_pointers: claripy.ast.BV
    command_bytes: claripy.ast.BV
    length_modifiers: claripy.ast.BV
    target_frequency_high: claripy.ast.BV
    target_frequency_low: claripy.ast.BV
    flags1: claripy.ast.BV
    continuation: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class NoteTypeEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    command_pointers: claripy.ast.BV
    command_byte: claripy.ast.BV
    note_speeds: claripy.ast.BV
    volumes: claripy.ast.BV
    music_wave_instrument: claripy.ast.BV
    sfx_wave_instrument: claripy.ast.BV
    continuation: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class SoundCallEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    command_pointers: claripy.ast.BV
    command_bytes: claripy.ast.BV
    return_addresses: claripy.ast.BV
    flags1: claripy.ast.BV
    continuation: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class SoundLoopEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    command_pointers: claripy.ast.BV
    command_bytes: claripy.ast.BV
    loop_counters: claripy.ast.BV
    continuation: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class NoteLengthEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    note_speeds: claripy.ast.BV
    music_tempo: claripy.ast.BV
    sfx_tempo: claripy.ast.BV
    fractional_note_delays: claripy.ast.BV
    note_delays: claripy.ast.BV
    flags2: claripy.ast.BV
    flags1: claripy.ast.BV
    sound5: claripy.ast.BV
    sound8: claripy.ast.BV
    tempo_modifier: claripy.ast.BV
    saved_a: claripy.ast.BV
    saved_f: claripy.ast.BV
    continuation: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class NotePitchEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    octaves: claripy.ast.BV
    flags1: claripy.ast.BV
    sfx_sound_ids: claripy.ast.BV
    volumes: claripy.ast.BV
    note_delays: claripy.ast.BV
    duty_cycles: claripy.ast.BV
    hardware_envelopes: claripy.ast.BV
    hardware_duty: claripy.ast.BV
    audio_terminal: claripy.ast.BV
    stereo_panning: claripy.ast.BV
    frequency_low_bytes: claripy.ast.BV
    music_instrument: claripy.ast.BV
    sfx_instrument: claripy.ast.BV
    sound5: claripy.ast.BV
    sound8: claripy.ast.BV
    frequency_modifier: claripy.ast.BV
    audio3_enable: claripy.ast.BV
    wave_ram: claripy.ast.BV
    hardware_frequency: claripy.ast.BV
    length_modifiers: claripy.ast.BV
    frequency_steps: claripy.ast.BV
    frequency_steps_fractional: claripy.ast.BV
    current_frequency_fractional: claripy.ast.BV
    current_frequency_high: claripy.ast.BV
    current_frequency_low: claripy.ast.BV
    target_frequency_high: claripy.ast.BV
    target_frequency_low: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class PlayNextNoteEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    vibrato_delay_reloads: claripy.ast.BV
    vibrato_delay_counters: claripy.ast.BV
    flags1: claripy.ast.BV
    low_health_alarm: claripy.ast.BV
    continuation: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class SoundRetEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    command_pointers: claripy.ast.BV
    command_bytes: claripy.ast.BV
    return_addresses: claripy.ast.BV
    flags1: claripy.ast.BV
    flags2: claripy.ast.BV
    disable_channel_output: claripy.ast.BV
    audio3_enable: claripy.ast.BV
    audio_terminal: claripy.ast.BV
    sound_ids: claripy.ast.BV
    saved_volume: claripy.ast.BV
    audio_volume: claripy.ast.BV
    continuation: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class SfxNoteEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    command_pointers: claripy.ast.BV
    command_bytes: claripy.ast.BV
    note_speeds: claripy.ast.BV
    music_tempo: claripy.ast.BV
    sfx_tempo: claripy.ast.BV
    fractional_note_delays: claripy.ast.BV
    note_delays: claripy.ast.BV
    flags2: claripy.ast.BV
    flags1: claripy.ast.BV
    sound_ids: claripy.ast.BV
    tempo_modifier: claripy.ast.BV
    duty_cycles: claripy.ast.BV
    hardware_envelopes: claripy.ast.BV
    hardware_duty: claripy.ast.BV
    audio_terminal: claripy.ast.BV
    stereo_panning: claripy.ast.BV
    music_instrument: claripy.ast.BV
    sfx_instrument: claripy.ast.BV
    frequency_modifier: claripy.ast.BV
    audio3_enable: claripy.ast.BV
    wave_ram: claripy.ast.BV
    hardware_frequency: claripy.ast.BV
    continuation: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class ApplyMusicAffectsEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    note_delays: claripy.ast.BV
    sound_ids: claripy.ast.BV
    flags1: claripy.ast.BV
    flags2: claripy.ast.BV
    duty_patterns: claripy.ast.BV
    hardware_duty: claripy.ast.BV
    vibrato_delay_counters: claripy.ast.BV
    vibrato_extents: claripy.ast.BV
    vibrato_rates: claripy.ast.BV
    frequency_low_bytes: claripy.ast.BV
    hardware_frequency_low: claripy.ast.BV
    continuation: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class UpdateMusicEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    sound_ids: claripy.ast.BV
    mute_audio_and_pause_music: claripy.ast.BV
    audio_terminal: claripy.ast.BV
    audio3_enable: claripy.ast.BV
    continuation: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class PlaySoundEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    audio_ram: claripy.ast.BV
    hardware_audio: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class UnknownEfEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    audio_ram: claripy.ast.BV
    hardware_audio: claripy.ast.BV
    command_byte: claripy.ast.BV
    continuation: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class NoteEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    audio_ram_0: claripy.ast.BV
    audio_ram_1: claripy.ast.BV
    audio_ram_2: claripy.ast.BV
    audio_ram_3: claripy.ast.BV
    audio_ram_4: claripy.ast.BV
    audio_ram_5: claripy.ast.BV
    audio_ram_6: claripy.ast.BV
    audio_ram_7: claripy.ast.BV
    hardware_audio: claripy.ast.BV
    command_byte: claripy.ast.BV
    continuation: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _assembly_endpoints(
    symbol: str, inputs: dict[str, claripy.ast.BV]
) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, symbol)
    sound_address = symbol_location(SYMBOLS, "wChannelSoundIDs").address + 4
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
    project.hook(
        location.address,
        Sm83LoadAImmediate(sound_address, location.address + 3),
        length=3,
    )
    project.hook(
        location.address + 3,
        Sm83CpImmediate(0x14, location.address + 5),
        length=2,
    )
    project.hook(
        location.address + 9,
        Sm83CpImmediate(0x86, location.address + 11),
        length=2,
    )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    state.memory.store(sound_address, inputs["sound_id"])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    return [
        Endpoint(
            **assembly_registers(end),
            sound_id=end.memory.load(sound_address, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, GB_RETURN)
    ]


def _native_endpoints(
    symbol: str, inputs: dict[str, claripy.ast.BV]
) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["sound_id"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            sound_id=end.memory.load(NATIVE_STATE + 8, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


def _battle_sfx_assembly(
    inputs: dict[str, claripy.ast.BV]
) -> list[BattleSfxEndpoint]:
    location = symbol_location(SYMBOLS, "Audio2_IsBattleSFX")
    channel_base = symbol_location(SYMBOLS, "wChannelSoundIDs").address
    sound5_address = channel_base + 4
    sound8_address = channel_base + 7
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
    project.hook(
        location.address,
        Sm83LoadAImmediate(sound8_address, location.address + 3),
        length=3,
    )
    project.hook(
        location.address + 4,
        Sm83LoadAImmediate(sound5_address, location.address + 7),
        length=3,
    )
    project.hook(
        location.address + 8,
        Sm83CpImmediate(0x9D, location.address + 10),
        length=2,
    )
    project.hook(
        location.address + 14,
        Sm83CpImmediate(0xEA, location.address + 16),
        length=2,
    )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    state.memory.store(sound5_address, inputs["sound5"])
    state.memory.store(sound8_address, inputs["sound8"])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    return [
        BattleSfxEndpoint(
            **assembly_registers(end),
            sound5=end.memory.load(sound5_address, 1),
            sound8=end.memory.load(sound8_address, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, GB_RETURN)
    ]


def _battle_sfx_native(
    inputs: dict[str, claripy.ast.BV]
) -> list[BattleSfxEndpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_audio2_is_battle_sfx")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["sound5"])
    state.memory.store(NATIVE_STATE + 9, inputs["sound8"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        BattleSfxEndpoint(
            **native_registers(end, NATIVE_STATE),
            sound5=end.memory.load(NATIVE_STATE + 8, 1),
            sound8=end.memory.load(NATIVE_STATE + 9, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


def _channel_output_assembly(
    symbol: str, inputs: dict[str, claripy.ast.BV]
) -> list[ChannelOutputEndpoint]:
    location = symbol_location(SYMBOLS, symbol)
    stereo_address = symbol_location(SYMBOLS, "wStereoPanning").address
    sfx_address = symbol_location(SYMBOLS, "wChannelSoundIDs").address + 4
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
    project.hook(
        location.address + 6,
        Sm83LoadAHighImmediate(0x25, location.address + 8),
        length=2,
    )
    project.hook(
        location.address + 11,
        Sm83CpImmediate(7, location.address + 13),
        length=2,
    )
    project.hook(
        location.address + 15,
        Sm83CpImmediate(4, location.address + 17),
        length=2,
    )
    project.hook(
        location.address + 27,
        Sm83LoadAImmediate(stereo_address, location.address + 30),
        length=3,
    )
    project.hook(
        location.address + 36,
        Sm83LoadAHighImmediate(0x25, location.address + 38),
        length=2,
    )
    project.hook(
        location.address + 46,
        Sm83StoreAHighImmediate(0x25, location.address + 48),
        length=2,
    )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    state.memory.store(0xFF25, inputs["audio_terminal"])
    state.memory.store(stereo_address, inputs["stereo_panning"])
    state.memory.store(sfx_address, inputs["sfx_sound_ids"])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    return [
        ChannelOutputEndpoint(
            **assembly_registers(end),
            audio_terminal=end.memory.load(0xFF25, 1),
            stereo_panning=end.memory.load(stereo_address, 1),
            sfx_sound_ids=end.memory.load(sfx_address, 4),
            constraints=tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, GB_RETURN)
    ]


def _channel_output_native(
    symbol: str, inputs: dict[str, claripy.ast.BV]
) -> list[ChannelOutputEndpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["audio_terminal"])
    state.memory.store(NATIVE_STATE + 9, inputs["stereo_panning"])
    state.memory.store(NATIVE_STATE + 10, inputs["sfx_sound_ids"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        ChannelOutputEndpoint(
            **native_registers(end, NATIVE_STATE),
            audio_terminal=end.memory.load(NATIVE_STATE + 8, 1),
            stereo_panning=end.memory.load(NATIVE_STATE + 9, 1),
            sfx_sound_ids=end.memory.load(NATIVE_STATE + 10, 4),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@lru_cache(maxsize=None)
def _multiply_add_assembly_project(symbol: str) -> tuple[angr.Project, int]:
    location = symbol_location(SYMBOLS, symbol)
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
    project.hook(
        location.address + 2,
        Sm83SrlRegister("a", location.address + 4),
        length=2,
    )
    project.hook(
        location.address + 7,
        Sm83SlaRegister("e", location.address + 9),
        length=2,
    )
    project.hook(
        location.address + 9,
        Sm83RlRegister("d", location.address + 11),
        length=2,
    )
    return project, location.address


def _multiply_add_assembly(
    symbol: str, inputs: dict[str, claripy.ast.BV]
) -> RegisterEndpoint:
    project, address = _multiply_add_assembly_project(symbol)
    state = project.factory.blank_state(addr=address)
    set_assembly_registers(state, inputs)
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    end = collect_returns(project, state, GB_RETURN)[0]
    return RegisterEndpoint(
        **assembly_registers(end), constraints=tuple(end.solver.constraints)
    )


@lru_cache(maxsize=None)
def _multiply_add_native_project(symbol: str) -> tuple[angr.Project, int]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(symbol)
    assert function is not None
    return project, function.rebased_addr


def _multiply_add_native(
    symbol: str, inputs: dict[str, claripy.ast.BV]
) -> RegisterEndpoint:
    project, address = _multiply_add_native_project(symbol)
    state = project.factory.call_state(address, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    end = manager.deadended[0]
    return RegisterEndpoint(
        **native_registers(end, NATIVE_STATE),
        constraints=tuple(end.solver.constraints),
    )


def _register_pointer_assembly(
    symbol: str, inputs: dict[str, claripy.ast.BV]
) -> RegisterEndpoint:
    location = symbol_location(SYMBOLS, symbol)
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
    project.hook(
        location.address + 4,
        Sm83AddRegister("l", location.address + 5),
        length=1,
    )
    project.hook(
        location.address + 10,
        Sm83AddRegister("b", location.address + 11),
        length=1,
    )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    end = collect_returns(project, state, GB_RETURN)[0]
    return RegisterEndpoint(
        **assembly_registers(end), constraints=tuple(end.solver.constraints)
    )


@lru_cache(maxsize=None)
def _calculate_frequency_assembly_project(symbol: str) -> tuple[angr.Project, int]:
    location = symbol_location(SYMBOLS, symbol)
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
    project.hook(
        location.address + 14,
        Sm83CpImmediate(7, location.address + 16),
        length=2,
    )
    project.hook(
        location.address + 18,
        Sm83SraRegister("d", location.address + 20),
        length=2,
    )
    project.hook(
        location.address + 20,
        Sm83RrRegister("e", location.address + 22),
        length=2,
    )
    project.hook(
        location.address + 22,
        Sm83IncRegister("a", location.address + 23),
        length=1,
    )
    project.hook(
        location.address + 27,
        Sm83AddRegister("d", location.address + 28),
        length=1,
    )
    return project, location.address


def _calculate_frequency_assembly(
    symbol: str, inputs: dict[str, claripy.ast.BV]
) -> RegisterEndpoint:
    project, address = _calculate_frequency_assembly_project(symbol)
    state = project.factory.blank_state(addr=address)
    set_assembly_registers(state, inputs)
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    end = collect_returns(project, state, GB_RETURN)[0]
    return RegisterEndpoint(
        **assembly_registers(end), constraints=tuple(end.solver.constraints)
    )


@lru_cache(maxsize=None)
def _duty_pattern_assembly_project(symbol: str) -> tuple[angr.Project, int]:
    location = symbol_location(SYMBOLS, symbol)
    callee_name = symbol.replace("ApplyDutyCyclePattern", "GetRegisterPointer")
    callee = symbol_location(SYMBOLS, callee_name)
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
    project.hook(
        callee.address + 4,
        Sm83AddRegister("l", callee.address + 5),
        length=1,
    )
    project.hook(
        callee.address + 10,
        Sm83AddRegister("b", callee.address + 11),
        length=1,
    )
    return project, location.address


def _duty_pattern_assembly(
    symbol: str, inputs: dict[str, claripy.ast.BV]
) -> DutyPatternEndpoint:
    project, address = _duty_pattern_assembly_project(symbol)
    duty_address = symbol_location(SYMBOLS, "wChannelDutyCyclePatterns").address
    hardware_addresses = (0xFF11, 0xFF16, 0xFF1B, 0xFF20)
    state = project.factory.blank_state(addr=address)
    set_assembly_registers(state, inputs)
    state.memory.store(duty_address, inputs["duty_patterns"])
    for index, hardware_address in enumerate(hardware_addresses):
        high = 31 - index * 8
        state.memory.store(hardware_address, inputs["hardware_registers"][high : high - 7])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    end = collect_returns(project, state, GB_RETURN)[0]
    return DutyPatternEndpoint(
        **assembly_registers(end),
        duty_patterns=end.memory.load(duty_address, 8),
        hardware_registers=claripy.Concat(
            *(end.memory.load(hardware_address, 1) for hardware_address in hardware_addresses)
        ),
        constraints=tuple(end.solver.constraints),
    )


def _duty_pattern_native(
    symbol: str, inputs: dict[str, claripy.ast.BV]
) -> DutyPatternEndpoint:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["duty_patterns"])
    state.memory.store(NATIVE_STATE + 16, inputs["hardware_registers"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    end = manager.deadended[0]
    return DutyPatternEndpoint(
        **native_registers(end, NATIVE_STATE),
        duty_patterns=end.memory.load(NATIVE_STATE + 8, 8),
        hardware_registers=end.memory.load(NATIVE_STATE + 16, 4),
        constraints=tuple(end.solver.constraints),
    )


@lru_cache(maxsize=None)
def _duty_length_assembly_project(symbol: str) -> tuple[angr.Project, int]:
    location = symbol_location(SYMBOLS, symbol)
    callee_name = symbol.replace("ApplyDutyCycleAndSoundLength", "GetRegisterPointer")
    callee = symbol_location(SYMBOLS, callee_name)
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
    project.hook(
        location.address + 8,
        Sm83CpImmediate(2, location.address + 10),
        length=2,
    )
    project.hook(
        location.address + 12,
        Sm83CpImmediate(6, location.address + 14),
        length=2,
    )
    project.hook(
        callee.address + 4,
        Sm83AddRegister("l", callee.address + 5),
        length=1,
    )
    project.hook(
        callee.address + 10,
        Sm83AddRegister("b", callee.address + 11),
        length=1,
    )
    return project, location.address


def _duty_length_assembly(
    symbol: str, inputs: dict[str, claripy.ast.BV]
) -> DutyLengthEndpoint:
    project, address = _duty_length_assembly_project(symbol)
    note_delay_address = symbol_location(SYMBOLS, "wChannelNoteDelayCounters").address
    duty_cycle_address = symbol_location(SYMBOLS, "wChannelDutyCycles").address
    hardware_addresses = (0xFF11, 0xFF16, 0xFF1B, 0xFF20)
    state = project.factory.blank_state(addr=address)
    set_assembly_registers(state, inputs)
    state.memory.store(note_delay_address, inputs["note_delays"])
    state.memory.store(duty_cycle_address, inputs["duty_cycles"])
    for index, hardware_address in enumerate(hardware_addresses):
        high = 31 - index * 8
        state.memory.store(
            hardware_address, inputs["hardware_registers"][high : high - 7]
        )
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    end = collect_returns(project, state, GB_RETURN)[0]
    return DutyLengthEndpoint(
        **assembly_registers(end),
        note_delays=end.memory.load(note_delay_address, 8),
        duty_cycles=end.memory.load(duty_cycle_address, 8),
        hardware_registers=claripy.Concat(
            *(end.memory.load(hardware_address, 1) for hardware_address in hardware_addresses)
        ),
        constraints=tuple(end.solver.constraints),
    )


def _duty_length_native(
    symbol: str, inputs: dict[str, claripy.ast.BV]
) -> DutyLengthEndpoint:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["note_delays"])
    state.memory.store(NATIVE_STATE + 16, inputs["duty_cycles"])
    state.memory.store(NATIVE_STATE + 24, inputs["hardware_registers"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    end = manager.deadended[0]
    return DutyLengthEndpoint(
        **native_registers(end, NATIVE_STATE),
        note_delays=end.memory.load(NATIVE_STATE + 8, 8),
        duty_cycles=end.memory.load(NATIVE_STATE + 16, 8),
        hardware_registers=end.memory.load(NATIVE_STATE + 24, 4),
        constraints=tuple(end.solver.constraints),
    )


def _reset_cry_modifiers_assembly(
    inputs: dict[str, claripy.ast.BV],
) -> list[CryModifiersEndpoint]:
    location = symbol_location(SYMBOLS, "Audio2_ResetCryModifiers")
    low_health_address = symbol_location(SYMBOLS, "wLowHealthAlarm").address
    frequency_address = symbol_location(SYMBOLS, "wFrequencyModifier").address
    tempo_address = symbol_location(SYMBOLS, "wTempoModifier").address
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
    project.hook(
        location.address + 1,
        Sm83CpImmediate(4, location.address + 3),
        length=2,
    )
    project.hook(
        location.address + 5,
        Sm83LoadAImmediate(low_health_address, location.address + 8),
        length=3,
    )
    project.hook(
        location.address + 8,
        Sm83BitRegister(7, "a", location.address + 10),
        length=2,
    )
    project.hook(
        location.address + 13,
        Sm83StoreAImmediate(frequency_address, location.address + 16),
        length=3,
    )
    project.hook(
        location.address + 18,
        Sm83StoreAImmediate(tempo_address, location.address + 21),
        length=3,
    )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    state.memory.store(low_health_address, inputs["low_health_alarm"])
    state.memory.store(frequency_address, inputs["frequency_modifier"])
    state.memory.store(tempo_address, inputs["tempo_modifier"])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    return [
        CryModifiersEndpoint(
            **assembly_registers(end),
            low_health_alarm=end.memory.load(low_health_address, 1),
            frequency_modifier=end.memory.load(frequency_address, 1),
            tempo_modifier=end.memory.load(tempo_address, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, GB_RETURN)
    ]


def _reset_cry_modifiers_native(
    inputs: dict[str, claripy.ast.BV],
) -> list[CryModifiersEndpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_audio2_reset_cry_modifiers")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["low_health_alarm"])
    state.memory.store(NATIVE_STATE + 9, inputs["frequency_modifier"])
    state.memory.store(NATIVE_STATE + 10, inputs["tempo_modifier"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        CryModifiersEndpoint(
            **native_registers(end, NATIVE_STATE),
            low_health_alarm=end.memory.load(NATIVE_STATE + 8, 1),
            frequency_modifier=end.memory.load(NATIVE_STATE + 9, 1),
            tempo_modifier=end.memory.load(NATIVE_STATE + 10, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


def _set_sfx_tempo_assembly(
    symbol: str, inputs: dict[str, claripy.ast.BV]
) -> list[SfxTempoEndpoint]:
    location = symbol_location(SYMBOLS, symbol)
    variant = int(symbol[5])
    is_cry = symbol_location(SYMBOLS, f"Audio{variant}_IsCry")
    sound_address = symbol_location(SYMBOLS, "wChannelSoundIDs").address
    tempo_modifier_address = symbol_location(SYMBOLS, "wTempoModifier").address
    sfx_tempo_address = symbol_location(SYMBOLS, "wSfxTempo").address
    body_offset = 10 if variant == 2 else 5
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
    project.hook(
        is_cry.address,
        Sm83LoadAImmediate(sound_address + 4, is_cry.address + 3),
        length=3,
    )
    project.hook(
        is_cry.address + 3,
        Sm83CpImmediate(0x14, is_cry.address + 5),
        length=2,
    )
    project.hook(
        is_cry.address + 9,
        Sm83CpImmediate(0x86, is_cry.address + 11),
        length=2,
    )
    if variant == 2:
        battle = symbol_location(SYMBOLS, "Audio2_IsBattleSFX")
        project.hook(
            battle.address,
            Sm83LoadAImmediate(sound_address + 7, battle.address + 3),
            length=3,
        )
        project.hook(
            battle.address + 4,
            Sm83LoadAImmediate(sound_address + 4, battle.address + 7),
            length=3,
        )
        project.hook(
            battle.address + 8,
            Sm83CpImmediate(0x9D, battle.address + 10),
            length=2,
        )
        project.hook(
            battle.address + 14,
            Sm83CpImmediate(0xEA, battle.address + 16),
            length=2,
        )
    project.hook(
        location.address + body_offset + 2,
        Sm83LoadAImmediate(
            tempo_modifier_address, location.address + body_offset + 5
        ),
        length=3,
    )
    project.hook(
        location.address + body_offset + 5,
        Sm83AddImmediate(0x80, location.address + body_offset + 7),
        length=2,
    )
    project.hook(
        location.address + body_offset + 9,
        Sm83IncRegister("d", location.address + body_offset + 10),
        length=1,
    )
    for offset, memory_address, next_offset in (
        (10, sfx_tempo_address + 1, 13),
        (14, sfx_tempo_address, 17),
        (20, sfx_tempo_address + 1, 23),
        (25, sfx_tempo_address, 28),
    ):
        project.hook(
            location.address + body_offset + offset,
            Sm83StoreAImmediate(
                memory_address, location.address + body_offset + next_offset
            ),
            length=3,
        )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    state.memory.store(sound_address + 4, inputs["sound5"])
    state.memory.store(sound_address + 7, inputs["sound8"])
    state.memory.store(tempo_modifier_address, inputs["tempo_modifier"])
    state.memory.store(sfx_tempo_address, inputs["sfx_tempo_high"])
    state.memory.store(sfx_tempo_address + 1, inputs["sfx_tempo_low"])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    return [
        SfxTempoEndpoint(
            **assembly_registers(end),
            sound5=end.memory.load(sound_address + 4, 1),
            sound8=end.memory.load(sound_address + 7, 1),
            tempo_modifier=end.memory.load(tempo_modifier_address, 1),
            sfx_tempo_high=end.memory.load(sfx_tempo_address, 1),
            sfx_tempo_low=end.memory.load(sfx_tempo_address + 1, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, GB_RETURN)
    ]


def _set_sfx_tempo_native(
    symbol: str, inputs: dict[str, claripy.ast.BV]
) -> list[SfxTempoEndpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["sound5"])
    state.memory.store(NATIVE_STATE + 9, inputs["sound8"])
    state.memory.store(NATIVE_STATE + 10, inputs["tempo_modifier"])
    state.memory.store(NATIVE_STATE + 11, inputs["sfx_tempo_high"])
    state.memory.store(NATIVE_STATE + 12, inputs["sfx_tempo_low"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        SfxTempoEndpoint(
            **native_registers(end, NATIVE_STATE),
            sound5=end.memory.load(NATIVE_STATE + 8, 1),
            sound8=end.memory.load(NATIVE_STATE + 9, 1),
            tempo_modifier=end.memory.load(NATIVE_STATE + 10, 1),
            sfx_tempo_high=end.memory.load(NATIVE_STATE + 11, 1),
            sfx_tempo_low=end.memory.load(NATIVE_STATE + 12, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


def _apply_frequency_modifier_assembly(
    symbol: str, inputs: dict[str, claripy.ast.BV]
) -> list[FrequencyModifierEndpoint]:
    location = symbol_location(SYMBOLS, symbol)
    variant = int(symbol[5])
    is_cry = symbol_location(SYMBOLS, f"Audio{variant}_IsCry")
    sound_address = symbol_location(SYMBOLS, "wChannelSoundIDs").address
    modifier_address = symbol_location(SYMBOLS, "wFrequencyModifier").address
    hardware_addresses = (0xFF13, 0xFF14, 0xFF18, 0xFF19, 0xFF1D, 0xFF1E, 0xFF22, 0xFF23)
    body_offset = 10 if variant == 2 else 5
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
    project.hook(
        is_cry.address,
        Sm83LoadAImmediate(sound_address + 4, is_cry.address + 3),
        length=3,
    )
    project.hook(
        is_cry.address + 3,
        Sm83CpImmediate(0x14, is_cry.address + 5),
        length=2,
    )
    project.hook(
        is_cry.address + 9,
        Sm83CpImmediate(0x86, is_cry.address + 11),
        length=2,
    )
    if variant == 2:
        battle = symbol_location(SYMBOLS, "Audio2_IsBattleSFX")
        project.hook(
            battle.address,
            Sm83LoadAImmediate(sound_address + 7, battle.address + 3),
            length=3,
        )
        project.hook(
            battle.address + 4,
            Sm83LoadAImmediate(sound_address + 4, battle.address + 7),
            length=3,
        )
        project.hook(
            battle.address + 8,
            Sm83CpImmediate(0x9D, battle.address + 10),
            length=2,
        )
        project.hook(
            battle.address + 14,
            Sm83CpImmediate(0xEA, battle.address + 16),
            length=2,
        )
    project.hook(
        location.address + body_offset,
        Sm83LoadAImmediate(modifier_address, location.address + body_offset + 3),
        length=3,
    )
    project.hook(
        location.address + body_offset + 3,
        Sm83AddRegister("e", location.address + body_offset + 4),
        length=1,
    )
    project.hook(
        location.address + body_offset + 6,
        Sm83IncRegister("d", location.address + body_offset + 7),
        length=1,
    )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    state.memory.store(sound_address + 4, inputs["sound5"])
    state.memory.store(sound_address + 7, inputs["sound8"])
    state.memory.store(modifier_address, inputs["frequency_modifier"])
    for index, hardware_address in enumerate(hardware_addresses):
        high = 63 - index * 8
        state.memory.store(
            hardware_address, inputs["hardware_registers"][high : high - 7]
        )
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    return [
        FrequencyModifierEndpoint(
            **assembly_registers(end),
            sound5=end.memory.load(sound_address + 4, 1),
            sound8=end.memory.load(sound_address + 7, 1),
            frequency_modifier=end.memory.load(modifier_address, 1),
            hardware_registers=claripy.Concat(
                *(end.memory.load(address, 1) for address in hardware_addresses)
            ),
            constraints=tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, GB_RETURN)
    ]


def _apply_frequency_modifier_native(
    symbol: str, inputs: dict[str, claripy.ast.BV]
) -> list[FrequencyModifierEndpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["sound5"])
    state.memory.store(NATIVE_STATE + 9, inputs["sound8"])
    state.memory.store(NATIVE_STATE + 10, inputs["frequency_modifier"])
    state.memory.store(NATIVE_STATE + 11, inputs["hardware_registers"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        FrequencyModifierEndpoint(
            **native_registers(end, NATIVE_STATE),
            sound5=end.memory.load(NATIVE_STATE + 8, 1),
            sound8=end.memory.load(NATIVE_STATE + 9, 1),
            frequency_modifier=end.memory.load(NATIVE_STATE + 10, 1),
            hardware_registers=end.memory.load(NATIVE_STATE + 11, 8),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@lru_cache(maxsize=None)
def _wave_frequency_assembly_project(symbol: str) -> tuple[angr.Project, int]:
    location = symbol_location(SYMBOLS, symbol)
    variant = int(symbol[5])
    get_pointer = symbol_location(SYMBOLS, f"Audio{variant}_GetRegisterPointer")
    modifier = symbol_location(SYMBOLS, f"Audio{variant}_ApplyFrequencyModifier")
    is_cry = symbol_location(SYMBOLS, f"Audio{variant}_IsCry")
    sound_address = symbol_location(SYMBOLS, "wChannelSoundIDs").address
    frequency_modifier_address = symbol_location(SYMBOLS, "wFrequencyModifier").address
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
    for offset, immediate in ((1, 2), (5, 6), (13, 2)):
        project.hook(
            location.address + offset,
            Sm83CpImmediate(immediate, location.address + offset + 2),
            length=2,
        )
    project.hook(
        location.address + 39,
        Sm83StoreAHighImmediate(0x1A, location.address + 41),
        length=2,
    )
    project.hook(
        location.address + 43,
        Sm83StoreAAtHlIncrement(location.address + 44),
        length=1,
    )
    project.hook(
        location.address + 45,
        Sm83DecRegister("b", location.address + 46),
        length=1,
    )
    project.hook(
        location.address + 51,
        Sm83StoreAHighImmediate(0x1A, location.address + 53),
        length=2,
    )
    project.hook(
        get_pointer.address + 4,
        Sm83AddRegister("l", get_pointer.address + 5),
        length=1,
    )
    project.hook(
        get_pointer.address + 10,
        Sm83AddRegister("b", get_pointer.address + 11),
        length=1,
    )
    if variant == 2:
        project.hook(
            location.address + 69,
            Sm83CpImmediate(4, location.address + 71),
            length=2,
        )
    project.hook(
        is_cry.address,
        Sm83LoadAImmediate(sound_address + 4, is_cry.address + 3),
        length=3,
    )
    project.hook(
        is_cry.address + 3,
        Sm83CpImmediate(0x14, is_cry.address + 5),
        length=2,
    )
    project.hook(
        is_cry.address + 9,
        Sm83CpImmediate(0x86, is_cry.address + 11),
        length=2,
    )
    if variant == 2:
        battle = symbol_location(SYMBOLS, "Audio2_IsBattleSFX")
        project.hook(
            battle.address,
            Sm83LoadAImmediate(sound_address + 7, battle.address + 3),
            length=3,
        )
        project.hook(
            battle.address + 4,
            Sm83LoadAImmediate(sound_address + 4, battle.address + 7),
            length=3,
        )
        project.hook(
            battle.address + 8,
            Sm83CpImmediate(0x9D, battle.address + 10),
            length=2,
        )
        project.hook(
            battle.address + 14,
            Sm83CpImmediate(0xEA, battle.address + 16),
            length=2,
        )
    modifier_body = 10 if variant == 2 else 5
    project.hook(
        modifier.address + modifier_body,
        Sm83LoadAImmediate(
            frequency_modifier_address, modifier.address + modifier_body + 3
        ),
        length=3,
    )
    project.hook(
        modifier.address + modifier_body + 3,
        Sm83AddRegister("e", modifier.address + modifier_body + 4),
        length=1,
    )
    project.hook(
        modifier.address + modifier_body + 6,
        Sm83IncRegister("d", modifier.address + modifier_body + 7),
        length=1,
    )
    return project, location.address


def _wave_frequency_assembly(
    symbol: str, inputs: dict[str, claripy.ast.BV]
) -> list[WaveFrequencyEndpoint]:
    project, address = _wave_frequency_assembly_project(symbol)
    music_instrument_address = symbol_location(SYMBOLS, "wMusicWaveInstrument").address
    sfx_instrument_address = symbol_location(SYMBOLS, "wSfxWaveInstrument").address
    sound_address = symbol_location(SYMBOLS, "wChannelSoundIDs").address
    modifier_address = symbol_location(SYMBOLS, "wFrequencyModifier").address
    hardware_addresses = (0xFF13, 0xFF14, 0xFF18, 0xFF19, 0xFF1D, 0xFF1E, 0xFF22, 0xFF23)
    state = project.factory.blank_state(addr=address)
    set_assembly_registers(state, inputs)
    state.memory.store(music_instrument_address, inputs["music_instrument"])
    state.memory.store(sfx_instrument_address, inputs["sfx_instrument"])
    state.memory.store(sound_address + 4, inputs["sound5"])
    state.memory.store(sound_address + 7, inputs["sound8"])
    state.memory.store(modifier_address, inputs["frequency_modifier"])
    state.memory.store(0xFF1A, inputs["audio3_enable"])
    state.memory.store(0xFF30, inputs["wave_ram"])
    for index, hardware_address in enumerate(hardware_addresses):
        high = 63 - index * 8
        state.memory.store(
            hardware_address, inputs["hardware_registers"][high : high - 7]
        )
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    return [
        WaveFrequencyEndpoint(
            **assembly_registers(end),
            music_instrument=end.memory.load(music_instrument_address, 1),
            sfx_instrument=end.memory.load(sfx_instrument_address, 1),
            sound5=end.memory.load(sound_address + 4, 1),
            sound8=end.memory.load(sound_address + 7, 1),
            frequency_modifier=end.memory.load(modifier_address, 1),
            audio3_enable=end.memory.load(0xFF1A, 1),
            wave_ram=end.memory.load(0xFF30, 16),
            hardware_registers=claripy.Concat(
                *(end.memory.load(item, 1) for item in hardware_addresses)
            ),
            constraints=tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, GB_RETURN)
    ]


def _wave_frequency_native(
    symbol: str, inputs: dict[str, claripy.ast.BV]
) -> list[WaveFrequencyEndpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["music_instrument"])
    state.memory.store(NATIVE_STATE + 9, inputs["sfx_instrument"])
    state.memory.store(NATIVE_STATE + 10, inputs["sound5"])
    state.memory.store(NATIVE_STATE + 11, inputs["sound8"])
    state.memory.store(NATIVE_STATE + 12, inputs["frequency_modifier"])
    state.memory.store(NATIVE_STATE + 13, inputs["audio3_enable"])
    state.memory.store(NATIVE_STATE + 14, inputs["wave_ram"])
    state.memory.store(NATIVE_STATE + 30, inputs["hardware_registers"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        WaveFrequencyEndpoint(
            **native_registers(end, NATIVE_STATE),
            music_instrument=end.memory.load(NATIVE_STATE + 8, 1),
            sfx_instrument=end.memory.load(NATIVE_STATE + 9, 1),
            sound5=end.memory.load(NATIVE_STATE + 10, 1),
            sound8=end.memory.load(NATIVE_STATE + 11, 1),
            frequency_modifier=end.memory.load(NATIVE_STATE + 12, 1),
            audio3_enable=end.memory.load(NATIVE_STATE + 13, 1),
            wave_ram=end.memory.load(NATIVE_STATE + 14, 16),
            hardware_registers=end.memory.load(NATIVE_STATE + 30, 8),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@lru_cache(maxsize=None)
def _command_rewind_assembly_project(symbol: str) -> tuple[angr.Project, int]:
    location = symbol_location(SYMBOLS, symbol)
    variant = int(symbol[5])
    is_cry = symbol_location(SYMBOLS, f"Audio{variant}_IsCry")
    sound_address = symbol_location(SYMBOLS, "wChannelSoundIDs").address + 4
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
    project.hook(
        is_cry.address,
        Sm83LoadAImmediate(sound_address, is_cry.address + 3),
        length=3,
    )
    project.hook(
        is_cry.address + 3,
        Sm83CpImmediate(0x14, is_cry.address + 5),
        length=2,
    )
    project.hook(
        is_cry.address + 9,
        Sm83CpImmediate(0x86, is_cry.address + 11),
        length=2,
    )
    project.hook(
        location.address + 11,
        Sm83SlaRegister("e", location.address + 13),
        length=2,
    )
    project.hook(
        location.address + 13,
        Sm83RlRegister("d", location.address + 15),
        length=2,
    )
    project.hook(
        location.address + 17,
        Sm83SubImmediate(1, location.address + 19),
        length=2,
    )
    project.hook(
        location.address + 22,
        Sm83SbcImmediate(0, location.address + 24),
        length=2,
    )
    return project, location.address


def _command_rewind_assembly(
    symbol: str, inputs: dict[str, claripy.ast.BV]
) -> list[CommandRewindEndpoint]:
    project, address = _command_rewind_assembly_project(symbol)
    sound_address = symbol_location(SYMBOLS, "wChannelSoundIDs").address + 4
    pointer_address = symbol_location(SYMBOLS, "wChannelCommandPointers").address
    state = project.factory.blank_state(addr=address)
    set_assembly_registers(state, inputs)
    state.memory.store(sound_address, inputs["sound5"])
    state.memory.store(pointer_address, inputs["command_pointers"])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    return [
        CommandRewindEndpoint(
            **assembly_registers(end),
            sound5=end.memory.load(sound_address, 1),
            command_pointers=end.memory.load(pointer_address, 16),
            constraints=tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, GB_RETURN)
    ]


def _command_rewind_native(
    symbol: str, inputs: dict[str, claripy.ast.BV]
) -> list[CommandRewindEndpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["sound5"])
    state.memory.store(NATIVE_STATE + 9, inputs["command_pointers"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        CommandRewindEndpoint(
            **native_registers(end, NATIVE_STATE),
            sound5=end.memory.load(NATIVE_STATE + 8, 1),
            command_pointers=end.memory.load(NATIVE_STATE + 9, 16),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@lru_cache(maxsize=None)
def _next_music_byte_assembly_project(symbol: str) -> tuple[angr.Project, int]:
    location = symbol_location(SYMBOLS, symbol)
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
    project.hook(
        location.address + 3,
        Sm83AddRegister("a", location.address + 4),
        length=1,
    )
    project.hook(
        location.address + 8,
        Sm83AddHlRegisterPair("de", location.address + 9),
        length=1,
    )
    project.hook(
        location.address + 9,
        Sm83LoadAAtHlIncrement(location.address + 10),
        length=1,
    )
    project.hook(
        location.address + 11,
        Sm83LoadAAtHlDecrement(location.address + 12),
        length=1,
    )
    project.hook(
        location.address + 13,
        Sm83LoadSymbolicCommandByte(location.address + 14),
        length=1,
    )
    return project, location.address


def _next_music_byte_pointer(
    pointers: claripy.ast.BV, channel: int
) -> claripy.ast.BV:
    offset = channel * 2
    return claripy.Concat(pointers.get_byte(offset + 1), pointers.get_byte(offset))


def _next_music_byte_assembly(
    symbol: str, inputs: dict[str, claripy.ast.BV], channel: int
) -> NextMusicByteEndpoint:
    project, address = _next_music_byte_assembly_project(symbol)
    pointer_address = symbol_location(SYMBOLS, "wChannelCommandPointers").address
    state = project.factory.blank_state(addr=address)
    set_assembly_registers(state, inputs)
    state.memory.store(pointer_address, inputs["command_pointers"])
    pointer = claripy.Concat(
        state.memory.load(pointer_address + channel * 2 + 1, 1),
        state.memory.load(pointer_address + channel * 2, 1),
    )
    state.solver.add(pointer.UGE(0x4000), pointer.ULE(0x7FFF))
    state.globals["command_byte"] = inputs["command_byte"]
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    end = collect_returns(project, state, GB_RETURN)[0]
    return NextMusicByteEndpoint(
        **assembly_registers(end),
        command_pointers=end.memory.load(pointer_address, 16),
        command_byte=inputs["command_byte"],
        constraints=tuple(end.solver.constraints),
    )


def _next_music_byte_native(
    symbol: str, inputs: dict[str, claripy.ast.BV], channel: int
) -> NextMusicByteEndpoint:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["command_pointers"])
    state.memory.store(NATIVE_STATE + 24, inputs["command_byte"])
    pointer = _next_music_byte_pointer(inputs["command_pointers"], channel)
    state.solver.add(pointer.UGE(0x4000), pointer.ULE(0x7FFF))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    end = manager.deadended[0]
    return NextMusicByteEndpoint(
        **native_registers(end, NATIVE_STATE),
        command_pointers=end.memory.load(NATIVE_STATE + 8, 16),
        command_byte=end.memory.load(NATIVE_STATE + 24, 1),
        constraints=tuple(end.solver.constraints),
    )


@lru_cache(maxsize=None)
def _pitch_slide_assembly_project(symbol: str) -> tuple[angr.Project, int]:
    location = symbol_location(SYMBOLS, symbol)
    variant = int(symbol[5])
    get_pointer = symbol_location(SYMBOLS, f"Audio{variant}_GetRegisterPointer")
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
    for offset in (3, 12, 17, 22, 31, 36, 52, 63, 74, 79, 84, 94, 107, 117, 125, 130, 144):
        project.hook(
            location.address + offset,
            Sm83AddHlRegisterPair("bc", location.address + offset + 1),
            length=1,
        )
    project.hook(
        location.address + 4,
        Sm83BitAtHl(5, location.address + 6),
        length=2,
    )
    project.hook(
        location.address + 25,
        Sm83AddHlRegisterPair("de", location.address + 26),
        length=1,
    )
    project.hook(
        location.address + 39,
        Sm83AddAtHl(location.address + 40),
        length=1,
    )
    project.hook(
        location.address + 43,
        Sm83AdcRegister("e", location.address + 44),
        length=1,
    )
    project.hook(
        location.address + 47,
        Sm83AdcRegister("d", location.address + 48),
        length=1,
    )
    project.hook(
        location.address + 54,
        Sm83CpRegister("d", location.address + 55),
        length=1,
    )
    project.hook(
        location.address + 65,
        Sm83CpRegister("e", location.address + 66),
        length=1,
    )
    project.hook(
        location.address + 86,
        Sm83SubRegister("e", location.address + 87),
        length=1,
    )
    project.hook(
        location.address + 89,
        Sm83SbcRegister("b", location.address + 90),
        length=1,
    )
    project.hook(
        location.address + 96,
        Sm83AddRegister("a", location.address + 97),
        length=1,
    )
    for offset in (99, 102):
        project.hook(
            location.address + offset,
            Sm83SbcRegister("b", location.address + offset + 1),
            length=1,
        )
    for offset in (109, 119):
        project.hook(
            location.address + offset,
            Sm83CpAtHl(location.address + offset + 1),
            length=1,
        )
    project.hook(
        location.address + 138,
        Sm83StoreAAtHlIncrement(location.address + 139),
        length=1,
    )
    project.hook(
        location.address + 145,
        Sm83ResAtHl(4, location.address + 147),
        length=2,
    )
    project.hook(
        location.address + 147,
        Sm83ResAtHl(5, location.address + 149),
        length=2,
    )
    project.hook(
        get_pointer.address + 4,
        Sm83AddRegister("l", get_pointer.address + 5),
        length=1,
    )
    project.hook(
        get_pointer.address + 10,
        Sm83AddRegister("b", get_pointer.address + 11),
        length=1,
    )
    return project, location.address


def _pitch_slide_addresses() -> dict[str, int]:
    return {
        "flags1": symbol_location(SYMBOLS, "wChannelFlags1").address,
        "frequency_steps": symbol_location(
            SYMBOLS, "wChannelPitchSlideFrequencySteps"
        ).address,
        "frequency_steps_fractional": symbol_location(
            SYMBOLS, "wChannelPitchSlideFrequencyStepsFractionalPart"
        ).address,
        "current_frequency_fractional": symbol_location(
            SYMBOLS, "wChannelPitchSlideCurrentFrequencyFractionalPart"
        ).address,
        "current_frequency_high": symbol_location(
            SYMBOLS, "wChannelPitchSlideCurrentFrequencyHighBytes"
        ).address,
        "current_frequency_low": symbol_location(
            SYMBOLS, "wChannelPitchSlideCurrentFrequencyLowBytes"
        ).address,
        "target_frequency_high": symbol_location(
            SYMBOLS, "wChannelPitchSlideTargetFrequencyHighBytes"
        ).address,
        "target_frequency_low": symbol_location(
            SYMBOLS, "wChannelPitchSlideTargetFrequencyLowBytes"
        ).address,
    }


def _pitch_slide_assembly(
    symbol: str,
    inputs: dict[str, claripy.ast.BV],
    channel: int,
    decreasing: bool,
) -> list[PitchSlideEndpoint]:
    project, address = _pitch_slide_assembly_project(symbol)
    addresses = _pitch_slide_addresses()
    hardware_addresses = (0xFF13, 0xFF14, 0xFF18, 0xFF19, 0xFF1D, 0xFF1E, 0xFF22, 0xFF23)
    state = project.factory.blank_state(addr=address)
    set_assembly_registers(state, inputs)
    for name, memory_address in addresses.items():
        state.memory.store(memory_address, inputs[name])
    selected_flags = state.memory.load(addresses["flags1"] + channel, 1)
    if decreasing:
        state.solver.add((selected_flags & 0x20) != 0)
    else:
        state.solver.add((selected_flags & 0x20) == 0)
    for index, hardware_address in enumerate(hardware_addresses):
        high = 63 - index * 8
        state.memory.store(
            hardware_address, inputs["hardware_registers"][high : high - 7]
        )
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    return [
        PitchSlideEndpoint(
            **assembly_registers(end),
            **{
                name: end.memory.load(memory_address, 8)
                for name, memory_address in addresses.items()
            },
            hardware_registers=claripy.Concat(
                *(end.memory.load(item, 1) for item in hardware_addresses)
            ),
            constraints=tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, GB_RETURN)
    ]


def _pitch_slide_native(
    symbol: str,
    inputs: dict[str, claripy.ast.BV],
    channel: int,
    decreasing: bool,
) -> list[PitchSlideEndpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(symbol)
    assert function is not None
    offsets = {
        "flags1": 8,
        "frequency_steps": 16,
        "frequency_steps_fractional": 24,
        "current_frequency_fractional": 32,
        "current_frequency_high": 40,
        "current_frequency_low": 48,
        "target_frequency_high": 56,
        "target_frequency_low": 64,
    }
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    for name, offset in offsets.items():
        state.memory.store(NATIVE_STATE + offset, inputs[name])
    selected_flags = inputs["flags1"].get_byte(channel)
    if decreasing:
        state.solver.add((selected_flags & 0x20) != 0)
    else:
        state.solver.add((selected_flags & 0x20) == 0)
    state.memory.store(NATIVE_STATE + 72, inputs["hardware_registers"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        PitchSlideEndpoint(
            **native_registers(end, NATIVE_STATE),
            **{
                name: end.memory.load(NATIVE_STATE + offset, 8)
                for name, offset in offsets.items()
            },
            hardware_registers=end.memory.load(NATIVE_STATE + 72, 8),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@lru_cache(maxsize=None)
def _init_pitch_slide_assembly_project(symbol: str) -> tuple[angr.Project, int]:
    location = symbol_location(SYMBOLS, symbol)
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
    for offset in (3, 8, 13, 18, 28, 37, 47, 55, 60, 65, 75, 84, 90, 113, 118, 123):
        project.hook(
            location.address + offset,
            Sm83AddHlRegisterPair("bc", location.address + offset + 1),
            length=1,
        )
    for offset in (19, 30, 38):
        project.hook(
            location.address + offset,
            Sm83SubAtHl(location.address + offset + 1),
            length=1,
        )
    project.hook(
        location.address + 33,
        Sm83SbcRegister("b", location.address + 34),
        length=1,
    )
    project.hook(
        location.address + 48,
        Sm83SetAtHl(5, location.address + 50),
        length=2,
    )
    project.hook(
        location.address + 67,
        Sm83SubRegister("e", location.address + 68),
        length=1,
    )
    project.hook(
        location.address + 70,
        Sm83SbcRegister("b", location.address + 71),
        length=1,
    )
    project.hook(
        location.address + 77,
        Sm83SubRegister("d", location.address + 78),
        length=1,
    )
    project.hook(
        location.address + 85,
        Sm83ResAtHl(5, location.address + 87),
        length=2,
    )
    project.hook(
        location.address + 91,
        PitchSlideDivideLoopSummary(location.address + 105),
        length=1,
    )
    project.hook(
        location.address + 106,
        Sm83AddAtHl(location.address + 107),
        length=1,
    )
    return project, location.address


def _init_pitch_slide_addresses() -> dict[str, int]:
    return {
        "flags1": symbol_location(SYMBOLS, "wChannelFlags1").address,
        "note_delays": symbol_location(SYMBOLS, "wChannelNoteDelayCounters").address,
        "length_modifiers": symbol_location(
            SYMBOLS, "wChannelPitchSlideLengthModifiers"
        ).address,
        "frequency_steps": symbol_location(
            SYMBOLS, "wChannelPitchSlideFrequencySteps"
        ).address,
        "frequency_steps_fractional": symbol_location(
            SYMBOLS, "wChannelPitchSlideFrequencyStepsFractionalPart"
        ).address,
        "current_frequency_fractional": symbol_location(
            SYMBOLS, "wChannelPitchSlideCurrentFrequencyFractionalPart"
        ).address,
        "current_frequency_high": symbol_location(
            SYMBOLS, "wChannelPitchSlideCurrentFrequencyHighBytes"
        ).address,
        "current_frequency_low": symbol_location(
            SYMBOLS, "wChannelPitchSlideCurrentFrequencyLowBytes"
        ).address,
        "target_frequency_high": symbol_location(
            SYMBOLS, "wChannelPitchSlideTargetFrequencyHighBytes"
        ).address,
        "target_frequency_low": symbol_location(
            SYMBOLS, "wChannelPitchSlideTargetFrequencyLowBytes"
        ).address,
    }


def _init_pitch_slide_assembly(
    symbol: str, inputs: dict[str, claripy.ast.BV], channel: int
) -> list[InitPitchSlideEndpoint]:
    project, address = _init_pitch_slide_assembly_project(symbol)
    addresses = _init_pitch_slide_addresses()
    state = project.factory.blank_state(addr=address)
    set_assembly_registers(state, inputs)
    for name, memory_address in addresses.items():
        state.memory.store(memory_address, inputs[name])
    target_high = state.memory.load(addresses["target_frequency_high"] + channel, 1)
    note_delay = state.memory.load(addresses["note_delays"] + channel, 1)
    length_modifier = state.memory.load(addresses["length_modifiers"] + channel, 1)
    state.solver.add(inputs["d"].ULE(7))
    state.solver.add(target_high.ULE(7))
    state.solver.add(note_delay != length_modifier)
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    return [
        InitPitchSlideEndpoint(
            **assembly_registers(end),
            **{
                name: end.memory.load(memory_address, 8)
                for name, memory_address in addresses.items()
            },
            constraints=tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, GB_RETURN)
    ]


def _init_pitch_slide_native(
    symbol: str, inputs: dict[str, claripy.ast.BV], channel: int
) -> list[InitPitchSlideEndpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(symbol)
    assert function is not None
    offsets = {
        "flags1": 8,
        "note_delays": 16,
        "length_modifiers": 24,
        "frequency_steps": 32,
        "frequency_steps_fractional": 40,
        "current_frequency_fractional": 48,
        "current_frequency_high": 56,
        "current_frequency_low": 64,
        "target_frequency_high": 72,
        "target_frequency_low": 80,
    }
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    for name, offset in offsets.items():
        state.memory.store(NATIVE_STATE + offset, inputs[name])
    target_high = inputs["target_frequency_high"].get_byte(channel)
    note_delay = inputs["note_delays"].get_byte(channel)
    length_modifier = inputs["length_modifiers"].get_byte(channel)
    state.solver.add(inputs["d"].ULE(7))
    state.solver.add(target_high.ULE(7))
    state.solver.add(note_delay != length_modifier)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        InitPitchSlideEndpoint(
            **native_registers(end, NATIVE_STATE),
            **{
                name: end.memory.load(NATIVE_STATE + offset, 8)
                for name, offset in offsets.items()
            },
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


def _handler_boundaries(
    project: angr.Project, state: angr.SimState, boundaries: set[int]
) -> list[angr.SimState]:
    manager = project.factory.simulation_manager(state)
    manager.explore(find=lambda candidate: candidate.addr in boundaries, num_find=len(boundaries))
    assert not manager.errored
    assert len(manager.found) == len(boundaries)
    return list(manager.found)


def _all_handler_boundaries(
    project: angr.Project, state: angr.SimState, boundaries: set[int]
) -> list[angr.SimState]:
    manager = project.factory.simulation_manager(state)
    manager.stashes["found"] = []
    while manager.active:
        manager.move(
            from_stash="active",
            to_stash="found",
            filter_func=lambda candidate: candidate.addr in boundaries,
        )
        if manager.active:
            manager.step()
    assert not manager.errored
    assert {end.addr for end in manager.found} == boundaries
    return list(manager.found)


def _execute_music_assembly(
    symbol: str, inputs: dict[str, claripy.ast.BV]
) -> list[ExecuteMusicEndpoint]:
    location = symbol_location(SYMBOLS, symbol)
    variant = int(symbol[5])
    octave = symbol_location(SYMBOLS, f"Audio{variant}_octave").address
    sound_ret = symbol_location(SYMBOLS, f"Audio{variant}_sound_ret").address
    flags_address = symbol_location(SYMBOLS, "wChannelFlags2").address
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
    project.hook(
        location.address,
        Sm83CpImmediate(0xF8, location.address + 2),
        length=2,
    )
    project.hook(
        location.address + 9,
        Sm83AddHlRegisterPair("bc", location.address + 10),
        length=1,
    )
    project.hook(
        location.address + 10,
        Sm83SetAtHl(0, location.address + 12),
        length=2,
    )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    state.memory.store(flags_address, inputs["flags2"])
    return [
        ExecuteMusicEndpoint(
            **assembly_registers(end),
            flags2=end.memory.load(flags_address, 8),
            continuation=claripy.BVV(1 if end.addr == sound_ret else 2, 8),
            constraints=tuple(end.solver.constraints),
        )
        for end in _handler_boundaries(project, state, {sound_ret, octave})
    ]


def _execute_music_native(
    symbol: str, inputs: dict[str, claripy.ast.BV]
) -> list[ExecuteMusicEndpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["flags2"])
    state.memory.store(NATIVE_STATE + 16, inputs["continuation"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        ExecuteMusicEndpoint(
            **native_registers(end, NATIVE_STATE),
            flags2=end.memory.load(NATIVE_STATE + 8, 8),
            continuation=end.memory.load(NATIVE_STATE + 16, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


def _octave_assembly(
    symbol: str, inputs: dict[str, claripy.ast.BV]
) -> list[OctaveEndpoint]:
    location = symbol_location(SYMBOLS, symbol)
    variant = int(symbol[5])
    sfx_note = symbol_location(SYMBOLS, f"Audio{variant}_sfx_note").address
    sound_ret = symbol_location(SYMBOLS, f"Audio{variant}_sound_ret").address
    octaves_address = symbol_location(SYMBOLS, "wChannelOctaves").address
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
    project.hook(
        location.address + 2,
        Sm83CpImmediate(0xE0, location.address + 4),
        length=2,
    )
    project.hook(
        location.address + 11,
        Sm83AddHlRegisterPair("bc", location.address + 12),
        length=1,
    )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    state.memory.store(octaves_address, inputs["octaves"])
    return [
        OctaveEndpoint(
            **assembly_registers(end),
            octaves=end.memory.load(octaves_address, 8),
            continuation=claripy.BVV(1 if end.addr == sound_ret else 3, 8),
            constraints=tuple(end.solver.constraints),
        )
        for end in _handler_boundaries(project, state, {sound_ret, sfx_note})
    ]


def _octave_native(
    symbol: str, inputs: dict[str, claripy.ast.BV]
) -> list[OctaveEndpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["octaves"])
    state.memory.store(NATIVE_STATE + 16, inputs["continuation"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        OctaveEndpoint(
            **native_registers(end, NATIVE_STATE),
            octaves=end.memory.load(NATIVE_STATE + 8, 8),
            continuation=end.memory.load(NATIVE_STATE + 16, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


def _hook_get_next_music_byte(
    project: angr.Project, callee_address: int, *, sequential: bool = False
) -> None:
    project.hook(
        callee_address + 3,
        Sm83AddRegister("a", callee_address + 4),
        length=1,
    )
    project.hook(
        callee_address + 8,
        Sm83AddHlRegisterPair("de", callee_address + 9),
        length=1,
    )
    project.hook(
        callee_address + 9,
        Sm83LoadAAtHlIncrement(callee_address + 10),
        length=1,
    )
    project.hook(
        callee_address + 11,
        Sm83LoadAAtHlDecrement(callee_address + 12),
        length=1,
    )
    command_load = (
        Sm83LoadSequentialCommandByte(callee_address + 14)
        if sequential
        else Sm83LoadSymbolicCommandByte(callee_address + 14)
    )
    project.hook(callee_address + 13, command_load, length=1)


def _hook_calculate_frequency(
    project: angr.Project, callee_address: int
) -> None:
    project.hook(
        callee_address + 14,
        Sm83CpImmediate(7, callee_address + 16),
        length=2,
    )
    project.hook(
        callee_address + 18,
        Sm83SraRegister("d", callee_address + 20),
        length=2,
    )
    project.hook(
        callee_address + 20,
        Sm83RrRegister("e", callee_address + 22),
        length=2,
    )
    project.hook(
        callee_address + 22,
        Sm83IncRegister("a", callee_address + 23),
        length=1,
    )
    project.hook(
        callee_address + 27,
        Sm83AddRegister("d", callee_address + 28),
        length=1,
    )


def _initialize_command_pointer_state(
    state: angr.SimState,
    inputs: dict[str, claripy.ast.BV],
    channel: int,
) -> int:
    pointer_address = symbol_location(SYMBOLS, "wChannelCommandPointers").address
    state.memory.store(pointer_address, inputs["command_pointers"])
    pointer = claripy.Concat(
        state.memory.load(pointer_address + channel * 2 + 1, 1),
        state.memory.load(pointer_address + channel * 2, 1),
    )
    state.solver.add(pointer.UGE(0x4000), pointer.ULE(0x7FFF))
    state.globals["command_byte"] = inputs["command_byte"]
    return pointer_address


def _duty_command_assembly(
    symbol: str, inputs: dict[str, claripy.ast.BV], channel: int
) -> list[DutyCommandEndpoint]:
    location = symbol_location(SYMBOLS, symbol)
    variant = int(symbol[5])
    tempo = symbol_location(SYMBOLS, f"Audio{variant}_tempo").address
    sound_ret = symbol_location(SYMBOLS, f"Audio{variant}_sound_ret").address
    callee = symbol_location(SYMBOLS, f"Audio{variant}_GetNextMusicByte").address
    duty_address = symbol_location(SYMBOLS, "wChannelDutyCycles").address
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
    project.hook(
        location.address,
        Sm83CpImmediate(0xEC, location.address + 2),
        length=2,
    )
    project.hook(
        location.address + 7,
        Sm83Rrca(location.address + 8),
        length=1,
    )
    project.hook(
        location.address + 8,
        Sm83Rrca(location.address + 9),
        length=1,
    )
    project.hook(
        location.address + 16,
        Sm83AddHlRegisterPair("bc", location.address + 17),
        length=1,
    )
    _hook_get_next_music_byte(project, callee)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    pointer_address = _initialize_command_pointer_state(state, inputs, channel)
    state.memory.store(duty_address, inputs["duty_cycles"])
    return [
        DutyCommandEndpoint(
            **assembly_registers(end),
            command_pointers=end.memory.load(pointer_address, 16),
            command_byte=inputs["command_byte"],
            duty_cycles=end.memory.load(duty_address, 8),
            continuation=claripy.BVV(1 if end.addr == sound_ret else 4, 8),
            constraints=tuple(end.solver.constraints),
        )
        for end in _handler_boundaries(project, state, {sound_ret, tempo})
    ]


def _duty_command_native(
    symbol: str, inputs: dict[str, claripy.ast.BV], channel: int
) -> list[DutyCommandEndpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["command_pointers"])
    state.memory.store(NATIVE_STATE + 24, inputs["command_byte"])
    state.memory.store(NATIVE_STATE + 25, inputs["duty_cycles"])
    state.memory.store(NATIVE_STATE + 33, inputs["continuation"])
    pointer = _next_music_byte_pointer(inputs["command_pointers"], channel)
    state.solver.add(pointer.UGE(0x4000), pointer.ULE(0x7FFF))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        DutyCommandEndpoint(
            **native_registers(end, NATIVE_STATE),
            command_pointers=end.memory.load(NATIVE_STATE + 8, 16),
            command_byte=end.memory.load(NATIVE_STATE + 24, 1),
            duty_cycles=end.memory.load(NATIVE_STATE + 25, 8),
            continuation=end.memory.load(NATIVE_STATE + 33, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


def _byte_command_assembly(
    symbol: str,
    inputs: dict[str, claripy.ast.BV],
    channel: int,
    expected: int,
    next_name: str,
    continuation: int,
) -> list[ByteCommandEndpoint]:
    location = symbol_location(SYMBOLS, symbol)
    variant = int(symbol[5])
    fallthrough = symbol_location(SYMBOLS, f"Audio{variant}_{next_name}").address
    sound_ret = symbol_location(SYMBOLS, f"Audio{variant}_sound_ret").address
    callee = symbol_location(SYMBOLS, f"Audio{variant}_GetNextMusicByte").address
    value_address = (
        symbol_location(SYMBOLS, "wStereoPanning").address
        if expected == 0xEE
        else 0xFF24
    )
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
    project.hook(
        location.address,
        Sm83CpImmediate(expected, location.address + 2),
        length=2,
    )
    if expected == 0xEE:
        project.hook(
            location.address + 7,
            Sm83StoreAImmediate(value_address, location.address + 10),
            length=3,
        )
    else:
        project.hook(
            location.address + 7,
            Sm83StoreAHighImmediate(0x24, location.address + 9),
            length=2,
        )
    _hook_get_next_music_byte(project, callee)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    pointer_address = _initialize_command_pointer_state(state, inputs, channel)
    state.memory.store(value_address, inputs["value"])
    return [
        ByteCommandEndpoint(
            **assembly_registers(end),
            command_pointers=end.memory.load(pointer_address, 16),
            command_byte=inputs["command_byte"],
            value=end.memory.load(value_address, 1),
            continuation=claripy.BVV(
                1 if end.addr == sound_ret else continuation, 8
            ),
            constraints=tuple(end.solver.constraints),
        )
        for end in _handler_boundaries(project, state, {sound_ret, fallthrough})
    ]


def _byte_command_native(
    symbol: str, inputs: dict[str, claripy.ast.BV], channel: int
) -> list[ByteCommandEndpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["command_pointers"])
    state.memory.store(NATIVE_STATE + 24, inputs["command_byte"])
    state.memory.store(NATIVE_STATE + 25, inputs["value"])
    state.memory.store(NATIVE_STATE + 26, inputs["continuation"])
    pointer = _next_music_byte_pointer(inputs["command_pointers"], channel)
    state.solver.add(pointer.UGE(0x4000), pointer.ULE(0x7FFF))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        ByteCommandEndpoint(
            **native_registers(end, NATIVE_STATE),
            command_pointers=end.memory.load(NATIVE_STATE + 8, 16),
            command_byte=end.memory.load(NATIVE_STATE + 24, 1),
            value=end.memory.load(NATIVE_STATE + 25, 1),
            continuation=end.memory.load(NATIVE_STATE + 26, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


def _duty_pattern_command_assembly(
    symbol: str, inputs: dict[str, claripy.ast.BV], channel: int
) -> list[DutyPatternCommandEndpoint]:
    location = symbol_location(SYMBOLS, symbol)
    variant = int(symbol[5])
    volume = symbol_location(SYMBOLS, f"Audio{variant}_volume").address
    sound_ret = symbol_location(SYMBOLS, f"Audio{variant}_sound_ret").address
    callee = symbol_location(SYMBOLS, f"Audio{variant}_GetNextMusicByte").address
    patterns_address = symbol_location(SYMBOLS, "wChannelDutyCyclePatterns").address
    duty_address = symbol_location(SYMBOLS, "wChannelDutyCycles").address
    flags_address = symbol_location(SYMBOLS, "wChannelFlags1").address
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
    project.hook(
        location.address,
        Sm83CpImmediate(0xFC, location.address + 2),
        length=2,
    )
    for offset in (12, 19, 24):
        project.hook(
            location.address + offset,
            Sm83AddHlRegisterPair("bc", location.address + offset + 1),
            length=1,
        )
    project.hook(
        location.address + 25,
        Sm83SetAtHl(6, location.address + 27),
        length=2,
    )
    _hook_get_next_music_byte(project, callee)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    pointer_address = _initialize_command_pointer_state(state, inputs, channel)
    state.memory.store(patterns_address, inputs["duty_patterns"])
    state.memory.store(duty_address, inputs["duty_cycles"])
    state.memory.store(flags_address, inputs["flags1"])
    return [
        DutyPatternCommandEndpoint(
            **assembly_registers(end),
            command_pointers=end.memory.load(pointer_address, 16),
            command_byte=inputs["command_byte"],
            duty_patterns=end.memory.load(patterns_address, 8),
            duty_cycles=end.memory.load(duty_address, 8),
            flags1=end.memory.load(flags_address, 8),
            continuation=claripy.BVV(1 if end.addr == sound_ret else 7, 8),
            constraints=tuple(end.solver.constraints),
        )
        for end in _handler_boundaries(project, state, {sound_ret, volume})
    ]


def _duty_pattern_command_native(
    symbol: str, inputs: dict[str, claripy.ast.BV], channel: int
) -> list[DutyPatternCommandEndpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["command_pointers"])
    state.memory.store(NATIVE_STATE + 24, inputs["command_byte"])
    state.memory.store(NATIVE_STATE + 25, inputs["duty_patterns"])
    state.memory.store(NATIVE_STATE + 33, inputs["duty_cycles"])
    state.memory.store(NATIVE_STATE + 41, inputs["flags1"])
    state.memory.store(NATIVE_STATE + 49, inputs["continuation"])
    pointer = _next_music_byte_pointer(inputs["command_pointers"], channel)
    state.solver.add(pointer.UGE(0x4000), pointer.ULE(0x7FFF))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        DutyPatternCommandEndpoint(
            **native_registers(end, NATIVE_STATE),
            command_pointers=end.memory.load(NATIVE_STATE + 8, 16),
            command_byte=end.memory.load(NATIVE_STATE + 24, 1),
            duty_patterns=end.memory.load(NATIVE_STATE + 25, 8),
            duty_cycles=end.memory.load(NATIVE_STATE + 33, 8),
            flags1=end.memory.load(NATIVE_STATE + 41, 8),
            continuation=end.memory.load(NATIVE_STATE + 49, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


def _tempo_command_assembly(
    symbol: str, inputs: dict[str, claripy.ast.BV], channel: int
) -> list[TempoCommandEndpoint]:
    location = symbol_location(SYMBOLS, symbol)
    variant = int(symbol[5])
    stereo = symbol_location(SYMBOLS, f"Audio{variant}_stereo_panning").address
    sound_ret = symbol_location(SYMBOLS, f"Audio{variant}_sound_ret").address
    callee = symbol_location(SYMBOLS, f"Audio{variant}_GetNextMusicByte").address
    music_tempo_address = symbol_location(SYMBOLS, "wMusicTempo").address
    sfx_tempo_address = symbol_location(SYMBOLS, "wSfxTempo").address
    fractional_address = symbol_location(
        SYMBOLS, "wChannelNoteDelayCountersFractionalPart"
    ).address
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
    project.hook(
        location.address,
        Sm83CpImmediate(0xED, location.address + 2),
        length=2,
    )
    project.hook(
        location.address + 5,
        Sm83CpImmediate(4, location.address + 7),
        length=2,
    )
    stores = {
        12: music_tempo_address,
        18: music_tempo_address + 1,
        22: fractional_address,
        25: fractional_address + 1,
        28: fractional_address + 2,
        31: fractional_address + 3,
        39: sfx_tempo_address,
        45: sfx_tempo_address + 1,
        49: fractional_address + 4,
        52: fractional_address + 5,
        55: fractional_address + 6,
        58: fractional_address + 7,
    }
    for offset, address in stores.items():
        project.hook(
            location.address + offset,
            Sm83StoreAImmediate(address, location.address + offset + 3),
            length=3,
        )
    _hook_get_next_music_byte(project, callee, sequential=True)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    pointer_address = _initialize_command_pointer_state(state, inputs, channel)
    pointer = _next_music_byte_pointer(inputs["command_pointers"], channel)
    state.solver.add(pointer.ULE(0x7FFE))
    state.globals["command_bytes"] = (
        inputs["command_bytes"].get_byte(0),
        inputs["command_bytes"].get_byte(1),
    )
    state.globals["command_byte_index"] = 0
    state.memory.store(music_tempo_address, inputs["music_tempo"])
    state.memory.store(sfx_tempo_address, inputs["sfx_tempo"])
    state.memory.store(fractional_address, inputs["fractional_note_delays"])
    return [
        TempoCommandEndpoint(
            **assembly_registers(end),
            command_pointers=end.memory.load(pointer_address, 16),
            command_bytes=inputs["command_bytes"],
            music_tempo=end.memory.load(music_tempo_address, 2),
            sfx_tempo=end.memory.load(sfx_tempo_address, 2),
            fractional_note_delays=end.memory.load(fractional_address, 8),
            continuation=claripy.BVV(1 if end.addr == sound_ret else 9, 8),
            constraints=tuple(end.solver.constraints),
        )
        for end in _handler_boundaries(project, state, {sound_ret, stereo})
    ]


def _tempo_command_native(
    symbol: str, inputs: dict[str, claripy.ast.BV], channel: int
) -> list[TempoCommandEndpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["command_pointers"])
    state.memory.store(NATIVE_STATE + 24, inputs["command_bytes"])
    state.memory.store(NATIVE_STATE + 26, inputs["music_tempo"])
    state.memory.store(NATIVE_STATE + 28, inputs["sfx_tempo"])
    state.memory.store(NATIVE_STATE + 30, inputs["fractional_note_delays"])
    state.memory.store(NATIVE_STATE + 38, inputs["continuation"])
    pointer = _next_music_byte_pointer(inputs["command_pointers"], channel)
    state.solver.add(pointer.UGE(0x4000), pointer.ULE(0x7FFE))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        TempoCommandEndpoint(
            **native_registers(end, NATIVE_STATE),
            command_pointers=end.memory.load(NATIVE_STATE + 8, 16),
            command_bytes=end.memory.load(NATIVE_STATE + 24, 2),
            music_tempo=end.memory.load(NATIVE_STATE + 26, 2),
            sfx_tempo=end.memory.load(NATIVE_STATE + 28, 2),
            fractional_note_delays=end.memory.load(NATIVE_STATE + 30, 8),
            continuation=end.memory.load(NATIVE_STATE + 38, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


def _toggle_perfect_pitch_assembly(
    symbol: str, inputs: dict[str, claripy.ast.BV]
) -> list[TogglePerfectPitchEndpoint]:
    location = symbol_location(SYMBOLS, symbol)
    variant = int(symbol[5])
    vibrato = symbol_location(SYMBOLS, f"Audio{variant}_vibrato").address
    sound_ret = symbol_location(SYMBOLS, f"Audio{variant}_sound_ret").address
    flags_address = symbol_location(SYMBOLS, "wChannelFlags1").address
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
    project.hook(
        location.address + 1,
        Sm83CpImmediate(0xE8, location.address + 3),
        length=2,
    )
    project.hook(
        location.address + 10,
        Sm83AddHlRegisterPair("bc", location.address + 11),
        length=1,
    )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    state.memory.store(flags_address, inputs["flags1"])
    return [
        TogglePerfectPitchEndpoint(
            **assembly_registers(end),
            flags1=end.memory.load(flags_address, 8),
            continuation=claripy.BVV(1 if end.addr == sound_ret else 8, 8),
            constraints=tuple(end.solver.constraints),
        )
        for end in _handler_boundaries(project, state, {sound_ret, vibrato})
    ]


def _toggle_perfect_pitch_native(
    symbol: str, inputs: dict[str, claripy.ast.BV]
) -> list[TogglePerfectPitchEndpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["flags1"])
    state.memory.store(NATIVE_STATE + 16, inputs["continuation"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        TogglePerfectPitchEndpoint(
            **native_registers(end, NATIVE_STATE),
            flags1=end.memory.load(NATIVE_STATE + 8, 8),
            continuation=end.memory.load(NATIVE_STATE + 16, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


def _vibrato_command_assembly(
    symbol: str, inputs: dict[str, claripy.ast.BV], channel: int
) -> list[VibratoCommandEndpoint]:
    location = symbol_location(SYMBOLS, symbol)
    variant = int(symbol[5])
    pitch_slide = symbol_location(SYMBOLS, f"Audio{variant}_pitch_slide").address
    sound_ret = symbol_location(SYMBOLS, f"Audio{variant}_sound_ret").address
    callee = symbol_location(SYMBOLS, f"Audio{variant}_GetNextMusicByte").address
    delay_address = symbol_location(SYMBOLS, "wChannelVibratoDelayCounters").address
    reload_address = symbol_location(
        SYMBOLS, "wChannelVibratoDelayCounterReloadValues"
    ).address
    extents_address = symbol_location(SYMBOLS, "wChannelVibratoExtents").address
    rates_address = symbol_location(SYMBOLS, "wChannelVibratoRates").address
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
    project.hook(
        location.address,
        Sm83CpImmediate(0xEA, location.address + 2),
        length=2,
    )
    for offset in (12, 17, 32, 48):
        project.hook(
            location.address + offset,
            Sm83AddHlRegisterPair("bc", location.address + offset + 1),
            length=1,
        )
    project.hook(
        location.address + 33,
        Sm83SrlRegister("a", location.address + 35),
        length=2,
    )
    project.hook(
        location.address + 36,
        Sm83AdcRegister("b", location.address + 37),
        length=1,
    )
    for offset in (25, 37, 49):
        project.hook(
            location.address + offset,
            Sm83SwapRegister("a", location.address + offset + 2),
            length=2,
        )
    _hook_get_next_music_byte(project, callee, sequential=True)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    pointer_address = _initialize_command_pointer_state(state, inputs, channel)
    pointer = _next_music_byte_pointer(inputs["command_pointers"], channel)
    state.solver.add(pointer.ULE(0x7FFE))
    state.globals["command_bytes"] = (
        inputs["command_bytes"].get_byte(0),
        inputs["command_bytes"].get_byte(1),
    )
    state.globals["command_byte_index"] = 0
    state.memory.store(delay_address, inputs["delay_counters"])
    state.memory.store(reload_address, inputs["delay_reloads"])
    state.memory.store(extents_address, inputs["extents"])
    state.memory.store(rates_address, inputs["rates"])
    return [
        VibratoCommandEndpoint(
            **assembly_registers(end),
            command_pointers=end.memory.load(pointer_address, 16),
            command_bytes=inputs["command_bytes"],
            delay_counters=end.memory.load(delay_address, 8),
            delay_reloads=end.memory.load(reload_address, 8),
            extents=end.memory.load(extents_address, 8),
            rates=end.memory.load(rates_address, 8),
            continuation=claripy.BVV(1 if end.addr == sound_ret else 10, 8),
            constraints=tuple(end.solver.constraints),
        )
        for end in _handler_boundaries(project, state, {sound_ret, pitch_slide})
    ]


def _vibrato_command_native(
    symbol: str, inputs: dict[str, claripy.ast.BV], channel: int
) -> list[VibratoCommandEndpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["command_pointers"])
    state.memory.store(NATIVE_STATE + 24, inputs["command_bytes"])
    state.memory.store(NATIVE_STATE + 26, inputs["delay_counters"])
    state.memory.store(NATIVE_STATE + 34, inputs["delay_reloads"])
    state.memory.store(NATIVE_STATE + 42, inputs["extents"])
    state.memory.store(NATIVE_STATE + 50, inputs["rates"])
    state.memory.store(NATIVE_STATE + 58, inputs["continuation"])
    pointer = _next_music_byte_pointer(inputs["command_pointers"], channel)
    state.solver.add(pointer.UGE(0x4000), pointer.ULE(0x7FFE))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        VibratoCommandEndpoint(
            **native_registers(end, NATIVE_STATE),
            command_pointers=end.memory.load(NATIVE_STATE + 8, 16),
            command_bytes=end.memory.load(NATIVE_STATE + 24, 2),
            delay_counters=end.memory.load(NATIVE_STATE + 26, 8),
            delay_reloads=end.memory.load(NATIVE_STATE + 34, 8),
            extents=end.memory.load(NATIVE_STATE + 42, 8),
            rates=end.memory.load(NATIVE_STATE + 50, 8),
            continuation=end.memory.load(NATIVE_STATE + 58, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


def _pitch_sweep_assembly(
    symbol: str, inputs: dict[str, claripy.ast.BV], channel: int
) -> list[PitchSweepEndpoint]:
    location = symbol_location(SYMBOLS, symbol)
    variant = int(symbol[5])
    note = symbol_location(SYMBOLS, f"Audio{variant}_note").address
    sound_ret = symbol_location(SYMBOLS, f"Audio{variant}_sound_ret").address
    callee = symbol_location(SYMBOLS, f"Audio{variant}_GetNextMusicByte").address
    flags_address = symbol_location(SYMBOLS, "wChannelFlags2").address
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
    project.hook(
        location.address + 1,
        Sm83CpImmediate(4, location.address + 3),
        length=2,
    )
    project.hook(
        location.address + 6,
        Sm83CpImmediate(0x10, location.address + 8),
        length=2,
    )
    project.hook(
        location.address + 15,
        Sm83AddHlRegisterPair("bc", location.address + 16),
        length=1,
    )
    project.hook(
        location.address + 16,
        Sm83BitAtHl(0, location.address + 18),
        length=2,
    )
    project.hook(
        location.address + 23,
        Sm83StoreAHighImmediate(0x10, location.address + 25),
        length=2,
    )
    _hook_get_next_music_byte(project, callee)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    pointer_address = _initialize_command_pointer_state(state, inputs, channel)
    state.memory.store(flags_address, inputs["flags2"])
    state.memory.store(0xFF10, inputs["sweep"])
    boundaries = {note} if channel < 4 else {sound_ret, note}
    return [
        PitchSweepEndpoint(
            **assembly_registers(end),
            command_pointers=end.memory.load(pointer_address, 16),
            command_byte=inputs["command_byte"],
            flags2=end.memory.load(flags_address, 8),
            sweep=end.memory.load(0xFF10, 1),
            continuation=claripy.BVV(1 if end.addr == sound_ret else 11, 8),
            constraints=tuple(end.solver.constraints),
        )
        for end in _all_handler_boundaries(project, state, boundaries)
    ]


def _pitch_sweep_native(
    symbol: str, inputs: dict[str, claripy.ast.BV], channel: int
) -> list[PitchSweepEndpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["command_pointers"])
    state.memory.store(NATIVE_STATE + 24, inputs["command_byte"])
    state.memory.store(NATIVE_STATE + 25, inputs["flags2"])
    state.memory.store(NATIVE_STATE + 33, inputs["sweep"])
    state.memory.store(NATIVE_STATE + 34, inputs["continuation"])
    pointer = _next_music_byte_pointer(inputs["command_pointers"], channel)
    state.solver.add(pointer.UGE(0x4000), pointer.ULE(0x7FFF))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        PitchSweepEndpoint(
            **native_registers(end, NATIVE_STATE),
            command_pointers=end.memory.load(NATIVE_STATE + 8, 16),
            command_byte=end.memory.load(NATIVE_STATE + 24, 1),
            flags2=end.memory.load(NATIVE_STATE + 25, 8),
            sweep=end.memory.load(NATIVE_STATE + 33, 1),
            continuation=end.memory.load(NATIVE_STATE + 34, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


def _pitch_slide_command_assembly(
    symbol: str, inputs: dict[str, claripy.ast.BV], channel: int
) -> list[PitchSlideCommandEndpoint]:
    location = symbol_location(SYMBOLS, symbol)
    variant = int(symbol[5])
    duty_cycle = symbol_location(SYMBOLS, f"Audio{variant}_duty_cycle").address
    note_length = symbol_location(SYMBOLS, f"Audio{variant}_note_length").address
    get_next = symbol_location(SYMBOLS, f"Audio{variant}_GetNextMusicByte").address
    calculate = symbol_location(SYMBOLS, f"Audio{variant}_CalculateFrequency").address
    pointer_address = symbol_location(SYMBOLS, "wChannelCommandPointers").address
    length_address = symbol_location(
        SYMBOLS, "wChannelPitchSlideLengthModifiers"
    ).address
    target_high_address = symbol_location(
        SYMBOLS, "wChannelPitchSlideTargetFrequencyHighBytes"
    ).address
    target_low_address = symbol_location(
        SYMBOLS, "wChannelPitchSlideTargetFrequencyLowBytes"
    ).address
    flags_address = symbol_location(SYMBOLS, "wChannelFlags1").address
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
    project.hook(
        location.address,
        Sm83CpImmediate(0xEB, location.address + 2),
        length=2,
    )
    project.hook(
        location.address + 20,
        Sm83SwapRegister("a", location.address + 22),
        length=2,
    )
    for offset in (12, 34, 39, 46):
        project.hook(
            location.address + offset,
            Sm83AddHlRegisterPair("bc", location.address + offset + 1),
            length=1,
        )
    project.hook(
        location.address + 47,
        Sm83SetAtHl(4, location.address + 49),
        length=2,
    )
    _hook_get_next_music_byte(project, get_next, sequential=True)
    _hook_calculate_frequency(project, calculate)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    state.memory.store(pointer_address, inputs["command_pointers"])
    pointer = _next_music_byte_pointer(inputs["command_pointers"], channel)
    parameter = inputs["command_bytes"].get_byte(1)
    state.solver.add(
        pointer.UGE(0x4000),
        pointer.ULE(0x7FFD),
        claripy.LShR(parameter, 4).ULE(7),
        (parameter & 0x0F).ULE(11),
    )
    state.globals["command_bytes"] = tuple(
        inputs["command_bytes"].get_byte(index) for index in range(3)
    )
    state.globals["command_byte_index"] = 0
    state.memory.store(length_address, inputs["length_modifiers"])
    state.memory.store(target_high_address, inputs["target_frequency_high"])
    state.memory.store(target_low_address, inputs["target_frequency_low"])
    state.memory.store(flags_address, inputs["flags1"])
    return [
        PitchSlideCommandEndpoint(
            **assembly_registers(end),
            command_pointers=end.memory.load(pointer_address, 16),
            command_bytes=inputs["command_bytes"],
            length_modifiers=end.memory.load(length_address, 8),
            target_frequency_high=end.memory.load(target_high_address, 8),
            target_frequency_low=end.memory.load(target_low_address, 8),
            flags1=end.memory.load(flags_address, 8),
            continuation=claripy.BVV(
                13 if end.addr == note_length else 12, 8
            ),
            constraints=tuple(end.solver.constraints),
        )
        for end in _all_handler_boundaries(
            project, state, {duty_cycle, note_length}
        )
    ]


def _pitch_slide_command_native(
    symbol: str, inputs: dict[str, claripy.ast.BV], channel: int
) -> list[PitchSlideCommandEndpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["command_pointers"])
    state.memory.store(NATIVE_STATE + 24, inputs["command_bytes"])
    state.memory.store(NATIVE_STATE + 27, inputs["length_modifiers"])
    state.memory.store(NATIVE_STATE + 35, inputs["target_frequency_high"])
    state.memory.store(NATIVE_STATE + 43, inputs["target_frequency_low"])
    state.memory.store(NATIVE_STATE + 51, inputs["flags1"])
    state.memory.store(NATIVE_STATE + 59, inputs["continuation"])
    pointer = _next_music_byte_pointer(inputs["command_pointers"], channel)
    parameter = inputs["command_bytes"].get_byte(1)
    state.solver.add(
        pointer.UGE(0x4000),
        pointer.ULE(0x7FFD),
        claripy.LShR(parameter, 4).ULE(7),
        (parameter & 0x0F).ULE(11),
    )
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        PitchSlideCommandEndpoint(
            **native_registers(end, NATIVE_STATE),
            command_pointers=end.memory.load(NATIVE_STATE + 8, 16),
            command_bytes=end.memory.load(NATIVE_STATE + 24, 3),
            length_modifiers=end.memory.load(NATIVE_STATE + 27, 8),
            target_frequency_high=end.memory.load(NATIVE_STATE + 35, 8),
            target_frequency_low=end.memory.load(NATIVE_STATE + 43, 8),
            flags1=end.memory.load(NATIVE_STATE + 51, 8),
            continuation=end.memory.load(NATIVE_STATE + 59, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


def _note_type_assembly(
    symbol: str, inputs: dict[str, claripy.ast.BV], channel: int
) -> list[NoteTypeEndpoint]:
    location = symbol_location(SYMBOLS, symbol)
    variant = int(symbol[5])
    toggle = symbol_location(
        SYMBOLS, f"Audio{variant}_toggle_perfect_pitch"
    ).address
    sound_ret = symbol_location(SYMBOLS, f"Audio{variant}_sound_ret").address
    get_next = symbol_location(SYMBOLS, f"Audio{variant}_GetNextMusicByte").address
    speed_address = symbol_location(SYMBOLS, "wChannelNoteSpeeds").address
    volume_address = symbol_location(SYMBOLS, "wChannelVolumes").address
    music_wave_address = symbol_location(SYMBOLS, "wMusicWaveInstrument").address
    sfx_wave_address = symbol_location(SYMBOLS, "wSfxWaveInstrument").address
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
    for offset, immediate in ((2, 0xD0), (18, 3), (27, 2), (31, 6)):
        project.hook(
            location.address + offset,
            Sm83CpImmediate(immediate, location.address + offset + 2),
            length=2,
        )
    for offset in (15, 58):
        project.hook(
            location.address + offset,
            Sm83AddHlRegisterPair("bc", location.address + offset + 1),
            length=1,
        )
    project.hook(
        location.address + 50,
        Sm83SlaRegister("a", location.address + 52),
        length=2,
    )
    _hook_get_next_music_byte(project, get_next)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    pointer_address = _initialize_command_pointer_state(state, inputs, channel)
    state.memory.store(speed_address, inputs["note_speeds"])
    state.memory.store(volume_address, inputs["volumes"])
    state.memory.store(music_wave_address, inputs["music_wave_instrument"])
    state.memory.store(sfx_wave_address, inputs["sfx_wave_instrument"])
    return [
        NoteTypeEndpoint(
            **assembly_registers(end),
            command_pointers=end.memory.load(pointer_address, 16),
            command_byte=inputs["command_byte"],
            note_speeds=end.memory.load(speed_address, 8),
            volumes=end.memory.load(volume_address, 8),
            music_wave_instrument=end.memory.load(music_wave_address, 1),
            sfx_wave_instrument=end.memory.load(sfx_wave_address, 1),
            continuation=claripy.BVV(1 if end.addr == sound_ret else 14, 8),
            constraints=tuple(end.solver.constraints),
        )
        for end in _handler_boundaries(project, state, {sound_ret, toggle})
    ]


def _note_type_native(
    symbol: str, inputs: dict[str, claripy.ast.BV], channel: int
) -> list[NoteTypeEndpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["command_pointers"])
    state.memory.store(NATIVE_STATE + 24, inputs["command_byte"])
    state.memory.store(NATIVE_STATE + 25, inputs["note_speeds"])
    state.memory.store(NATIVE_STATE + 33, inputs["volumes"])
    state.memory.store(NATIVE_STATE + 41, inputs["music_wave_instrument"])
    state.memory.store(NATIVE_STATE + 42, inputs["sfx_wave_instrument"])
    state.memory.store(NATIVE_STATE + 43, inputs["continuation"])
    pointer = _next_music_byte_pointer(inputs["command_pointers"], channel)
    state.solver.add(pointer.UGE(0x4000), pointer.ULE(0x7FFF))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        NoteTypeEndpoint(
            **native_registers(end, NATIVE_STATE),
            command_pointers=end.memory.load(NATIVE_STATE + 8, 16),
            command_byte=end.memory.load(NATIVE_STATE + 24, 1),
            note_speeds=end.memory.load(NATIVE_STATE + 25, 8),
            volumes=end.memory.load(NATIVE_STATE + 33, 8),
            music_wave_instrument=end.memory.load(NATIVE_STATE + 41, 1),
            sfx_wave_instrument=end.memory.load(NATIVE_STATE + 42, 1),
            continuation=end.memory.load(NATIVE_STATE + 43, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


def _sound_call_assembly(
    symbol: str, inputs: dict[str, claripy.ast.BV], channel: int
) -> list[SoundCallEndpoint]:
    location = symbol_location(SYMBOLS, symbol)
    variant = int(symbol[5])
    sound_loop = symbol_location(SYMBOLS, f"Audio{variant}_sound_loop").address
    sound_ret = symbol_location(SYMBOLS, f"Audio{variant}_sound_ret").address
    get_next = symbol_location(SYMBOLS, f"Audio{variant}_GetNextMusicByte").address
    pointer_address = symbol_location(SYMBOLS, "wChannelCommandPointers").address
    return_address = symbol_location(SYMBOLS, "wChannelReturnAddresses").address
    flags_address = symbol_location(SYMBOLS, "wChannelFlags1").address
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
    project.hook(
        location.address,
        Sm83CpImmediate(0xFD, location.address + 2),
        length=2,
    )
    project.hook(
        location.address + 19,
        Sm83AddRegister("a", location.address + 20),
        length=1,
    )
    for offset, pair in ((24, "de"), (29, "de"), (47, "bc")):
        project.hook(
            location.address + offset,
            Sm83AddHlRegisterPair(pair, location.address + offset + 1),
            length=1,
        )
    project.hook(
        location.address + 33,
        Sm83LoadAAtHlIncrement(location.address + 34),
        length=1,
    )
    project.hook(
        location.address + 36,
        Sm83LoadAAtHlDecrement(location.address + 37),
        length=1,
    )
    project.hook(
        location.address + 48,
        Sm83SetAtHl(1, location.address + 50),
        length=2,
    )
    _hook_get_next_music_byte(project, get_next, sequential=True)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    state.memory.store(pointer_address, inputs["command_pointers"])
    pointer = _next_music_byte_pointer(inputs["command_pointers"], channel)
    state.solver.add(pointer.UGE(0x4000), pointer.ULE(0x7FFE))
    state.globals["command_bytes"] = (
        inputs["command_bytes"].get_byte(0),
        inputs["command_bytes"].get_byte(1),
    )
    state.globals["command_byte_index"] = 0
    state.memory.store(return_address, inputs["return_addresses"])
    state.memory.store(flags_address, inputs["flags1"])
    return [
        SoundCallEndpoint(
            **assembly_registers(end),
            command_pointers=end.memory.load(pointer_address, 16),
            command_bytes=inputs["command_bytes"],
            return_addresses=end.memory.load(return_address, 16),
            flags1=end.memory.load(flags_address, 8),
            continuation=claripy.BVV(1 if end.addr == sound_ret else 15, 8),
            constraints=tuple(end.solver.constraints),
        )
        for end in _handler_boundaries(project, state, {sound_ret, sound_loop})
    ]


def _sound_call_native(
    symbol: str, inputs: dict[str, claripy.ast.BV], channel: int
) -> list[SoundCallEndpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["command_pointers"])
    state.memory.store(NATIVE_STATE + 24, inputs["command_bytes"])
    state.memory.store(NATIVE_STATE + 26, inputs["return_addresses"])
    state.memory.store(NATIVE_STATE + 42, inputs["flags1"])
    state.memory.store(NATIVE_STATE + 50, inputs["continuation"])
    pointer = _next_music_byte_pointer(inputs["command_pointers"], channel)
    state.solver.add(pointer.UGE(0x4000), pointer.ULE(0x7FFE))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        SoundCallEndpoint(
            **native_registers(end, NATIVE_STATE),
            command_pointers=end.memory.load(NATIVE_STATE + 8, 16),
            command_bytes=end.memory.load(NATIVE_STATE + 24, 2),
            return_addresses=end.memory.load(NATIVE_STATE + 26, 16),
            flags1=end.memory.load(NATIVE_STATE + 42, 8),
            continuation=end.memory.load(NATIVE_STATE + 50, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


def _sound_loop_assembly(
    symbol: str, inputs: dict[str, claripy.ast.BV], channel: int
) -> list[SoundLoopEndpoint]:
    location = symbol_location(SYMBOLS, symbol)
    variant = int(symbol[5])
    note_type = symbol_location(SYMBOLS, f"Audio{variant}_note_type").address
    sound_ret = symbol_location(SYMBOLS, f"Audio{variant}_sound_ret").address
    get_next = symbol_location(SYMBOLS, f"Audio{variant}_GetNextMusicByte").address
    pointer_address = symbol_location(SYMBOLS, "wChannelCommandPointers").address
    counters_address = symbol_location(SYMBOLS, "wChannelLoopCounters").address
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
    project.hook(
        location.address,
        Sm83CpImmediate(0xFE, location.address + 2),
        length=2,
    )
    project.hook(
        location.address + 17,
        Sm83AddHlRegisterPair("bc", location.address + 18),
        length=1,
    )
    project.hook(
        location.address + 19,
        Sm83CpRegister("e", location.address + 20),
        length=1,
    )
    project.hook(
        location.address + 34,
        Sm83IncRegister("a", location.address + 35),
        length=1,
    )
    project.hook(
        location.address + 47,
        Sm83AddRegister("a", location.address + 48),
        length=1,
    )
    project.hook(
        location.address + 52,
        Sm83AddHlRegisterPair("de", location.address + 53),
        length=1,
    )
    project.hook(
        location.address + 54,
        Sm83StoreAAtHlIncrement(location.address + 55),
        length=1,
    )
    _hook_get_next_music_byte(project, get_next, sequential=True)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    state.memory.store(pointer_address, inputs["command_pointers"])
    pointer = _next_music_byte_pointer(inputs["command_pointers"], channel)
    state.solver.add(pointer.UGE(0x4000), pointer.ULE(0x7FFD))
    state.globals["command_bytes"] = tuple(
        inputs["command_bytes"].get_byte(index) for index in range(3)
    )
    state.globals["command_byte_index"] = 0
    state.memory.store(counters_address, inputs["loop_counters"])
    return [
        SoundLoopEndpoint(
            **assembly_registers(end),
            command_pointers=end.memory.load(pointer_address, 16),
            command_bytes=inputs["command_bytes"],
            loop_counters=end.memory.load(counters_address, 8),
            continuation=claripy.BVV(1 if end.addr == sound_ret else 16, 8),
            constraints=tuple(end.solver.constraints),
        )
        for end in _all_handler_boundaries(project, state, {sound_ret, note_type})
    ]


def _sound_loop_native(
    symbol: str, inputs: dict[str, claripy.ast.BV], channel: int
) -> list[SoundLoopEndpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["command_pointers"])
    state.memory.store(NATIVE_STATE + 24, inputs["command_bytes"])
    state.memory.store(NATIVE_STATE + 27, inputs["loop_counters"])
    state.memory.store(NATIVE_STATE + 35, inputs["continuation"])
    pointer = _next_music_byte_pointer(inputs["command_pointers"], channel)
    state.solver.add(pointer.UGE(0x4000), pointer.ULE(0x7FFD))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        SoundLoopEndpoint(
            **native_registers(end, NATIVE_STATE),
            command_pointers=end.memory.load(NATIVE_STATE + 8, 16),
            command_bytes=end.memory.load(NATIVE_STATE + 24, 3),
            loop_counters=end.memory.load(NATIVE_STATE + 27, 8),
            continuation=end.memory.load(NATIVE_STATE + 35, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


def _note_length_assembly(
    symbol: str, inputs: dict[str, claripy.ast.BV], channel: int
) -> list[NoteLengthEndpoint]:
    location = symbol_location(SYMBOLS, symbol)
    variant = int(symbol[5])
    note_pitch = symbol_location(SYMBOLS, f"Audio{variant}_note_pitch").address
    speed_address = symbol_location(SYMBOLS, "wChannelNoteSpeeds").address
    music_tempo_address = symbol_location(SYMBOLS, "wMusicTempo").address
    sfx_tempo_address = symbol_location(SYMBOLS, "wSfxTempo").address
    fractional_address = symbol_location(
        SYMBOLS, "wChannelNoteDelayCountersFractionalPart"
    ).address
    delay_address = symbol_location(SYMBOLS, "wChannelNoteDelayCounters").address
    flags2_address = symbol_location(SYMBOLS, "wChannelFlags2").address
    flags1_address = symbol_location(SYMBOLS, "wChannelFlags1").address
    sound_address = symbol_location(SYMBOLS, "wChannelSoundIDs").address
    modifier_address = symbol_location(SYMBOLS, "wTempoModifier").address
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
    project.hook(location.address + 1, Sm83PushAf(location.address + 2), length=1)
    project.hook(
        location.address + 4,
        Sm83IncRegister("a", location.address + 5),
        length=1,
    )
    for offset in (12, 58, 68, 74, 79, 87):
        project.hook(
            location.address + offset,
            Sm83AddHlRegisterPair("bc", location.address + offset + 1),
            length=1,
        )
    project.hook(
        location.address + 19,
        Sm83CpImmediate(4, location.address + 21),
        length=2,
    )
    project.hook(
        location.address + 23,
        Sm83LoadAImmediate(music_tempo_address, location.address + 26),
        length=3,
    )
    project.hook(
        location.address + 27,
        Sm83LoadAImmediate(music_tempo_address + 1, location.address + 30),
        length=3,
    )
    project.hook(
        location.address + 37,
        Sm83CpImmediate(7, location.address + 39),
        length=2,
    )
    project.hook(
        location.address + 44,
        Sm83LoadAImmediate(sfx_tempo_address, location.address + 47),
        length=3,
    )
    project.hook(
        location.address + 48,
        Sm83LoadAImmediate(sfx_tempo_address + 1, location.address + 51),
        length=3,
    )
    project.hook(
        location.address + 15,
        NoteLengthMultiplyAddSummary(location.address + 18),
        length=3,
    )
    project.hook(
        location.address + 41,
        NoteLengthSetSfxTempoSummary(
            variant, sfx_tempo_address, location.address + 44
        ),
        length=3,
    )
    project.hook(
        location.address + 60,
        NoteLengthMultiplyAddSummary(location.address + 63),
        length=3,
    )
    project.hook(
        location.address + 80,
        Sm83BitAtHl(0, location.address + 82),
        length=2,
    )
    project.hook(
        location.address + 88,
        Sm83BitAtHl(2, location.address + 90),
        length=2,
    )
    project.hook(location.address + 92, Sm83PopHl(location.address + 93), length=1)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    state.memory.store(speed_address, inputs["note_speeds"])
    state.memory.store(music_tempo_address, inputs["music_tempo"])
    state.memory.store(sfx_tempo_address, inputs["sfx_tempo"])
    state.memory.store(fractional_address, inputs["fractional_note_delays"])
    state.memory.store(delay_address, inputs["note_delays"])
    state.memory.store(flags2_address, inputs["flags2"])
    state.memory.store(flags1_address, inputs["flags1"])
    state.memory.store(sound_address + 4, inputs["sound5"])
    state.memory.store(sound_address + 7, inputs["sound8"])
    state.memory.store(modifier_address, inputs["tempo_modifier"])
    state.globals["note_length_sound5"] = inputs["sound5"]
    state.globals["note_length_sound8"] = inputs["sound8"]
    state.globals["note_length_tempo_modifier"] = inputs["tempo_modifier"]
    return [
        NoteLengthEndpoint(
            **assembly_registers(end),
            note_speeds=end.memory.load(speed_address, 8),
            music_tempo=end.memory.load(music_tempo_address, 2),
            sfx_tempo=end.memory.load(sfx_tempo_address, 2),
            fractional_note_delays=end.memory.load(fractional_address, 8),
            note_delays=end.memory.load(delay_address, 8),
            flags2=end.memory.load(flags2_address, 8),
            flags1=end.memory.load(flags1_address, 8),
            sound5=end.memory.load(sound_address + 4, 1),
            sound8=end.memory.load(sound_address + 7, 1),
            tempo_modifier=end.memory.load(modifier_address, 1),
            saved_a=inputs["d"],
            saved_f=inputs["f"],
            continuation=claripy.BVV(
                18 if end.addr == note_pitch else 17, 8
            ),
            constraints=tuple(end.solver.constraints),
        )
        for end in _all_handler_boundaries(
            project, state, {note_pitch, GB_RETURN}
        )
    ]


def _note_length_native(
    symbol: str, inputs: dict[str, claripy.ast.BV]
) -> list[NoteLengthEndpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(symbol)
    assert function is not None
    arithmetic = project.loader.find_symbol("port_audio_note_delay_arithmetic")
    assert arithmetic is not None
    project.hook(arithmetic.rebased_addr, NativeNoteDelayArithmeticSummary())
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    offsets = {
        "note_speeds": 8,
        "music_tempo": 16,
        "sfx_tempo": 18,
        "fractional_note_delays": 20,
        "note_delays": 28,
        "flags2": 36,
        "flags1": 44,
        "sound5": 52,
        "sound8": 53,
        "tempo_modifier": 54,
        "saved_a": 55,
        "saved_f": 56,
        "continuation": 57,
    }
    for name, offset in offsets.items():
        state.memory.store(NATIVE_STATE + offset, inputs[name])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        NoteLengthEndpoint(
            **native_registers(end, NATIVE_STATE),
            **{
                name: end.memory.load(NATIVE_STATE + offset, 1 if name in {
                    "sound5", "sound8", "tempo_modifier", "saved_a", "saved_f",
                    "continuation"
                } else 2 if name in {"music_tempo", "sfx_tempo"} else 8)
                for name, offset in offsets.items()
            },
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


def _note_pitch_addresses() -> dict[str, object]:
    return {
        "octaves": symbol_location(SYMBOLS, "wChannelOctaves").address,
        "flags1": symbol_location(SYMBOLS, "wChannelFlags1").address,
        "sound_ids": symbol_location(SYMBOLS, "wChannelSoundIDs").address,
        "volumes": symbol_location(SYMBOLS, "wChannelVolumes").address,
        "note_delays": symbol_location(SYMBOLS, "wChannelNoteDelayCounters").address,
        "duty_cycles": symbol_location(SYMBOLS, "wChannelDutyCycles").address,
        "stereo": symbol_location(SYMBOLS, "wStereoPanning").address,
        "frequency_low_bytes": symbol_location(
            SYMBOLS, "wChannelFrequencyLowBytes"
        ).address,
        "music_instrument": symbol_location(SYMBOLS, "wMusicWaveInstrument").address,
        "sfx_instrument": symbol_location(SYMBOLS, "wSfxWaveInstrument").address,
        "frequency_modifier": symbol_location(SYMBOLS, "wFrequencyModifier").address,
        "length_modifiers": symbol_location(
            SYMBOLS, "wChannelPitchSlideLengthModifiers"
        ).address,
        "frequency_steps": symbol_location(
            SYMBOLS, "wChannelPitchSlideFrequencySteps"
        ).address,
        "frequency_steps_fractional": symbol_location(
            SYMBOLS, "wChannelPitchSlideFrequencyStepsFractionalPart"
        ).address,
        "current_frequency_fractional": symbol_location(
            SYMBOLS, "wChannelPitchSlideCurrentFrequencyFractionalPart"
        ).address,
        "current_frequency_high": symbol_location(
            SYMBOLS, "wChannelPitchSlideCurrentFrequencyHighBytes"
        ).address,
        "current_frequency_low": symbol_location(
            SYMBOLS, "wChannelPitchSlideCurrentFrequencyLowBytes"
        ).address,
        "target_frequency_high": symbol_location(
            SYMBOLS, "wChannelPitchSlideTargetFrequencyHighBytes"
        ).address,
        "target_frequency_low": symbol_location(
            SYMBOLS, "wChannelPitchSlideTargetFrequencyLowBytes"
        ).address,
        "hardware_envelopes": (0xFF12, 0xFF17, 0xFF1C, 0xFF21),
        "hardware_duty": (0xFF11, 0xFF16, 0xFF1B, 0xFF20),
        "hardware_frequency": (
            (0xFF13, 0xFF14),
            (0xFF18, 0xFF19),
            (0xFF1D, 0xFF1E),
            (0xFF22, 0xFF23),
        ),
    }


def _note_pitch_endpoint(
    end: angr.SimState, addresses: dict[str, object]
) -> NotePitchEndpoint:
    scalar_arrays = (
        "octaves", "flags1", "volumes", "note_delays", "duty_cycles",
        "frequency_low_bytes", "length_modifiers", "frequency_steps",
        "frequency_steps_fractional", "current_frequency_fractional",
        "current_frequency_high", "current_frequency_low",
        "target_frequency_high", "target_frequency_low",
    )
    sound_address = int(addresses["sound_ids"])
    hardware_frequency = addresses["hardware_frequency"]
    assert isinstance(hardware_frequency, tuple)
    hardware_envelopes = addresses["hardware_envelopes"]
    hardware_duty = addresses["hardware_duty"]
    assert isinstance(hardware_envelopes, tuple)
    assert isinstance(hardware_duty, tuple)
    return NotePitchEndpoint(
        **assembly_registers(end),
        **{
            name: end.memory.load(int(addresses[name]), 8)
            for name in scalar_arrays
        },
        sfx_sound_ids=end.memory.load(sound_address + 4, 4),
        hardware_envelopes=claripy.Concat(
            *(end.memory.load(address, 1) for address in hardware_envelopes)
        ),
        hardware_duty=claripy.Concat(
            *(end.memory.load(address, 1) for address in hardware_duty)
        ),
        audio_terminal=end.memory.load(0xFF25, 1),
        stereo_panning=end.memory.load(int(addresses["stereo"]), 1),
        music_instrument=end.memory.load(int(addresses["music_instrument"]), 1),
        sfx_instrument=end.memory.load(int(addresses["sfx_instrument"]), 1),
        sound5=end.memory.load(sound_address + 4, 1),
        sound8=end.memory.load(sound_address + 7, 1),
        frequency_modifier=end.memory.load(int(addresses["frequency_modifier"]), 1),
        audio3_enable=end.memory.load(0xFF1A, 1),
        wave_ram=end.memory.load(0xFF30, 16),
        hardware_frequency=claripy.Concat(
            *(
                end.memory.load(address, 1)
                for pair in hardware_frequency
                for address in pair
            )
        ),
        constraints=tuple(end.solver.constraints),
    )


def _note_pitch_assembly(
    symbol: str,
    inputs: dict[str, claripy.ast.BV],
    channel: int,
    pitch_slide: bool,
    rest: bool,
) -> list[NotePitchEndpoint]:
    location = symbol_location(SYMBOLS, symbol)
    variant = int(symbol[5])
    addresses = _note_pitch_addresses()
    pitches = symbol_location(SYMBOLS, f"Audio{variant}_Pitches").address
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
    project.hook(location.address, Sm83PopAf(location.address + 1), length=1)
    for offset, immediate in ((3, 0xC0), (8, 4), (21, 2), (25, 6), (82, 4)):
        project.hook(
            location.address + offset,
            Sm83CpImmediate(immediate, location.address + offset + 2),
            length=2,
        )
    for offset in (15, 34, 62, 72, 106, 126, 138):
        project.hook(
            location.address + offset,
            Sm83AddHlRegisterPair("bc", location.address + offset + 1),
            length=1,
        )
    project.hook(
        location.address + 92,
        Sm83AddHlRegisterPair("de", location.address + 93),
        length=1,
    )
    project.hook(
        location.address + 35,
        Sm83LoadAHighImmediate(0x25, location.address + 37),
        length=2,
    )
    project.hook(
        location.address + 38,
        Sm83StoreAHighImmediate(0x25, location.address + 40),
        length=2,
    )
    project.hook(
        location.address + 49,
        Sm83StoreAAtHlIncrement(location.address + 50),
        length=1,
    )
    project.hook(
        location.address + 55,
        Sm83SwapRegister("a", location.address + 57),
        length=2,
    )
    project.hook(
        location.address + 73,
        Sm83BitAtHl(4, location.address + 75),
        length=2,
    )
    project.hook(
        location.address + 127,
        Sm83BitAtHl(0, location.address + 129),
        length=2,
    )
    project.hook(
        location.address + 131,
        Sm83IncRegister("e", location.address + 132),
        length=1,
    )
    project.hook(
        location.address + 134,
        Sm83IncRegister("d", location.address + 135),
        length=1,
    )
    project.hook(
        location.address + 44,
        NotePitchGetRegisterPointerSummary(channel, location.address + 47),
        length=3,
    )
    project.hook(
        location.address + 64,
        NotePitchCalculateFrequencySummary(pitches, location.address + 67),
        length=3,
    )
    project.hook(
        location.address + 77,
        NotePitchInitSlideSummary(
            {name: int(value) for name, value in addresses.items() if isinstance(value, int)},
            channel,
            location.address + 80,
        ),
        length=3,
    )
    project.hook(
        location.address + 110,
        NotePitchGetRegisterPointerSummary(channel, location.address + 113),
        length=3,
    )
    project.hook(
        location.address + 114,
        NotePitchDutyLengthSummary(addresses, channel, location.address + 117),
        length=3,
    )
    project.hook(
        location.address + 117,
        NotePitchEnableOutputSummary(
            addresses, channel, variant, location.address + 120
        ),
        length=3,
    )
    patterns = tuple(
        linked_bytes(
            ROM,
            symbol_location(SYMBOLS, f"Audio{variant}_WavePointers.wave{index}"),
            16,
        )
        for index in range(6)
    )
    project.hook(
        location.address + 140,
        NotePitchWaveFrequencySummary(
            addresses, channel, variant, patterns, location.address + 143
        ),
        length=3,
    )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, inputs["saved_f"])
    state.memory.store(GB_STACK + 1, inputs["saved_a"])
    state.memory.store(GB_STACK + 2, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    for name in (
        "octaves", "flags1", "volumes", "note_delays", "duty_cycles",
        "frequency_low_bytes", "length_modifiers", "frequency_steps",
        "frequency_steps_fractional", "current_frequency_fractional",
        "current_frequency_high", "current_frequency_low",
        "target_frequency_high", "target_frequency_low",
    ):
        state.memory.store(int(addresses[name]), inputs[name])
    sound_address = int(addresses["sound_ids"])
    state.memory.store(sound_address + 4, inputs["sfx_sound_ids"])
    for name in ("music_instrument", "sfx_instrument", "frequency_modifier"):
        state.memory.store(int(addresses[name]), inputs[name])
    for name in ("hardware_envelopes", "hardware_duty"):
        hardware_addresses = addresses[name]
        assert isinstance(hardware_addresses, tuple)
        for index, hardware_address in enumerate(hardware_addresses):
            high = 31 - index * 8
            state.memory.store(hardware_address, inputs[name][high : high - 7])
    hardware_frequency = addresses["hardware_frequency"]
    assert isinstance(hardware_frequency, tuple)
    for index, hardware_address in enumerate(
        address for pair in hardware_frequency for address in pair
    ):
        high = 63 - index * 8
        state.memory.store(
            hardware_address, inputs["hardware_frequency"][high : high - 7]
        )
    state.memory.store(0xFF25, inputs["audio_terminal"])
    state.memory.store(int(addresses["stereo"]), inputs["stereo_panning"])
    state.memory.store(0xFF1A, inputs["audio3_enable"])
    state.memory.store(0xFF30, inputs["wave_ram"])
    state.globals["note_pitch_slide_outputs"] = inputs["slide_outputs"]
    if not rest:
        flags = state.memory.load(int(addresses["flags1"]) + channel, 1)
        state.solver.add(
            (flags & 0x10) != 0 if pitch_slide else (flags & 0x10) == 0
        )
        state.solver.add((inputs["saved_a"] >> 4).ULE(11))
        octave = state.memory.load(int(addresses["octaves"]) + channel, 1)
        state.solver.add(octave.ULE(7))
    if pitch_slide and not rest:
        delay = state.memory.load(int(addresses["note_delays"]) + channel, 1)
        modifier = state.memory.load(int(addresses["length_modifiers"]) + channel, 1)
        target_high = state.memory.load(
            int(addresses["target_frequency_high"]) + channel, 1
        )
        state.solver.add(delay != modifier, target_high.ULE(7))
    return [
        _note_pitch_endpoint(end, addresses)
        for end in collect_returns(project, state, GB_RETURN)
    ]


def _note_pitch_native(
    symbol: str,
    inputs: dict[str, claripy.ast.BV],
    channel: int,
    pitch_slide: bool,
    rest: bool,
) -> list[NotePitchEndpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(symbol)
    assert function is not None
    init_slide = project.loader.find_symbol("port_audio1_init_pitch_slide_vars")
    assert init_slide is not None
    project.hook(
        init_slide.rebased_addr, NativeNotePitchInitSlideSummary(channel)
    )
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    offsets = {
        "saved_a": (8, 1), "saved_f": (9, 1), "octaves": (10, 8),
        "flags1": (18, 8), "sfx_sound_ids": (26, 4), "volumes": (30, 8),
        "note_delays": (38, 8), "duty_cycles": (46, 8),
        "hardware_envelopes": (54, 4), "hardware_duty": (58, 4),
        "audio_terminal": (62, 1), "stereo_panning": (63, 1),
        "frequency_low_bytes": (64, 8), "music_instrument": (72, 1),
        "sfx_instrument": (73, 1), "sound5": (74, 1), "sound8": (75, 1),
        "frequency_modifier": (76, 1), "audio3_enable": (77, 1),
        "wave_ram": (78, 16), "hardware_frequency": (94, 8),
        "length_modifiers": (102, 8), "frequency_steps": (110, 8),
        "frequency_steps_fractional": (118, 8),
        "current_frequency_fractional": (126, 8),
        "current_frequency_high": (134, 8), "current_frequency_low": (142, 8),
        "target_frequency_high": (150, 8), "target_frequency_low": (158, 8),
    }
    for name, (offset, _size) in offsets.items():
        state.memory.store(NATIVE_STATE + offset, inputs[name])
    state.globals["note_pitch_slide_outputs"] = inputs["slide_outputs"]
    if not rest:
        flags = state.memory.load(NATIVE_STATE + 18 + channel, 1)
        state.solver.add(
            (flags & 0x10) != 0 if pitch_slide else (flags & 0x10) == 0
        )
        state.solver.add((inputs["saved_a"] >> 4).ULE(11))
        octave = state.memory.load(NATIVE_STATE + 10 + channel, 1)
        state.solver.add(octave.ULE(7))
    if pitch_slide and not rest:
        delay = state.memory.load(NATIVE_STATE + 38 + channel, 1)
        modifier = state.memory.load(NATIVE_STATE + 102 + channel, 1)
        target_high = state.memory.load(NATIVE_STATE + 150 + channel, 1)
        state.solver.add(delay != modifier, target_high.ULE(7))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        NotePitchEndpoint(
            **native_registers(end, NATIVE_STATE),
            **{
                name: end.memory.load(NATIVE_STATE + offset, size)
                for name, (offset, size) in offsets.items()
                if name not in {"saved_a", "saved_f"}
            },
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


def _play_next_note_assembly(
    symbol: str, inputs: dict[str, claripy.ast.BV]
) -> list[PlayNextNoteEndpoint]:
    location = symbol_location(SYMBOLS, symbol)
    variant = int(symbol[5])
    sound_ret_call = location.address + (29 if variant == 2 else 18)
    reload_address = symbol_location(
        SYMBOLS, "wChannelVibratoDelayCounterReloadValues"
    ).address
    counter_address = symbol_location(
        SYMBOLS, "wChannelVibratoDelayCounters"
    ).address
    flags_address = symbol_location(SYMBOLS, "wChannelFlags1").address
    low_health_address = symbol_location(SYMBOLS, "wLowHealthAlarm").address
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
    for offset in (3, 8, 13):
        project.hook(
            location.address + offset,
            Sm83AddHlRegisterPair("bc", location.address + offset + 1),
            length=1,
        )
    project.hook(
        location.address + 14,
        Sm83ResAtHl(4, location.address + 16),
        length=2,
    )
    project.hook(
        location.address + 16,
        Sm83ResAtHl(5, location.address + 18),
        length=2,
    )
    if variant == 2:
        project.hook(
            location.address + 19,
            Sm83CpImmediate(4, location.address + 21),
            length=2,
        )
        project.hook(
            location.address + 26,
            Sm83BitRegister(7, "a", location.address + 28),
            length=2,
        )
        project.hook(
            location.address + 23,
            Sm83LoadAImmediate(low_health_address, location.address + 26),
            length=3,
        )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    state.memory.store(reload_address, inputs["vibrato_delay_reloads"])
    state.memory.store(counter_address, inputs["vibrato_delay_counters"])
    state.memory.store(flags_address, inputs["flags1"])
    state.memory.store(low_health_address, inputs["low_health_alarm"])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    manager = project.factory.simulation_manager(state)
    manager.stashes["found"] = []
    while manager.active:
        manager.move(
            from_stash="active",
            to_stash="found",
            filter_func=lambda candidate: candidate.addr in {sound_ret_call, GB_RETURN},
        )
        if manager.active:
            manager.step()
    assert not manager.errored
    return [
        PlayNextNoteEndpoint(
            **assembly_registers(end),
            vibrato_delay_reloads=end.memory.load(reload_address, 8),
            vibrato_delay_counters=end.memory.load(counter_address, 8),
            flags1=end.memory.load(flags_address, 8),
            low_health_alarm=end.memory.load(low_health_address, 1),
            continuation=claripy.BVV(
                1 if end.addr == sound_ret_call else 17, 8
            ),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _play_next_note_native(
    symbol: str, inputs: dict[str, claripy.ast.BV]
) -> list[PlayNextNoteEndpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["vibrato_delay_reloads"])
    state.memory.store(NATIVE_STATE + 16, inputs["vibrato_delay_counters"])
    state.memory.store(NATIVE_STATE + 24, inputs["flags1"])
    state.memory.store(NATIVE_STATE + 32, inputs["low_health_alarm"])
    state.memory.store(NATIVE_STATE + 33, inputs["continuation"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        PlayNextNoteEndpoint(
            **native_registers(end, NATIVE_STATE),
            vibrato_delay_reloads=end.memory.load(NATIVE_STATE + 8, 8),
            vibrato_delay_counters=end.memory.load(NATIVE_STATE + 16, 8),
            flags1=end.memory.load(NATIVE_STATE + 24, 8),
            low_health_alarm=end.memory.load(NATIVE_STATE + 32, 1),
            continuation=end.memory.load(NATIVE_STATE + 33, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


def _sound_ret_assembly(
    symbol: str, inputs: dict[str, claripy.ast.BV], channel: int
) -> list[SoundRetEndpoint]:
    location = symbol_location(SYMBOLS, symbol)
    variant = int(symbol[5])
    sound_call = symbol_location(SYMBOLS, f"Audio{variant}_sound_call").address
    get_next = symbol_location(SYMBOLS, f"Audio{variant}_GetNextMusicByte").address
    pointer_address = symbol_location(SYMBOLS, "wChannelCommandPointers").address
    return_address = symbol_location(SYMBOLS, "wChannelReturnAddresses").address
    flags1_address = symbol_location(SYMBOLS, "wChannelFlags1").address
    flags2_address = symbol_location(SYMBOLS, "wChannelFlags2").address
    disable_address = symbol_location(
        SYMBOLS, "wDisableChannelOutputWhenSfxEnds"
    ).address
    sound_address = symbol_location(SYMBOLS, "wChannelSoundIDs").address
    saved_volume_address = symbol_location(SYMBOLS, "wSavedVolume").address
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
    _hook_get_next_music_byte(project, get_next, sequential=True)
    for offset, immediate in ((4, 0xFF), (20, 3), (34, 6), (101, 0x14), (110, 0x86), (119, 4)):
        project.hook(
            location.address + offset,
            Sm83CpImmediate(immediate, location.address + offset + 2),
            length=2,
        )
    for offset in (14, 31, 92, 139):
        project.hook(
            location.address + offset,
            Sm83AddHlRegisterPair("bc", location.address + offset + 1),
            length=1,
        )
    for offset in (72, 77):
        project.hook(
            location.address + offset,
            Sm83AddHlRegisterPair("de", location.address + offset + 1),
            length=1,
        )
    project.hook(
        location.address + 15,
        Sm83BitAtHl(1, location.address + 17),
        length=2,
    )
    for offset, bit in ((26, 2), (32, 0), (62, 1)):
        project.hook(
            location.address + offset,
            Sm83ResAtHl(bit, location.address + offset + 2),
            length=2,
        )
    project.hook(
        location.address + 67,
        Sm83AddRegister("a", location.address + 68),
        length=1,
    )
    project.hook(
        location.address + 82,
        Sm83StoreAAtHlIncrement(location.address + 83),
        length=1,
    )
    for offset, high_address in ((40, 0x1A), (44, 0x1A), (93, 0x25), (96, 0x25), (130, 0x24)):
        procedure = (
            Sm83LoadAHighImmediate(high_address, location.address + offset + 2)
            if offset == 93
            else Sm83StoreAHighImmediate(high_address, location.address + offset + 2)
        )
        project.hook(location.address + offset, procedure, length=2)
    for offset, memory_address in (
        (48, disable_address),
        (98, sound_address + 4),
        (107, sound_address + 4),
        (127, saved_volume_address),
    ):
        project.hook(
            location.address + offset,
            Sm83LoadAImmediate(memory_address, location.address + offset + 3),
            length=3,
        )
    for offset, memory_address in ((55, disable_address), (133, saved_volume_address)):
        project.hook(
            location.address + offset,
            Sm83StoreAImmediate(memory_address, location.address + offset + 3),
            length=3,
        )
    project.hook(
        location.address + 123,
        SoundRetGoBackSummary(pointer_address, channel, location.address + 126),
        length=3,
    )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    state.memory.store(pointer_address, inputs["command_pointers"])
    state.memory.store(return_address, inputs["return_addresses"])
    state.memory.store(flags1_address, inputs["flags1"])
    state.memory.store(flags2_address, inputs["flags2"])
    state.memory.store(disable_address, inputs["disable_channel_output"])
    state.memory.store(0xFF1A, inputs["audio3_enable"])
    state.memory.store(0xFF25, inputs["audio_terminal"])
    state.memory.store(sound_address, inputs["sound_ids"])
    state.memory.store(saved_volume_address, inputs["saved_volume"])
    state.memory.store(0xFF24, inputs["audio_volume"])
    state.globals["command_bytes"] = (
        inputs["command_bytes"].get_byte(0),
        inputs["command_bytes"].get_byte(1),
    )
    state.globals["command_byte_index"] = 0
    pointer = _next_music_byte_pointer(inputs["command_pointers"], channel)
    return_pointer = _next_music_byte_pointer(inputs["return_addresses"], channel)
    state.solver.add(pointer.UGE(0x4000), pointer.ULE(0x7FFE))
    state.solver.add(return_pointer.UGE(0x4000), return_pointer.ULE(0x7FFE))
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    return [
        SoundRetEndpoint(
            **assembly_registers(end),
            command_pointers=end.memory.load(pointer_address, 16),
            command_bytes=inputs["command_bytes"],
            return_addresses=end.memory.load(return_address, 16),
            flags1=end.memory.load(flags1_address, 8),
            flags2=end.memory.load(flags2_address, 8),
            disable_channel_output=end.memory.load(disable_address, 1),
            audio3_enable=end.memory.load(0xFF1A, 1),
            audio_terminal=end.memory.load(0xFF25, 1),
            sound_ids=end.memory.load(sound_address, 8),
            saved_volume=end.memory.load(saved_volume_address, 1),
            audio_volume=end.memory.load(0xFF24, 1),
            continuation=claripy.BVV(19 if end.addr == sound_call else 17, 8),
            constraints=tuple(end.solver.constraints),
        )
        for end in _all_handler_boundaries(project, state, {sound_call, GB_RETURN})
    ]


def _sound_ret_native(
    symbol: str, inputs: dict[str, claripy.ast.BV]
) -> list[SoundRetEndpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    offsets = {
        "command_pointers": (8, 16), "command_bytes": (24, 2),
        "return_addresses": (26, 16), "flags1": (42, 8), "flags2": (50, 8),
        "disable_channel_output": (58, 1), "audio3_enable": (59, 1),
        "audio_terminal": (60, 1), "sound_ids": (61, 8),
        "saved_volume": (69, 1), "audio_volume": (70, 1),
        "continuation": (71, 1),
    }
    for name, (offset, _size) in offsets.items():
        state.memory.store(NATIVE_STATE + offset, inputs[name])
    pointer = _next_music_byte_pointer(inputs["command_pointers"], inputs["c"].args[0])
    return_pointer = _next_music_byte_pointer(inputs["return_addresses"], inputs["c"].args[0])
    state.solver.add(pointer.UGE(0x4000), pointer.ULE(0x7FFE))
    state.solver.add(return_pointer.UGE(0x4000), return_pointer.ULE(0x7FFE))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        SoundRetEndpoint(
            **native_registers(end, NATIVE_STATE),
            **{
                name: end.memory.load(NATIVE_STATE + offset, size)
                for name, (offset, size) in offsets.items()
            },
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


def _sfx_note_addresses() -> dict[str, object]:
    addresses = _note_pitch_addresses()
    addresses.update(
        {
            "note_speeds": symbol_location(
                SYMBOLS, "wChannelNoteSpeeds"
            ).address,
            "music_tempo": symbol_location(SYMBOLS, "wMusicTempo").address,
            "sfx_tempo": symbol_location(SYMBOLS, "wSfxTempo").address,
            "fractional_note_delays": symbol_location(
                SYMBOLS, "wChannelNoteDelayCountersFractionalPart"
            ).address,
            "flags2": symbol_location(SYMBOLS, "wChannelFlags2").address,
            "tempo_modifier": symbol_location(SYMBOLS, "wTempoModifier").address,
        }
    )
    return addresses


def _sfx_note_assembly(
    symbol: str, inputs: dict[str, object], channel: int
) -> list[SfxNoteEndpoint]:
    location = symbol_location(SYMBOLS, symbol)
    variant = int(symbol[5])
    pitch_sweep = symbol_location(SYMBOLS, f"Audio{variant}_pitch_sweep").address
    get_next = symbol_location(SYMBOLS, f"Audio{variant}_GetNextMusicByte").address
    addresses = _sfx_note_addresses()
    integer_addresses = {
        name: value for name, value in addresses.items() if isinstance(value, int)
    }
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
    for offset, immediate in ((0, 0x20), (5, 3), (53, 7)):
        project.hook(
            location.address + offset,
            Sm83CpImmediate(immediate, location.address + offset + 2),
            length=2,
        )
    for offset in (14, 28):
        project.hook(
            location.address + offset,
            Sm83AddHlRegisterPair("bc", location.address + offset + 1),
            length=1,
        )
    project.hook(
        location.address + 15,
        Sm83BitAtHl(0, location.address + 17),
        length=2,
    )
    project.hook(
        location.address + 19,
        SfxNoteLengthSummary(integer_addresses, location.address + 22),
        length=3,
    )
    project.hook(
        location.address + 34,
        NotePitchGetRegisterPointerSummary(channel, location.address + 37),
        length=3,
    )
    project.hook(
        location.address + 44,
        NotePitchGetRegisterPointerSummary(channel, location.address + 47),
        length=3,
    )
    _hook_get_next_music_byte(project, get_next, sequential=True)
    project.hook(
        location.address + 66,
        NotePitchDutyLengthSummary(addresses, channel, location.address + 69),
        length=3,
    )
    project.hook(
        location.address + 69,
        NotePitchEnableOutputSummary(
            addresses, channel, variant, location.address + 72
        ),
        length=3,
    )
    patterns = tuple(
        linked_bytes(
            ROM,
            symbol_location(SYMBOLS, f"Audio{variant}_WavePointers.wave{index}"),
            16,
        )
        for index in range(6)
    )
    project.hook(
        location.address + 73,
        NotePitchWaveFrequencySummary(
            addresses, channel, variant, patterns, location.address + 76
        ),
        length=3,
    )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)  # type: ignore[arg-type]
    scalar_arrays = (
        "note_speeds", "music_tempo", "sfx_tempo",
        "fractional_note_delays", "note_delays", "flags2", "flags1",
        "sound_ids", "duty_cycles",
    )
    pointer_address = symbol_location(SYMBOLS, "wChannelCommandPointers").address
    state.memory.store(pointer_address, inputs["command_pointers"])
    for name in scalar_arrays:
        state.memory.store(int(addresses[name]), inputs[name])
    for address_name, input_name in (
        ("tempo_modifier", "tempo_modifier"),
        ("stereo", "stereo_panning"),
        ("music_instrument", "music_instrument"),
        ("sfx_instrument", "sfx_instrument"),
        ("frequency_modifier", "frequency_modifier"),
    ):
        state.memory.store(int(addresses[address_name]), inputs[input_name])
    for name in ("hardware_envelopes", "hardware_duty"):
        hardware_addresses = addresses[name]
        assert isinstance(hardware_addresses, tuple)
        for index, hardware_address in enumerate(hardware_addresses):
            high = 31 - index * 8
            state.memory.store(hardware_address, inputs[name][high : high - 7])
    hardware_frequency = addresses["hardware_frequency"]
    assert isinstance(hardware_frequency, tuple)
    for index, hardware_address in enumerate(
        address for pair in hardware_frequency for address in pair
    ):
        high = 63 - index * 8
        state.memory.store(
            hardware_address, inputs["hardware_frequency"][high : high - 7]
        )
    state.memory.store(0xFF25, inputs["audio_terminal"])
    state.memory.store(0xFF1A, inputs["audio3_enable"])
    state.memory.store(0xFF30, inputs["wave_ram"])
    state.globals["command_bytes"] = tuple(
        inputs["command_bytes"].get_byte(index) for index in range(3)
    )
    state.globals["command_byte_index"] = 0
    state.globals["sfx_note_length_outputs"] = inputs["length_outputs"]
    pointer = _next_music_byte_pointer(inputs["command_pointers"], channel)
    state.solver.add(pointer.UGE(0x4000), pointer.ULE(0x7FFC))
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    hardware_envelopes = addresses["hardware_envelopes"]
    hardware_duty = addresses["hardware_duty"]
    assert isinstance(hardware_envelopes, tuple)
    assert isinstance(hardware_duty, tuple)
    return [
        SfxNoteEndpoint(
            **assembly_registers(end),
            command_pointers=end.memory.load(pointer_address, 16),
            command_bytes=inputs["command_bytes"],
            **{
                name: end.memory.load(int(addresses[name]), size)
                for name, size in (
                    ("note_speeds", 8), ("music_tempo", 2),
                    ("sfx_tempo", 2), ("fractional_note_delays", 8),
                    ("note_delays", 8), ("flags2", 8), ("flags1", 8),
                    ("sound_ids", 8), ("tempo_modifier", 1),
                    ("duty_cycles", 8),
                )
            },
            hardware_envelopes=claripy.Concat(
                *(end.memory.load(address, 1) for address in hardware_envelopes)
            ),
            hardware_duty=claripy.Concat(
                *(end.memory.load(address, 1) for address in hardware_duty)
            ),
            audio_terminal=end.memory.load(0xFF25, 1),
            stereo_panning=end.memory.load(int(addresses["stereo"]), 1),
            music_instrument=end.memory.load(int(addresses["music_instrument"]), 1),
            sfx_instrument=end.memory.load(int(addresses["sfx_instrument"]), 1),
            frequency_modifier=end.memory.load(
                int(addresses["frequency_modifier"]), 1
            ),
            audio3_enable=end.memory.load(0xFF1A, 1),
            wave_ram=end.memory.load(0xFF30, 16),
            hardware_frequency=claripy.Concat(
                *(
                    end.memory.load(address, 1)
                    for pair in hardware_frequency
                    for address in pair
                )
            ),
            continuation=claripy.BVV(
                20 if end.addr == pitch_sweep else 17, 8
            ),
            constraints=tuple(end.solver.constraints),
        )
        for end in _all_handler_boundaries(
            project,
            state,
            {pitch_sweep} if channel < 3 else {pitch_sweep, GB_RETURN},
        )
    ]


def _sfx_note_native(
    symbol: str, inputs: dict[str, object], channel: int
) -> list[SfxNoteEndpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(symbol)
    assert function is not None
    for variant in (1, 2, 3):
        leaf = project.loader.find_symbol(f"port_audio{variant}_note_length")
        assert leaf is not None
        project.hook(leaf.rebased_addr, NativeSfxNoteLengthSummary())
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)  # type: ignore[arg-type]
    offsets = {
        "command_pointers": (8, 16), "command_bytes": (24, 3),
        "note_speeds": (27, 8), "music_tempo": (35, 2),
        "sfx_tempo": (37, 2), "fractional_note_delays": (39, 8),
        "note_delays": (47, 8), "flags2": (55, 8), "flags1": (63, 8),
        "sound_ids": (71, 8), "tempo_modifier": (79, 1),
        "duty_cycles": (80, 8), "hardware_envelopes": (88, 4),
        "hardware_duty": (92, 4), "audio_terminal": (96, 1),
        "stereo_panning": (97, 1), "music_instrument": (98, 1),
        "sfx_instrument": (99, 1), "frequency_modifier": (100, 1),
        "audio3_enable": (101, 1), "wave_ram": (102, 16),
        "hardware_frequency": (118, 8), "continuation": (126, 1),
    }
    for name, (offset, _size) in offsets.items():
        state.memory.store(NATIVE_STATE + offset, inputs[name])
    state.globals["sfx_note_length_outputs"] = inputs["length_outputs"]
    pointer = _next_music_byte_pointer(inputs["command_pointers"], channel)
    state.solver.add(pointer.UGE(0x4000), pointer.ULE(0x7FFC))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        SfxNoteEndpoint(
            **native_registers(end, NATIVE_STATE),
            **{
                name: end.memory.load(NATIVE_STATE + offset, size)
                for name, (offset, size) in offsets.items()
            },
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


def _apply_music_affects_addresses() -> dict[str, object]:
    return {
        "note_delays": symbol_location(
            SYMBOLS, "wChannelNoteDelayCounters"
        ).address,
        "sound_ids": symbol_location(SYMBOLS, "wChannelSoundIDs").address,
        "flags1": symbol_location(SYMBOLS, "wChannelFlags1").address,
        "flags2": symbol_location(SYMBOLS, "wChannelFlags2").address,
        "duty_patterns": symbol_location(
            SYMBOLS, "wChannelDutyCyclePatterns"
        ).address,
        "vibrato_delay_counters": symbol_location(
            SYMBOLS, "wChannelVibratoDelayCounters"
        ).address,
        "vibrato_extents": symbol_location(
            SYMBOLS, "wChannelVibratoExtents"
        ).address,
        "vibrato_rates": symbol_location(
            SYMBOLS, "wChannelVibratoRates"
        ).address,
        "frequency_low_bytes": symbol_location(
            SYMBOLS, "wChannelFrequencyLowBytes"
        ).address,
        "hardware_duty": (0xFF11, 0xFF16, 0xFF1B, 0xFF20),
        "hardware_frequency_low": (0xFF13, 0xFF18, 0xFF1D, 0xFF22),
    }


def _apply_music_affects_endpoint(
    end: angr.SimState,
    addresses: dict[str, object],
    continuation: claripy.ast.BV,
) -> ApplyMusicAffectsEndpoint:
    hardware_duty = addresses["hardware_duty"]
    hardware_frequency_low = addresses["hardware_frequency_low"]
    assert isinstance(hardware_duty, tuple)
    assert isinstance(hardware_frequency_low, tuple)
    return ApplyMusicAffectsEndpoint(
        **assembly_registers(end),
        **{
            name: end.memory.load(int(addresses[name]), 8)
            for name in (
                "note_delays", "sound_ids", "flags1", "flags2",
                "duty_patterns", "vibrato_delay_counters",
                "vibrato_extents", "vibrato_rates", "frequency_low_bytes",
            )
        },
        hardware_duty=claripy.Concat(
            *(end.memory.load(address, 1) for address in hardware_duty)
        ),
        hardware_frequency_low=claripy.Concat(
            *(end.memory.load(address, 1) for address in hardware_frequency_low)
        ),
        continuation=continuation,
        constraints=tuple(end.solver.constraints),
    )


def _apply_music_affects_assembly(
    symbol: str, inputs: dict[str, claripy.ast.BV], channel: int
) -> list[ApplyMusicAffectsEndpoint]:
    location = symbol_location(SYMBOLS, symbol)
    variant = int(symbol[5])
    play_next_note = symbol_location(
        SYMBOLS, f"Audio{variant}_PlayNextNote"
    ).address
    apply_pitch_slide = symbol_location(
        SYMBOLS, f"Audio{variant}_ApplyPitchSlide"
    ).address
    addresses = _apply_music_affects_addresses()
    hardware_duty = addresses["hardware_duty"]
    assert isinstance(hardware_duty, tuple)
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
    for offset in (5, 22, 31, 44, 52, 60, 71, 81, 91, 108, 113):
        project.hook(
            location.address + offset,
            Sm83AddHlRegisterPair("bc", location.address + offset + 1),
            length=1,
        )
    for offset, immediate in ((7, 1), (15, 4)):
        project.hook(
            location.address + offset,
            Sm83CpImmediate(immediate, location.address + offset + 2),
            length=2,
        )
    project.hook(
        location.address + 12,
        Sm83DecRegister("a", location.address + 13),
        length=1,
    )
    for offset, bit in ((32, 6), (45, 0), (53, 2), (61, 4), (114, 3)):
        project.hook(
            location.address + offset,
            Sm83BitAtHl(bit, location.address + offset + 2),
            length=2,
        )
    project.hook(
        location.address + 36,
        ApplyMusicDutyPatternSummary(
            channel,
            int(addresses["duty_patterns"]),
            hardware_duty,
            location.address + 39,
        ),
        length=3,
    )
    for offset in (76, 98):
        project.hook(
            location.address + offset,
            Sm83DecAtHl(location.address + offset + 1),
            length=1,
        )
    project.hook(
        location.address + 101,
        Sm83SwapAtHl(location.address + 103),
        length=2,
    )
    project.hook(
        location.address + 118,
        Sm83ResAtHl(3, location.address + 120),
        length=2,
    )
    project.hook(
        location.address + 125,
        Sm83SubRegister("d", location.address + 126),
        length=1,
    )
    project.hook(
        location.address + 132,
        Sm83SetAtHl(3, location.address + 134),
        length=2,
    )
    project.hook(
        location.address + 137,
        Sm83SwapRegister("a", location.address + 139),
        length=2,
    )
    project.hook(
        location.address + 139,
        Sm83AddRegister("e", location.address + 140),
        length=1,
    )
    project.hook(
        location.address + 147,
        NotePitchGetRegisterPointerSummary(channel, location.address + 150),
        length=3,
    )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    for name in (
        "note_delays", "sound_ids", "flags1", "flags2", "duty_patterns",
        "vibrato_delay_counters", "vibrato_extents", "vibrato_rates",
        "frequency_low_bytes",
    ):
        state.memory.store(int(addresses[name]), inputs[name])
    for name in ("hardware_duty", "hardware_frequency_low"):
        hardware_addresses = addresses[name]
        assert isinstance(hardware_addresses, tuple)
        for index, hardware_address in enumerate(hardware_addresses):
            high = 31 - index * 8
            state.memory.store(
                hardware_address, inputs[name][high : high - 7]
            )
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    endpoints = []
    for end in _all_handler_boundaries(
        project, state, {play_next_note, apply_pitch_slide, GB_RETURN}
    ):
        continuation = 17
        if end.addr == play_next_note:
            continuation = 21
        elif end.addr == apply_pitch_slide:
            continuation = 22
        endpoints.append(
            _apply_music_affects_endpoint(
                end, addresses, claripy.BVV(continuation, 8)
            )
        )
    return endpoints


def _apply_music_affects_native(
    symbol: str, inputs: dict[str, claripy.ast.BV]
) -> list[ApplyMusicAffectsEndpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(symbol)
    assert function is not None
    offsets = {
        "note_delays": (8, 8), "sound_ids": (16, 8),
        "flags1": (24, 8), "flags2": (32, 8),
        "duty_patterns": (40, 8), "hardware_duty": (48, 4),
        "vibrato_delay_counters": (52, 8), "vibrato_extents": (60, 8),
        "vibrato_rates": (68, 8), "frequency_low_bytes": (76, 8),
        "hardware_frequency_low": (84, 4), "continuation": (88, 1),
    }
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    for name, (offset, _size) in offsets.items():
        state.memory.store(NATIVE_STATE + offset, inputs[name])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        ApplyMusicAffectsEndpoint(
            **native_registers(end, NATIVE_STATE),
            **{
                name: end.memory.load(NATIVE_STATE + offset, size)
                for name, (offset, size) in offsets.items()
            },
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


def _constrain_update_music_domain(
    state: angr.SimState,
    inputs: dict[str, claripy.ast.BV],
    target_channel: int,
    mute_mode: str,
    music_mask: int,
) -> None:
    sounds = inputs["sound_ids"]
    mute = inputs["mute_audio_and_pause_music"]
    if mute_mode == "zero":
        state.solver.add(mute == 0)
        for channel in range(8):
            byte = sounds.get_byte(channel)
            if target_channel >= 0 and channel == target_channel:
                state.solver.add(byte != 0)
                break
            state.solver.add(byte == 0)
    else:
        if mute_mode == "high":
            state.solver.add((mute & 0x80) != 0)
        else:
            state.solver.add(mute != 0, (mute & 0x80) == 0)
        for channel in range(4):
            byte = sounds.get_byte(channel)
            state.solver.add(
                byte != 0 if music_mask & (1 << channel) else byte == 0
            )
        for channel in range(4, 8):
            byte = sounds.get_byte(channel)
            if target_channel >= 0 and channel == target_channel:
                state.solver.add(byte != 0)
                break
            state.solver.add(byte == 0)


def _update_music_assembly(
    symbol: str,
    inputs: dict[str, claripy.ast.BV],
    target_channel: int,
    mute_mode: str,
    music_mask: int,
) -> list[UpdateMusicEndpoint]:
    location = symbol_location(SYMBOLS, symbol)
    variant = int(symbol[5])
    apply_music_affects = symbol_location(
        SYMBOLS, f"Audio{variant}_ApplyMusicAffects"
    ).address
    sound_ids_address = symbol_location(SYMBOLS, "wChannelSoundIDs").address
    mute_address = symbol_location(
        SYMBOLS, "wMuteAudioAndPauseMusic"
    ).address
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
    project.hook(
        location.address + 7,
        Sm83AddHlRegisterPair("bc", location.address + 8),
        length=1,
    )
    for offset, immediate in ((13, 4), (48, 7)):
        project.hook(
            location.address + offset,
            Sm83CpImmediate(immediate, location.address + offset + 2),
            length=2,
        )
    project.hook(
        location.address + 17,
        Sm83LoadAImmediate(mute_address, location.address + 20),
        length=3,
    )
    project.hook(
        location.address + 23,
        Sm83BitRegister(7, "a", location.address + 25),
        length=2,
    )
    project.hook(
        location.address + 29,
        Sm83StoreAImmediate(mute_address, location.address + 32),
        length=3,
    )
    for offset, high_address in ((33, 0x25), (35, 0x1A), (39, 0x1A)):
        project.hook(
            location.address + offset,
            Sm83StoreAHighImmediate(
                high_address, location.address + offset + 2
            ),
            length=2,
        )
    project.hook(
        location.address + 47,
        Sm83IncRegister("c", location.address + 48),
        length=1,
    )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    state.memory.store(sound_ids_address, inputs["sound_ids"])
    state.memory.store(mute_address, inputs["mute_audio_and_pause_music"])
    state.memory.store(0xFF25, inputs["audio_terminal"])
    state.memory.store(0xFF1A, inputs["audio3_enable"])
    _constrain_update_music_domain(
        state, inputs, target_channel, mute_mode, music_mask
    )
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    boundary = apply_music_affects if target_channel >= 0 else GB_RETURN
    return [
        UpdateMusicEndpoint(
            **assembly_registers(end),
            sound_ids=end.memory.load(sound_ids_address, 8),
            mute_audio_and_pause_music=end.memory.load(mute_address, 1),
            audio_terminal=end.memory.load(0xFF25, 1),
            audio3_enable=end.memory.load(0xFF1A, 1),
            continuation=claripy.BVV(
                23 if end.addr == apply_music_affects else 17, 8
            ),
            constraints=tuple(end.solver.constraints),
        )
        for end in _all_handler_boundaries(project, state, {boundary})
    ]


def _update_music_native(
    symbol: str,
    inputs: dict[str, claripy.ast.BV],
    target_channel: int,
    mute_mode: str,
    music_mask: int,
) -> list[UpdateMusicEndpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    offsets = {
        "sound_ids": (8, 8), "mute_audio_and_pause_music": (16, 1),
        "audio_terminal": (17, 1), "audio3_enable": (18, 1),
        "continuation": (19, 1),
    }
    for name, (offset, _size) in offsets.items():
        state.memory.store(NATIVE_STATE + offset, inputs[name])
    _constrain_update_music_domain(
        state, inputs, target_channel, mute_mode, music_mask
    )
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        UpdateMusicEndpoint(
            **native_registers(end, NATIVE_STATE),
            **{
                name: end.memory.load(NATIVE_STATE + offset, size)
                for name, (offset, size) in offsets.items()
            },
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


def _sm83_instruction_offsets(code: bytes) -> list[tuple[int, int, int | None]]:
    immediate8 = {
        0x06, 0x0E, 0x16, 0x1E, 0x26, 0x2E, 0x36, 0x3E,
        0x10, 0x18, 0x20, 0x28, 0x30, 0x38,
        0xC6, 0xCE, 0xD6, 0xDE, 0xE0, 0xE6, 0xE8, 0xEE,
        0xF0, 0xF6, 0xF8, 0xFE,
    }
    immediate16 = {
        0x01, 0x08, 0x11, 0x21, 0x31,
        0xC2, 0xC3, 0xC4, 0xCA, 0xCC, 0xCD,
        0xD2, 0xD4, 0xDA, 0xDC, 0xEA, 0xFA,
    }
    result = []
    offset = 0
    while offset < len(code):
        opcode = code[offset]
        cb_opcode = code[offset + 1] if opcode == 0xCB else None
        result.append((offset, opcode, cb_opcode))
        if opcode == 0xCB or opcode in immediate8:
            offset += 2
        elif opcode in immediate16:
            offset += 3
        else:
            offset += 1
    assert offset == len(code)
    return result


def _hook_play_sound_sm83(
    project: angr.Project, address: int, code: bytes
) -> None:
    for offset, opcode, cb_opcode in _sm83_instruction_offsets(code):
        current = address + offset
        if opcode == 0xEA:
            memory_address = code[offset + 1] | code[offset + 2] << 8
            project.hook(
                current,
                Sm83StoreAImmediate(memory_address, current + 3),
                length=3,
            )
        elif opcode == 0xFA:
            memory_address = code[offset + 1] | code[offset + 2] << 8
            project.hook(
                current,
                Sm83LoadAImmediate(memory_address, current + 3),
                length=3,
            )
        elif opcode == 0xE0:
            project.hook(
                current,
                Sm83StoreAHighImmediate(code[offset + 1], current + 2),
                length=2,
            )
        elif opcode == 0xF0:
            project.hook(
                current,
                Sm83LoadAHighImmediate(code[offset + 1], current + 2),
                length=2,
            )
        elif opcode == 0xFE:
            project.hook(
                current,
                Sm83CpImmediate(code[offset + 1], current + 2),
                length=2,
            )
        elif opcode in (0x09, 0x19, 0x29):
            pair = {0x09: "bc", 0x19: "de", 0x29: "hl"}[opcode]
            project.hook(
                current,
                Sm83AddHlRegisterPair(pair, current + 1),
                length=1,
            )
        elif opcode == 0x87:
            project.hook(
                current, Sm83AddRegister("a", current + 1), length=1
            )
        elif opcode == 0x81:
            project.hook(
                current, Sm83AddRegister("c", current + 1), length=1
            )
        elif opcode == 0xBE:
            project.hook(current, Sm83CpAtHl(current + 1), length=1)
        elif opcode == 0x22:
            project.hook(
                current, Sm83StoreAAtHlIncrement(current + 1), length=1
            )
        elif opcode == 0x04:
            project.hook(
                current, Sm83IncRegister("b", current + 1), length=1
            )
        elif opcode == 0x0C:
            project.hook(
                current, Sm83IncRegister("c", current + 1), length=1
            )
        elif opcode == 0x05:
            project.hook(
                current, Sm83DecRegister("b", current + 1), length=1
            )
        elif opcode == 0x0D:
            project.hook(
                current, Sm83DecRegister("c", current + 1), length=1
            )
        elif opcode == 0x07:
            project.hook(current, Sm83Rlca(current + 1), length=1)
        elif opcode == 0xF5:
            project.hook(current, Sm83PushAf(current + 1), length=1)
        elif opcode == 0xF1:
            project.hook(current, Sm83PopAf(current + 1), length=1)
        elif opcode == 0xCB:
            assert cb_opcode == 0xD6
            project.hook(
                current, Sm83SetAtHl(2, current + 2), length=2
            )


@lru_cache(maxsize=None)
def _play_sound_assembly_project(symbol: str) -> tuple[angr.Project, int]:
    location = symbol_location(SYMBOLS, symbol)
    code = linked_bytes(ROM, location, 672)
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
    _hook_play_sound_sm83(project, location.address, code)
    return project, location.address


def _play_sound_assembly(
    symbol: str, inputs: dict[str, claripy.ast.BV], sound_id: int
) -> list[PlaySoundEndpoint]:
    project, address = _play_sound_assembly_project(symbol)
    state = project.factory.blank_state(addr=address)
    set_assembly_registers(state, inputs)
    state.regs.a = sound_id
    state.memory.store(0xC000, inputs["audio_ram"])
    state.memory.store(0xFF10, inputs["hardware_audio"])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    return [
        PlaySoundEndpoint(
            **assembly_registers(end),
            audio_ram=end.memory.load(0xC000, 243),
            hardware_audio=end.memory.load(0xFF10, 23),
            constraints=tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, GB_RETURN)
    ]


def _play_sound_native(
    symbol: str,
    assembly_symbol: str,
    inputs: dict[str, claripy.ast.BV],
    sound_id: int,
) -> list[PlaySoundEndpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(symbol)
    assert function is not None
    variant = int(assembly_symbol[5])
    bank = symbol_location(SYMBOLS, f"SFX_Headers_{variant}").bank
    header_data = rom_window(ROM, bank).getvalue()[0x4000 : 0x4000 + 784]
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE, claripy.BVV(sound_id, 8))
    state.memory.store(NATIVE_STATE + 8, inputs["audio_ram"])
    state.memory.store(NATIVE_STATE + 251, inputs["hardware_audio"])
    state.memory.store(NATIVE_STATE + 274, header_data)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        PlaySoundEndpoint(
            **native_registers(end, NATIVE_STATE),
            audio_ram=end.memory.load(NATIVE_STATE + 8, 243),
            hardware_audio=end.memory.load(NATIVE_STATE + 251, 23),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


def _unknown_ef_assembly(
    symbol: str,
    inputs: dict[str, object],
    channel: int,
    matched: bool,
) -> list[UnknownEfEndpoint]:
    location = symbol_location(SYMBOLS, symbol)
    variant = int(symbol[5])
    get_next = symbol_location(SYMBOLS, f"Audio{variant}_GetNextMusicByte").address
    duty_pattern = symbol_location(
        SYMBOLS, f"Audio{variant}_duty_cycle_pattern"
    ).address
    sound_ret = symbol_location(SYMBOLS, f"Audio{variant}_sound_ret").address
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
    project.hook(
        location.address,
        Sm83CpImmediate(0xEF, location.address + 2),
        length=2,
    )
    _hook_get_next_music_byte(project, get_next)
    project.hook(
        location.address + 8,
        UnknownEfPlaySoundSummary(location.address + 11),
        length=3,
    )
    for offset, memory_address in ((12, 0xC003), (18, 0xC02D)):
        project.hook(
            location.address + offset,
            Sm83LoadAImmediate(memory_address, location.address + offset + 3),
            length=3,
        )
    for offset, memory_address in ((21, 0xC003), (25, 0xC02D)):
        project.hook(
            location.address + offset,
            Sm83StoreAImmediate(memory_address, location.address + offset + 3),
            length=3,
        )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)  # type: ignore[arg-type]
    state.memory.store(0xC000, inputs["audio_ram"])
    state.memory.store(0xFF10, inputs["hardware_audio"])
    state.globals["command_byte"] = inputs["command_byte"]
    state.globals["unknown_ef_play_outputs"] = inputs["play_outputs"]
    state.solver.add(
        inputs["a"] == 0xEF if matched else inputs["a"] != 0xEF
    )
    if matched:
        pointer = claripy.Concat(
            inputs["audio_ram"].get_byte(6 + channel * 2 + 1),
            inputs["audio_ram"].get_byte(6 + channel * 2),
        )
        state.solver.add(pointer.UGE(0x4000), pointer.ULE(0x7FFF))
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    boundary = sound_ret if matched else duty_pattern
    return [
        UnknownEfEndpoint(
            **assembly_registers(end),
            audio_ram=end.memory.load(0xC000, 243),
            hardware_audio=end.memory.load(0xFF10, 23),
            command_byte=inputs["command_byte"],
            continuation=claripy.BVV(1 if matched else 24, 8),
            constraints=tuple(end.solver.constraints),
        )
        for end in _all_handler_boundaries(project, state, {boundary})
    ]


def _unknown_ef_native(
    symbol: str,
    inputs: dict[str, object],
    channel: int,
    matched: bool,
) -> list[UnknownEfEndpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(symbol)
    assert function is not None
    for variant in (1, 2, 3):
        play = project.loader.find_symbol(f"port_audio{variant}_play_sound")
        assert play is not None
        project.hook(play.rebased_addr, NativeUnknownEfPlaySoundSummary())
    variant = int(symbol[10])
    bank = symbol_location(SYMBOLS, f"SFX_Headers_{variant}").bank
    header_data = rom_window(ROM, bank).getvalue()[0x4000 : 0x4310]
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)  # type: ignore[arg-type]
    state.memory.store(NATIVE_STATE + 8, inputs["audio_ram"])
    state.memory.store(NATIVE_STATE + 251, inputs["hardware_audio"])
    state.memory.store(NATIVE_STATE + 274, header_data)
    state.memory.store(NATIVE_STATE + 1058, inputs["command_byte"])
    state.memory.store(NATIVE_STATE + 1059, inputs["continuation"])
    state.globals["unknown_ef_play_outputs"] = inputs["play_outputs"]
    state.solver.add(
        inputs["a"] == 0xEF if matched else inputs["a"] != 0xEF
    )
    if matched:
        pointer = claripy.Concat(
            inputs["audio_ram"].get_byte(6 + channel * 2 + 1),
            inputs["audio_ram"].get_byte(6 + channel * 2),
        )
        state.solver.add(pointer.UGE(0x4000), pointer.ULE(0x7FFF))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        UnknownEfEndpoint(
            **native_registers(end, NATIVE_STATE),
            audio_ram=end.memory.load(NATIVE_STATE + 8, 243),
            hardware_audio=end.memory.load(NATIVE_STATE + 251, 23),
            command_byte=end.memory.load(NATIVE_STATE + 1058, 1),
            continuation=end.memory.load(NATIVE_STATE + 1059, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


def _constrain_note_category(
    state: angr.SimState,
    inputs: dict[str, object],
    channel: int,
    category: str,
    command_high: int | None,
    play_enabled: bool | None,
) -> None:
    if channel != 3:
        assert category == "ordinary"
        return
    assert command_high is not None
    state.solver.add((inputs["d"] & 0xF0) == command_high)
    if category in {"short", "drum"}:
        assert play_enabled is not None


def _note_assembly(
    symbol: str,
    inputs: dict[str, object],
    channel: int,
    category: str,
    command_high: int | None,
    play_enabled: bool | None,
) -> list[NoteEndpoint]:
    location = symbol_location(SYMBOLS, symbol)
    variant = int(symbol[5])
    get_next = symbol_location(SYMBOLS, f"Audio{variant}_GetNextMusicByte").address
    note_length = symbol_location(SYMBOLS, f"Audio{variant}_note_length").address
    boundary = 0xF000
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
    for offset, immediate in ((1, 3), (8, 0xB0)):
        project.hook(
            location.address + offset,
            Sm83CpImmediate(immediate, location.address + offset + 2),
            length=2,
        )
    for offset, immediate in ((6, 0xF0), (18, 0x0F), (27, 0x0F)):
        project.hook(
            location.address + offset,
            Sm83AndImmediate(immediate, location.address + offset + 2),
            length=2,
        )
    project.hook(
        location.address + 14,
        Sm83SwapRegister("a", location.address + 16),
        length=2,
    )
    project.hook(
        location.address + 29,
        Sm83PushAf(location.address + 30),
        length=1,
    )
    _hook_get_next_music_byte(project, get_next)
    project.hook(
        location.address + 35,
        Sm83LoadAImmediate(0xC003, location.address + 38),
        length=3,
    )
    project.hook(
        location.address + 42,
        UnknownEfPlaySoundSummary(location.address + 45),
        length=3,
    )
    project.hook(note_length, HandlerFallthroughBoundary(boundary), length=0)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)  # type: ignore[arg-type]
    state.memory.store(0xC000, inputs["audio_ram"])
    if play_enabled is not None:
        state.memory.store(0xC003, 0 if play_enabled else 1)
    state.memory.store(0xFF10, inputs["hardware_audio"])
    state.globals["command_byte"] = inputs["command_byte"]
    state.globals["unknown_ef_play_outputs"] = inputs["play_outputs"]
    _constrain_note_category(
        state, inputs, channel, category, command_high, play_enabled
    )
    if category == "drum":
        pointer = claripy.Concat(
            inputs["audio_ram"].get_byte(6 + channel * 2 + 1),
            inputs["audio_ram"].get_byte(6 + channel * 2),
        )
        state.solver.add(pointer.UGE(0x4000), pointer.ULE(0x7FFF))
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    return [
        NoteEndpoint(
            **assembly_registers(end),
            **{
                f"audio_ram_{index}": end.memory.load(
                    0xC000 + index * 32, 32 if index != 7 else 19
                )
                for index in range(8)
            },
            hardware_audio=end.memory.load(0xFF10, 23),
            command_byte=inputs["command_byte"],
            continuation=claripy.BVV(13, 8),
            constraints=tuple(end.solver.constraints),
        )
        for end in _all_handler_boundaries(project, state, {boundary})
    ]


def _note_native(
    symbol: str,
    inputs: dict[str, object],
    channel: int,
    category: str,
    command_high: int | None,
    play_enabled: bool | None,
) -> list[NoteEndpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(symbol)
    assert function is not None
    play = project.loader.find_symbol("port_audio_note_play_sound")
    assert play is not None
    project.hook(play.rebased_addr, NativeNotePlaySoundSummary())
    variant = int(symbol[10])
    bank = symbol_location(SYMBOLS, f"SFX_Headers_{variant}").bank
    header_data = rom_window(ROM, bank).getvalue()[0x4000 : 0x4310]
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)  # type: ignore[arg-type]
    state.memory.store(NATIVE_STATE + 8, inputs["audio_ram"])
    if play_enabled is not None:
        state.memory.store(NATIVE_STATE + 11, 0 if play_enabled else 1)
    state.memory.store(NATIVE_STATE + 251, inputs["hardware_audio"])
    state.memory.store(NATIVE_STATE + 274, header_data)
    state.memory.store(NATIVE_STATE + 1058, inputs["command_byte"])
    state.memory.store(NATIVE_STATE + 1059, inputs["continuation"])
    state.globals["unknown_ef_play_outputs"] = inputs["play_outputs"]
    _constrain_note_category(
        state, inputs, channel, category, command_high, play_enabled
    )
    if category == "drum":
        pointer = claripy.Concat(
            inputs["audio_ram"].get_byte(6 + channel * 2 + 1),
            inputs["audio_ram"].get_byte(6 + channel * 2),
        )
        state.solver.add(pointer.UGE(0x4000), pointer.ULE(0x7FFF))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        NoteEndpoint(
            **native_registers(end, NATIVE_STATE),
            **{
                f"audio_ram_{index}": end.memory.load(
                    NATIVE_STATE + 8 + index * 32,
                    32 if index != 7 else 19,
                )
                for index in range(8)
            },
            hardware_audio=end.memory.load(NATIVE_STATE + 251, 23),
            command_byte=end.memory.load(NATIVE_STATE + 1058, 1),
            continuation=end.memory.load(NATIVE_STATE + 1059, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


def test_native_note_delay_arithmetic_complete_domain() -> None:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_audio_note_delay_arithmetic")
    assert function is not None
    for factor in range(256):
        tempo = claripy.BVS(f"note_delay_tempo_{factor}", 16)
        fractional = claripy.BVS(f"note_delay_fractional_{factor}", 8)
        state = project.factory.call_state(
            function.rebased_addr,
            claripy.BVV(factor, 64),
            claripy.ZeroExt(48, tempo),
            claripy.ZeroExt(56, fractional),
        )
        manager = project.factory.simulation_manager(state)
        manager.run()
        assert not manager.errored
        assert len(manager.deadended) == 1
        result = manager.deadended[0].regs.rax[15:0]
        expected = (
            claripy.BVV(factor, 16) * tempo
            + claripy.ZeroExt(8, fractional)
        )[15:0]
        solver = claripy.Solver()
        solver.add(result != expected)
        assert not solver.satisfiable(), f"factor {factor:#04x}"


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("assembly_symbol", "c_symbol"),
    [
        ("Audio1_IsCry", "port_audio1_is_cry"),
        ("Audio2_IsCry", "port_audio2_is_cry"),
        ("Audio3_IsCry", "port_audio3_is_cry"),
    ],
)
def test_audio_is_cry_symbolic_equivalence(
    assembly_symbol: str, c_symbol: str
) -> None:
    inputs = symbolic_registers(assembly_symbol)
    inputs["sound_id"] = claripy.BVS(f"{assembly_symbol}_sound_id", 8)
    assert_pathwise_equivalent(
        _assembly_endpoints(assembly_symbol, inputs),
        _native_endpoints(c_symbol, inputs),
        (*REGISTERS, "sound_id"),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_audio2_is_battle_sfx_symbolic_equivalence() -> None:
    inputs = symbolic_registers("Audio2_IsBattleSFX")
    inputs["sound5"] = claripy.BVS("Audio2_IsBattleSFX_sound5", 8)
    inputs["sound8"] = claripy.BVS("Audio2_IsBattleSFX_sound8", 8)
    assert_pathwise_equivalent(
        _battle_sfx_assembly(inputs),
        _battle_sfx_native(inputs),
        (*REGISTERS, "sound5", "sound8"),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("assembly_symbol", "c_symbol", "channel"),
    [
        (f"Audio{variant}_EnableChannelOutput", f"port_audio{variant}_enable_channel_output", channel)
        for variant in (1, 2, 3)
        for channel in range(8)
    ],
)
def test_enable_channel_output_symbolic_equivalence(
    assembly_symbol: str, c_symbol: str, channel: int
) -> None:
    prefix = f"{assembly_symbol}_{channel}"
    inputs = symbolic_registers(prefix)
    inputs["c"] = claripy.BVV(channel, 8)
    inputs["audio_terminal"] = claripy.BVS(f"{prefix}_audio_terminal", 8)
    inputs["stereo_panning"] = claripy.BVS(f"{prefix}_stereo_panning", 8)
    inputs["sfx_sound_ids"] = claripy.BVS(f"{prefix}_sfx_sound_ids", 32)
    assert_pathwise_equivalent(
        _channel_output_assembly(assembly_symbol, inputs),
        _channel_output_native(c_symbol, inputs),
        (*REGISTERS, "audio_terminal", "stereo_panning", "sfx_sound_ids"),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("assembly_symbol", "c_symbol"),
    [
        ("Audio1_MultiplyAdd", "port_audio1_multiply_add"),
    ],
)
def test_audio_multiply_add_symbolic_equivalence(
    assembly_symbol: str, c_symbol: str
) -> None:
    for multiplier in range(256):
        prefix = f"{assembly_symbol}_{multiplier}"
        inputs = symbolic_registers(prefix)
        inputs["a"] = claripy.BVV(multiplier, 8)
        try:
            assert_pathwise_equivalent(
                [_multiply_add_assembly(assembly_symbol, inputs)],
                [_multiply_add_native(c_symbol, inputs)],
                REGISTERS,
            )
        except AssertionError as error:
            raise AssertionError(f"multiplier {multiplier:#04x}: {error}") from error


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
def test_audio_multiply_add_native_variants_are_byte_identical() -> None:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    bodies = []
    for symbol in (
        "port_audio1_multiply_add",
        "port_audio2_multiply_add",
        "port_audio3_multiply_add",
    ):
        function = project.loader.find_symbol(symbol)
        assert function is not None
        bodies.append(project.loader.memory.load(function.rebased_addr, 76))
    assert bodies[0] == bodies[1] == bodies[2]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("assembly_symbol", "c_symbol", "channel"),
    [
        (f"Audio{variant}_GetRegisterPointer", f"port_audio{variant}_get_register_pointer", channel)
        for variant in (1, 2, 3)
        for channel in range(8)
    ],
)
def test_audio_get_register_pointer_symbolic_equivalence(
    assembly_symbol: str, c_symbol: str, channel: int
) -> None:
    prefix = f"{assembly_symbol}_{channel}"
    inputs = symbolic_registers(prefix)
    inputs["c"] = claripy.BVV(channel, 8)
    assert_pathwise_equivalent(
        [_register_pointer_assembly(assembly_symbol, inputs)],
        [_multiply_add_native(c_symbol, inputs)],
        REGISTERS,
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("assembly_symbol", "c_symbol"),
    [
        ("Audio1_CalculateFrequency", "port_audio1_calculate_frequency"),
        ("Audio2_CalculateFrequency", "port_audio2_calculate_frequency"),
        ("Audio3_CalculateFrequency", "port_audio3_calculate_frequency"),
    ],
)
def test_audio_calculate_frequency_symbolic_equivalence(
    assembly_symbol: str, c_symbol: str
) -> None:
    for note in range(12):
        for octave in range(8):
            prefix = f"{assembly_symbol}_{note}_{octave}"
            inputs = symbolic_registers(prefix)
            inputs["a"] = claripy.BVV(note, 8)
            inputs["b"] = claripy.BVV(octave, 8)
            try:
                assert_pathwise_equivalent(
                    [_calculate_frequency_assembly(assembly_symbol, inputs)],
                    [_multiply_add_native(c_symbol, inputs)],
                    REGISTERS,
                )
            except AssertionError as error:
                raise AssertionError(
                    f"note {note}, encoded octave {octave}: {error}"
                ) from error


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("assembly_symbol", "c_symbol", "channel"),
    [
        (
            f"Audio{variant}_ApplyDutyCyclePattern",
            f"port_audio{variant}_apply_duty_cycle_pattern",
            channel,
        )
        for variant in (1, 2, 3)
        for channel in range(8)
    ],
)
def test_audio_apply_duty_cycle_pattern_symbolic_equivalence(
    assembly_symbol: str, c_symbol: str, channel: int
) -> None:
    prefix = f"{assembly_symbol}_{channel}"
    inputs = symbolic_registers(prefix)
    inputs["c"] = claripy.BVV(channel, 8)
    inputs["duty_patterns"] = claripy.BVS(f"{prefix}_duty_patterns", 64)
    inputs["hardware_registers"] = claripy.BVS(f"{prefix}_hardware", 32)
    assert_pathwise_equivalent(
        [_duty_pattern_assembly(assembly_symbol, inputs)],
        [_duty_pattern_native(c_symbol, inputs)],
        (*REGISTERS, "duty_patterns", "hardware_registers"),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("assembly_symbol", "c_symbol", "channel"),
    [
        (
            f"Audio{variant}_ApplyDutyCycleAndSoundLength",
            f"port_audio{variant}_apply_duty_cycle_and_sound_length",
            channel,
        )
        for variant in (1, 2, 3)
        for channel in range(8)
    ],
)
def test_audio_apply_duty_cycle_and_sound_length_symbolic_equivalence(
    assembly_symbol: str, c_symbol: str, channel: int
) -> None:
    prefix = f"{assembly_symbol}_{channel}"
    inputs = symbolic_registers(prefix)
    inputs["c"] = claripy.BVV(channel, 8)
    inputs["note_delays"] = claripy.BVS(f"{prefix}_note_delays", 64)
    inputs["duty_cycles"] = claripy.BVS(f"{prefix}_duty_cycles", 64)
    inputs["hardware_registers"] = claripy.BVS(f"{prefix}_hardware", 32)
    assert_pathwise_equivalent(
        [_duty_length_assembly(assembly_symbol, inputs)],
        [_duty_length_native(c_symbol, inputs)],
        (
            *REGISTERS,
            "note_delays",
            "duty_cycles",
            "hardware_registers",
        ),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_audio2_reset_cry_modifiers_symbolic_equivalence() -> None:
    inputs = symbolic_registers("Audio2_ResetCryModifiers")
    inputs["low_health_alarm"] = claripy.BVS("reset_cry_low_health", 8)
    inputs["frequency_modifier"] = claripy.BVS("reset_cry_frequency", 8)
    inputs["tempo_modifier"] = claripy.BVS("reset_cry_tempo", 8)
    assert_pathwise_equivalent(
        _reset_cry_modifiers_assembly(inputs),
        _reset_cry_modifiers_native(inputs),
        (
            *REGISTERS,
            "low_health_alarm",
            "frequency_modifier",
            "tempo_modifier",
        ),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("assembly_symbol", "c_symbol"),
    [
        (f"Audio{variant}_SetSfxTempo", f"port_audio{variant}_set_sfx_tempo")
        for variant in (1, 2, 3)
    ],
)
def test_audio_set_sfx_tempo_symbolic_equivalence(
    assembly_symbol: str, c_symbol: str
) -> None:
    inputs = symbolic_registers(assembly_symbol)
    inputs["sound5"] = claripy.BVS(f"{assembly_symbol}_sound5", 8)
    inputs["sound8"] = claripy.BVS(f"{assembly_symbol}_sound8", 8)
    inputs["tempo_modifier"] = claripy.BVS(f"{assembly_symbol}_modifier", 8)
    inputs["sfx_tempo_high"] = claripy.BVS(f"{assembly_symbol}_tempo_high", 8)
    inputs["sfx_tempo_low"] = claripy.BVS(f"{assembly_symbol}_tempo_low", 8)
    assert_pathwise_equivalent(
        _set_sfx_tempo_assembly(assembly_symbol, inputs),
        _set_sfx_tempo_native(c_symbol, inputs),
        (
            *REGISTERS,
            "sound5",
            "sound8",
            "tempo_modifier",
            "sfx_tempo_high",
            "sfx_tempo_low",
        ),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("assembly_symbol", "c_symbol", "hardware_index"),
    [
        (
            f"Audio{variant}_ApplyFrequencyModifier",
            f"port_audio{variant}_apply_frequency_modifier",
            hardware_index,
        )
        for variant in (1, 2, 3)
        for hardware_index in range(4)
    ],
)
def test_audio_apply_frequency_modifier_symbolic_equivalence(
    assembly_symbol: str, c_symbol: str, hardware_index: int
) -> None:
    prefix = f"{assembly_symbol}_{hardware_index}"
    inputs = symbolic_registers(prefix)
    high_address = 0xFF14 + hardware_index * 5
    inputs["h"] = claripy.BVV(high_address >> 8, 8)
    inputs["l"] = claripy.BVV(high_address & 0xFF, 8)
    inputs["sound5"] = claripy.BVS(f"{prefix}_sound5", 8)
    inputs["sound8"] = claripy.BVS(f"{prefix}_sound8", 8)
    inputs["frequency_modifier"] = claripy.BVS(f"{prefix}_modifier", 8)
    inputs["hardware_registers"] = claripy.BVS(f"{prefix}_hardware", 64)
    assert_pathwise_equivalent(
        _apply_frequency_modifier_assembly(assembly_symbol, inputs),
        _apply_frequency_modifier_native(c_symbol, inputs),
        (
            *REGISTERS,
            "sound5",
            "sound8",
            "frequency_modifier",
            "hardware_registers",
        ),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("assembly_symbol", "c_symbol", "channel", "instrument"),
    [
        (
            f"Audio{variant}_ApplyWavePatternAndFrequency",
            f"port_audio{variant}_apply_wave_pattern_and_frequency",
            channel,
            instrument,
        )
        for variant in (1, 2, 3)
        for channel in range(8)
        for instrument in (range(9) if channel in (2, 6) else (-1,))
    ],
)
def test_audio_apply_wave_pattern_and_frequency_symbolic_equivalence(
    assembly_symbol: str, c_symbol: str, channel: int, instrument: int
) -> None:
    prefix = f"{assembly_symbol}_{channel}_{instrument}"
    inputs = symbolic_registers(prefix)
    inputs["c"] = claripy.BVV(channel, 8)
    inputs["music_instrument"] = claripy.BVS(f"{prefix}_music_wave", 8)
    inputs["sfx_instrument"] = claripy.BVS(f"{prefix}_sfx_wave", 8)
    if channel == 2:
        inputs["music_instrument"] = claripy.BVV(instrument, 8)
    elif channel == 6:
        inputs["sfx_instrument"] = claripy.BVV(instrument, 8)
    inputs["sound5"] = claripy.BVS(f"{prefix}_sound5", 8)
    inputs["sound8"] = claripy.BVS(f"{prefix}_sound8", 8)
    inputs["frequency_modifier"] = claripy.BVS(f"{prefix}_modifier", 8)
    inputs["audio3_enable"] = claripy.BVS(f"{prefix}_audio3_enable", 8)
    inputs["wave_ram"] = claripy.BVS(f"{prefix}_wave_ram", 128)
    inputs["hardware_registers"] = claripy.BVS(f"{prefix}_hardware", 64)
    assert_pathwise_equivalent(
        _wave_frequency_assembly(assembly_symbol, inputs),
        _wave_frequency_native(c_symbol, inputs),
        (
            *REGISTERS,
            "music_instrument",
            "sfx_instrument",
            "sound5",
            "sound8",
            "frequency_modifier",
            "audio3_enable",
            "wave_ram",
            "hardware_registers",
        ),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("assembly_symbol", "c_symbol", "channel"),
    [
        (
            f"Audio{variant}_GoBackOneCommandIfCry",
            f"port_audio{variant}_go_back_one_command_if_cry",
            channel,
        )
        for variant in (1, 2, 3)
        for channel in range(8)
    ],
)
def test_audio_go_back_one_command_if_cry_symbolic_equivalence(
    assembly_symbol: str, c_symbol: str, channel: int
) -> None:
    prefix = f"{assembly_symbol}_{channel}"
    inputs = symbolic_registers(prefix)
    inputs["c"] = claripy.BVV(channel, 8)
    inputs["sound5"] = claripy.BVS(f"{prefix}_sound5", 8)
    inputs["command_pointers"] = claripy.BVS(f"{prefix}_pointers", 128)
    assert_pathwise_equivalent(
        _command_rewind_assembly(assembly_symbol, inputs),
        _command_rewind_native(c_symbol, inputs),
        (*REGISTERS, "sound5", "command_pointers"),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("assembly_symbol", "c_symbol", "channel"),
    [
        (
            f"Audio{variant}_GetNextMusicByte",
            f"port_audio{variant}_get_next_music_byte",
            channel,
        )
        for variant in (1, 2, 3)
        for channel in range(8)
    ],
)
def test_audio_get_next_music_byte_symbolic_equivalence(
    assembly_symbol: str, c_symbol: str, channel: int
) -> None:
    prefix = f"{assembly_symbol}_{channel}"
    inputs = symbolic_registers(prefix)
    inputs["c"] = claripy.BVV(channel, 8)
    inputs["command_pointers"] = claripy.BVS(f"{prefix}_pointers", 128)
    inputs["command_byte"] = claripy.BVS(f"{prefix}_command_byte", 8)
    assert_pathwise_equivalent(
        [_next_music_byte_assembly(assembly_symbol, inputs, channel)],
        [_next_music_byte_native(c_symbol, inputs, channel)],
        (*REGISTERS, "command_pointers", "command_byte"),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("assembly_symbol", "c_symbol", "channel", "decreasing"),
    [
        (
            f"Audio{variant}_ApplyPitchSlide",
            f"port_audio{variant}_apply_pitch_slide",
            channel,
            decreasing,
        )
        for variant in (1, 2, 3)
        for channel in range(8)
        for decreasing in (False, True)
    ],
)
def test_audio_apply_pitch_slide_symbolic_equivalence(
    assembly_symbol: str, c_symbol: str, channel: int, decreasing: bool
) -> None:
    prefix = f"{assembly_symbol}_{channel}_{int(decreasing)}"
    inputs = symbolic_registers(prefix)
    inputs["b"] = claripy.BVV(0, 8)
    inputs["c"] = claripy.BVV(channel, 8)
    for name in (
        "flags1",
        "frequency_steps",
        "frequency_steps_fractional",
        "current_frequency_fractional",
        "current_frequency_high",
        "current_frequency_low",
        "target_frequency_high",
        "target_frequency_low",
    ):
        inputs[name] = claripy.BVS(f"{prefix}_{name}", 64)
    inputs["hardware_registers"] = claripy.BVS(f"{prefix}_hardware", 64)
    assert_pathwise_equivalent(
        _pitch_slide_assembly(assembly_symbol, inputs, channel, decreasing),
        _pitch_slide_native(c_symbol, inputs, channel, decreasing),
        (
            *REGISTERS,
            "flags1",
            "frequency_steps",
            "frequency_steps_fractional",
            "current_frequency_fractional",
            "current_frequency_high",
            "current_frequency_low",
            "target_frequency_high",
            "target_frequency_low",
            "hardware_registers",
        ),
    )


def test_pitch_slide_divide_loop_summary_is_inductive() -> None:
    remaining = claripy.BVS("pitch_div_remaining", 16)
    divisor = claripy.BVS("pitch_div_divisor", 8)
    divisor16 = claripy.ZeroExt(8, divisor)
    low = remaining[7:0]
    high = remaining[15:8]
    borrow = low.ULT(divisor)
    exits = claripy.And(borrow, high == 0)

    solver = claripy.Solver()
    solver.add(divisor != 0)
    solver.add(exits != remaining.ULT(divisor16))
    assert not solver.satisfiable()

    next_low = low - divisor
    next_high = claripy.If(borrow, high - 1, high)
    solver = claripy.Solver()
    solver.add(divisor != 0, claripy.Not(exits))
    solver.add(claripy.Concat(next_high, next_low) != remaining - divisor16)
    assert not solver.satisfiable()

    quotient = remaining // divisor16
    remainder = remaining % divisor16
    solver = claripy.Solver()
    solver.add(divisor != 0)
    solver.add(
        claripy.Or(
            remaining != quotient * divisor16 + remainder,
            remainder.UGE(divisor16),
        )
    )
    assert not solver.satisfiable()


def test_pitch_slide_divide_loop_summary_exhaustive_legal_domain() -> None:
    for difference in range(0x900):
        for divisor in range(1, 256):
            d = difference >> 8
            e = difference & 0xFF
            b = 0
            while True:
                b = (b + 1) & 0xFF
                raw = e - divisor
                e = raw & 0xFF
                if raw >= 0:
                    continue
                if d == 0:
                    break
                d = (d - 1) & 0xFF

            quotient, remainder = divmod(difference, divisor)
            assert b == (quotient + 1) & 0xFF
            assert e == (remainder - divisor) & 0xFF


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("assembly_symbol", "c_symbol", "channel"),
    [
        (
            "Audio1_InitPitchSlideVars",
            "port_audio1_init_pitch_slide_vars",
            channel,
        )
        for channel in range(8)
    ],
)
def test_audio_init_pitch_slide_vars_symbolic_equivalence(
    assembly_symbol: str, c_symbol: str, channel: int
) -> None:
    prefix = f"{assembly_symbol}_{channel}"
    inputs = symbolic_registers(prefix)
    inputs["b"] = claripy.BVV(0, 8)
    inputs["c"] = claripy.BVV(channel, 8)
    for name in (
        "flags1",
        "note_delays",
        "length_modifiers",
        "frequency_steps",
        "frequency_steps_fractional",
        "current_frequency_fractional",
        "current_frequency_high",
        "current_frequency_low",
        "target_frequency_high",
        "target_frequency_low",
    ):
        inputs[name] = claripy.BVS(f"{prefix}_{name}", 64)
    assert_pathwise_equivalent(
        _init_pitch_slide_assembly(assembly_symbol, inputs, channel),
        _init_pitch_slide_native(c_symbol, inputs, channel),
        (
            *REGISTERS,
            "flags1",
            "note_delays",
            "length_modifiers",
            "frequency_steps",
            "frequency_steps_fractional",
            "current_frequency_fractional",
            "current_frequency_high",
            "current_frequency_low",
            "target_frequency_high",
            "target_frequency_low",
        ),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
def test_audio_init_pitch_slide_native_variants_are_aliases() -> None:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    addresses = []
    for symbol in (
        "port_audio1_init_pitch_slide_vars",
        "port_audio2_init_pitch_slide_vars",
        "port_audio3_init_pitch_slide_vars",
    ):
        function = project.loader.find_symbol(symbol)
        assert function is not None
        addresses.append(function.rebased_addr)
    assert addresses[0] == addresses[1] == addresses[2]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("assembly_symbol", "c_symbol", "channel"),
    [
        (
            f"Audio{variant}_execute_music",
            f"port_audio{variant}_execute_music",
            channel,
        )
        for variant in (1, 2, 3)
        for channel in range(8)
    ],
)
def test_audio_execute_music_symbolic_equivalence(
    assembly_symbol: str, c_symbol: str, channel: int
) -> None:
    prefix = f"{assembly_symbol}_{channel}"
    inputs = symbolic_registers(prefix)
    inputs["c"] = claripy.BVV(channel, 8)
    inputs["flags2"] = claripy.BVS(f"{prefix}_flags2", 64)
    inputs["continuation"] = claripy.BVS(f"{prefix}_continuation", 8)
    assert_pathwise_equivalent(
        _execute_music_assembly(assembly_symbol, inputs),
        _execute_music_native(c_symbol, inputs),
        (*REGISTERS, "flags2", "continuation"),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("assembly_symbol", "c_symbol", "channel"),
    [
        (f"Audio{variant}_octave", f"port_audio{variant}_octave", channel)
        for variant in (1, 2, 3)
        for channel in range(8)
    ],
)
def test_audio_octave_symbolic_equivalence(
    assembly_symbol: str, c_symbol: str, channel: int
) -> None:
    prefix = f"{assembly_symbol}_{channel}"
    inputs = symbolic_registers(prefix)
    inputs["c"] = claripy.BVV(channel, 8)
    inputs["octaves"] = claripy.BVS(f"{prefix}_octaves", 64)
    inputs["continuation"] = claripy.BVS(f"{prefix}_continuation", 8)
    assert_pathwise_equivalent(
        _octave_assembly(assembly_symbol, inputs),
        _octave_native(c_symbol, inputs),
        (*REGISTERS, "octaves", "continuation"),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("assembly_symbol", "c_symbol", "channel"),
    [
        (f"Audio{variant}_duty_cycle", f"port_audio{variant}_duty_cycle", channel)
        for variant in (1, 2, 3)
        for channel in range(8)
    ],
)
def test_audio_duty_cycle_command_symbolic_equivalence(
    assembly_symbol: str, c_symbol: str, channel: int
) -> None:
    prefix = f"{assembly_symbol}_{channel}"
    inputs = symbolic_registers(prefix)
    inputs["c"] = claripy.BVV(channel, 8)
    inputs["command_pointers"] = claripy.BVS(f"{prefix}_pointers", 128)
    inputs["command_byte"] = claripy.BVS(f"{prefix}_command_byte", 8)
    inputs["duty_cycles"] = claripy.BVS(f"{prefix}_duty_cycles", 64)
    inputs["continuation"] = claripy.BVS(f"{prefix}_continuation", 8)
    assert_pathwise_equivalent(
        _duty_command_assembly(assembly_symbol, inputs, channel),
        _duty_command_native(c_symbol, inputs, channel),
        (
            *REGISTERS,
            "command_pointers",
            "command_byte",
            "duty_cycles",
            "continuation",
        ),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    (
        "assembly_symbol",
        "c_symbol",
        "channel",
        "expected",
        "next_name",
        "continuation",
    ),
    [
        (
            f"Audio{variant}_{name}",
            f"port_audio{variant}_{name}",
            channel,
            expected,
            next_name,
            continuation,
        )
        for variant in (1, 2, 3)
        for name, expected, next_name, continuation in (
            ("stereo_panning", 0xEE, "unknownmusic0xef", 5),
            ("volume", 0xF0, "execute_music", 6),
        )
        for channel in range(8)
    ],
)
def test_audio_byte_command_symbolic_equivalence(
    assembly_symbol: str,
    c_symbol: str,
    channel: int,
    expected: int,
    next_name: str,
    continuation: int,
) -> None:
    prefix = f"{assembly_symbol}_{channel}"
    inputs = symbolic_registers(prefix)
    inputs["c"] = claripy.BVV(channel, 8)
    inputs["command_pointers"] = claripy.BVS(f"{prefix}_pointers", 128)
    inputs["command_byte"] = claripy.BVS(f"{prefix}_command_byte", 8)
    inputs["value"] = claripy.BVS(f"{prefix}_value", 8)
    inputs["continuation"] = claripy.BVS(f"{prefix}_continuation", 8)
    assert_pathwise_equivalent(
        _byte_command_assembly(
            assembly_symbol,
            inputs,
            channel,
            expected,
            next_name,
            continuation,
        ),
        _byte_command_native(c_symbol, inputs, channel),
        (
            *REGISTERS,
            "command_pointers",
            "command_byte",
            "value",
            "continuation",
        ),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("assembly_symbol", "c_symbol", "channel"),
    [
        (
            f"Audio{variant}_duty_cycle_pattern",
            f"port_audio{variant}_duty_cycle_pattern",
            channel,
        )
        for variant in (1, 2, 3)
        for channel in range(8)
    ],
)
def test_audio_duty_pattern_command_symbolic_equivalence(
    assembly_symbol: str, c_symbol: str, channel: int
) -> None:
    prefix = f"{assembly_symbol}_{channel}"
    inputs = symbolic_registers(prefix)
    inputs["c"] = claripy.BVV(channel, 8)
    inputs["command_pointers"] = claripy.BVS(f"{prefix}_pointers", 128)
    inputs["command_byte"] = claripy.BVS(f"{prefix}_command_byte", 8)
    inputs["duty_patterns"] = claripy.BVS(f"{prefix}_patterns", 64)
    inputs["duty_cycles"] = claripy.BVS(f"{prefix}_duties", 64)
    inputs["flags1"] = claripy.BVS(f"{prefix}_flags1", 64)
    inputs["continuation"] = claripy.BVS(f"{prefix}_continuation", 8)
    assert_pathwise_equivalent(
        _duty_pattern_command_assembly(assembly_symbol, inputs, channel),
        _duty_pattern_command_native(c_symbol, inputs, channel),
        (
            *REGISTERS,
            "command_pointers",
            "command_byte",
            "duty_patterns",
            "duty_cycles",
            "flags1",
            "continuation",
        ),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("assembly_symbol", "c_symbol", "channel"),
    [
        (f"Audio{variant}_tempo", f"port_audio{variant}_tempo", channel)
        for variant in (1, 2, 3)
        for channel in range(8)
    ],
)
def test_audio_tempo_command_symbolic_equivalence(
    assembly_symbol: str, c_symbol: str, channel: int
) -> None:
    prefix = f"{assembly_symbol}_{channel}"
    inputs = symbolic_registers(prefix)
    inputs["c"] = claripy.BVV(channel, 8)
    inputs["command_pointers"] = claripy.BVS(f"{prefix}_pointers", 128)
    inputs["command_bytes"] = claripy.BVS(f"{prefix}_command_bytes", 16)
    inputs["command_byte"] = inputs["command_bytes"].get_byte(0)
    inputs["music_tempo"] = claripy.BVS(f"{prefix}_music_tempo", 16)
    inputs["sfx_tempo"] = claripy.BVS(f"{prefix}_sfx_tempo", 16)
    inputs["fractional_note_delays"] = claripy.BVS(
        f"{prefix}_fractional", 64
    )
    inputs["continuation"] = claripy.BVS(f"{prefix}_continuation", 8)
    assert_pathwise_equivalent(
        _tempo_command_assembly(assembly_symbol, inputs, channel),
        _tempo_command_native(c_symbol, inputs, channel),
        (
            *REGISTERS,
            "command_pointers",
            "command_bytes",
            "music_tempo",
            "sfx_tempo",
            "fractional_note_delays",
            "continuation",
        ),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("assembly_symbol", "c_symbol", "channel"),
    [
        (
            f"Audio{variant}_toggle_perfect_pitch",
            f"port_audio{variant}_toggle_perfect_pitch",
            channel,
        )
        for variant in (1, 2, 3)
        for channel in range(8)
    ],
)
def test_audio_toggle_perfect_pitch_symbolic_equivalence(
    assembly_symbol: str, c_symbol: str, channel: int
) -> None:
    prefix = f"{assembly_symbol}_{channel}"
    inputs = symbolic_registers(prefix)
    inputs["c"] = claripy.BVV(channel, 8)
    inputs["flags1"] = claripy.BVS(f"{prefix}_flags1", 64)
    inputs["continuation"] = claripy.BVS(f"{prefix}_continuation", 8)
    assert_pathwise_equivalent(
        _toggle_perfect_pitch_assembly(assembly_symbol, inputs),
        _toggle_perfect_pitch_native(c_symbol, inputs),
        (*REGISTERS, "flags1", "continuation"),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("assembly_symbol", "c_symbol", "channel"),
    [
        (f"Audio{variant}_vibrato", f"port_audio{variant}_vibrato", channel)
        for variant in (1, 2, 3)
        for channel in range(8)
    ],
)
def test_audio_vibrato_command_symbolic_equivalence(
    assembly_symbol: str, c_symbol: str, channel: int
) -> None:
    prefix = f"{assembly_symbol}_{channel}"
    inputs = symbolic_registers(prefix)
    inputs["c"] = claripy.BVV(channel, 8)
    inputs["command_pointers"] = claripy.BVS(f"{prefix}_pointers", 128)
    inputs["command_bytes"] = claripy.BVS(f"{prefix}_command_bytes", 16)
    inputs["command_byte"] = inputs["command_bytes"].get_byte(0)
    for name in ("delay_counters", "delay_reloads", "extents", "rates"):
        inputs[name] = claripy.BVS(f"{prefix}_{name}", 64)
    inputs["continuation"] = claripy.BVS(f"{prefix}_continuation", 8)
    assert_pathwise_equivalent(
        _vibrato_command_assembly(assembly_symbol, inputs, channel),
        _vibrato_command_native(c_symbol, inputs, channel),
        (
            *REGISTERS,
            "command_pointers",
            "command_bytes",
            "delay_counters",
            "delay_reloads",
            "extents",
            "rates",
            "continuation",
        ),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("assembly_symbol", "c_symbol", "channel"),
    [
        (
            f"Audio{variant}_pitch_sweep",
            f"port_audio{variant}_pitch_sweep",
            channel,
        )
        for variant in (1, 2, 3)
        for channel in range(8)
    ],
)
def test_audio_pitch_sweep_symbolic_equivalence(
    assembly_symbol: str, c_symbol: str, channel: int
) -> None:
    prefix = f"{assembly_symbol}_{channel}"
    inputs = symbolic_registers(prefix)
    inputs["c"] = claripy.BVV(channel, 8)
    inputs["command_pointers"] = claripy.BVS(f"{prefix}_pointers", 128)
    inputs["command_byte"] = claripy.BVS(f"{prefix}_command_byte", 8)
    inputs["flags2"] = claripy.BVS(f"{prefix}_flags2", 64)
    inputs["sweep"] = claripy.BVS(f"{prefix}_sweep", 8)
    inputs["continuation"] = claripy.BVS(f"{prefix}_continuation", 8)
    assert_pathwise_equivalent(
        _pitch_sweep_assembly(assembly_symbol, inputs, channel),
        _pitch_sweep_native(c_symbol, inputs, channel),
        (
            *REGISTERS,
            "command_pointers",
            "command_byte",
            "flags2",
            "sweep",
            "continuation",
        ),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("assembly_symbol", "c_symbol", "channel"),
    [
        (
            f"Audio{variant}_pitch_slide",
            f"port_audio{variant}_pitch_slide",
            channel,
        )
        for variant in (1, 2, 3)
        for channel in range(8)
    ],
)
def test_audio_pitch_slide_command_symbolic_equivalence(
    assembly_symbol: str, c_symbol: str, channel: int
) -> None:
    prefix = f"{assembly_symbol}_{channel}"
    inputs = symbolic_registers(prefix)
    inputs["c"] = claripy.BVV(channel, 8)
    inputs["command_pointers"] = claripy.BVS(f"{prefix}_pointers", 128)
    inputs["command_bytes"] = claripy.BVS(f"{prefix}_command_bytes", 24)
    for name in (
        "length_modifiers",
        "target_frequency_high",
        "target_frequency_low",
        "flags1",
    ):
        inputs[name] = claripy.BVS(f"{prefix}_{name}", 64)
    inputs["continuation"] = claripy.BVS(f"{prefix}_continuation", 8)
    assert_pathwise_equivalent(
        _pitch_slide_command_assembly(assembly_symbol, inputs, channel),
        _pitch_slide_command_native(c_symbol, inputs, channel),
        (
            *REGISTERS,
            "command_pointers",
            "command_bytes",
            "length_modifiers",
            "target_frequency_high",
            "target_frequency_low",
            "flags1",
            "continuation",
        ),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("assembly_symbol", "c_symbol", "channel"),
    [
        (f"Audio{variant}_note_type", f"port_audio{variant}_note_type", channel)
        for variant in (1, 2, 3)
        for channel in range(8)
    ],
)
def test_audio_note_type_symbolic_equivalence(
    assembly_symbol: str, c_symbol: str, channel: int
) -> None:
    prefix = f"{assembly_symbol}_{channel}"
    inputs = symbolic_registers(prefix)
    inputs["c"] = claripy.BVV(channel, 8)
    inputs["command_pointers"] = claripy.BVS(f"{prefix}_pointers", 128)
    inputs["command_byte"] = claripy.BVS(f"{prefix}_command_byte", 8)
    inputs["note_speeds"] = claripy.BVS(f"{prefix}_note_speeds", 64)
    inputs["volumes"] = claripy.BVS(f"{prefix}_volumes", 64)
    inputs["music_wave_instrument"] = claripy.BVS(f"{prefix}_music_wave", 8)
    inputs["sfx_wave_instrument"] = claripy.BVS(f"{prefix}_sfx_wave", 8)
    inputs["continuation"] = claripy.BVS(f"{prefix}_continuation", 8)
    assert_pathwise_equivalent(
        _note_type_assembly(assembly_symbol, inputs, channel),
        _note_type_native(c_symbol, inputs, channel),
        (
            *REGISTERS,
            "command_pointers",
            "command_byte",
            "note_speeds",
            "volumes",
            "music_wave_instrument",
            "sfx_wave_instrument",
            "continuation",
        ),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("assembly_symbol", "c_symbol", "channel"),
    [
        (
            f"Audio{variant}_sound_call",
            f"port_audio{variant}_sound_call",
            channel,
        )
        for variant in (1, 2, 3)
        for channel in range(8)
    ],
)
def test_audio_sound_call_symbolic_equivalence(
    assembly_symbol: str, c_symbol: str, channel: int
) -> None:
    prefix = f"{assembly_symbol}_{channel}"
    inputs = symbolic_registers(prefix)
    inputs["c"] = claripy.BVV(channel, 8)
    inputs["command_pointers"] = claripy.BVS(f"{prefix}_pointers", 128)
    inputs["command_bytes"] = claripy.BVS(f"{prefix}_command_bytes", 16)
    inputs["return_addresses"] = claripy.BVS(f"{prefix}_returns", 128)
    inputs["flags1"] = claripy.BVS(f"{prefix}_flags1", 64)
    inputs["continuation"] = claripy.BVS(f"{prefix}_continuation", 8)
    assert_pathwise_equivalent(
        _sound_call_assembly(assembly_symbol, inputs, channel),
        _sound_call_native(c_symbol, inputs, channel),
        (
            *REGISTERS,
            "command_pointers",
            "command_bytes",
            "return_addresses",
            "flags1",
            "continuation",
        ),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("assembly_symbol", "c_symbol", "channel"),
    [
        (
            f"Audio{variant}_sound_loop",
            f"port_audio{variant}_sound_loop",
            channel,
        )
        for variant in (1, 2, 3)
        for channel in range(8)
    ],
)
def test_audio_sound_loop_symbolic_equivalence(
    assembly_symbol: str, c_symbol: str, channel: int
) -> None:
    prefix = f"{assembly_symbol}_{channel}"
    inputs = symbolic_registers(prefix)
    inputs["c"] = claripy.BVV(channel, 8)
    inputs["command_pointers"] = claripy.BVS(f"{prefix}_pointers", 128)
    inputs["command_bytes"] = claripy.BVS(f"{prefix}_command_bytes", 24)
    inputs["loop_counters"] = claripy.BVS(f"{prefix}_loop_counters", 64)
    inputs["continuation"] = claripy.BVS(f"{prefix}_continuation", 8)
    assert_pathwise_equivalent(
        _sound_loop_assembly(assembly_symbol, inputs, channel),
        _sound_loop_native(c_symbol, inputs, channel),
        (
            *REGISTERS,
            "command_pointers",
            "command_bytes",
            "loop_counters",
            "continuation",
        ),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("assembly_symbol", "c_symbol", "channel", "length"),
    [
        (
            f"Audio{variant}_note_length",
            f"port_audio{variant}_note_length",
            channel,
            length,
        )
        for variant in (1, 2, 3)
        for channel in range(8)
        for length in range(1, 17)
    ],
)
def test_audio_note_length_symbolic_equivalence(
    assembly_symbol: str, c_symbol: str, channel: int, length: int
) -> None:
    prefix = f"{assembly_symbol}_{channel}_{length}"
    inputs = symbolic_registers(prefix)
    inputs["c"] = claripy.BVV(channel, 8)
    inputs["d"] = claripy.Concat(
        claripy.BVS(f"{prefix}_command_high", 4),
        claripy.BVV(length - 1, 4),
    )
    for name in (
        "note_speeds",
        "fractional_note_delays",
        "note_delays",
        "flags2",
        "flags1",
    ):
        inputs[name] = claripy.BVS(f"{prefix}_{name}", 64)
    inputs["music_tempo"] = claripy.BVS(f"{prefix}_music_tempo", 16)
    inputs["sfx_tempo"] = claripy.BVS(f"{prefix}_sfx_tempo", 16)
    for name in (
        "sound5",
        "sound8",
        "tempo_modifier",
        "saved_a",
        "saved_f",
        "continuation",
    ):
        inputs[name] = claripy.BVS(f"{prefix}_{name}", 8)
    assert_pathwise_equivalent(
        _note_length_assembly(assembly_symbol, inputs, channel),
        _note_length_native(c_symbol, inputs),
        (
            *REGISTERS,
            "note_speeds",
            "music_tempo",
            "sfx_tempo",
            "fractional_note_delays",
            "note_delays",
            "flags2",
            "flags1",
            "sound5",
            "sound8",
            "tempo_modifier",
            "saved_a",
            "saved_f",
            "continuation",
        ),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("assembly_symbol", "c_symbol", "channel", "rest", "pitch_slide"),
    [
        (
            f"Audio{variant}_note_pitch",
            f"port_audio{variant}_note_pitch",
            channel,
            rest,
            pitch_slide,
        )
        for variant in (1, 2, 3)
        for channel in range(8)
        for rest, pitch_slide in ((True, False), (False, False), (False, True))
    ],
)
def test_audio_note_pitch_symbolic_equivalence(
    assembly_symbol: str,
    c_symbol: str,
    channel: int,
    rest: bool,
    pitch_slide: bool,
) -> None:
    prefix = f"{assembly_symbol}_{channel}_{rest}_{pitch_slide}"
    inputs = symbolic_registers(prefix)
    # note_length is the sole entry and establishes BC = channel before this tail.
    inputs["b"] = claripy.BVV(0, 8)
    inputs["c"] = claripy.BVV(channel, 8)
    low_nibble = claripy.BVS(f"{prefix}_command_low", 4)
    inputs["saved_a"] = (
        claripy.Concat(claripy.BVV(0xC, 4), low_nibble)
        if rest
        else claripy.Concat(claripy.BVS(f"{prefix}_note", 4), low_nibble)
    )
    inputs["saved_f"] = claripy.Concat(
        claripy.BVS(f"{prefix}_saved_flags", 4), claripy.BVV(0, 4)
    )
    for name in (
        "octaves", "flags1", "volumes", "note_delays", "duty_cycles",
        "frequency_low_bytes", "length_modifiers", "frequency_steps",
        "frequency_steps_fractional", "current_frequency_fractional",
        "current_frequency_high", "current_frequency_low",
        "target_frequency_high", "target_frequency_low",
    ):
        inputs[name] = claripy.BVS(f"{prefix}_{name}", 64)
    inputs["sfx_sound_ids"] = claripy.BVS(f"{prefix}_sfx_sound_ids", 32)
    inputs["sound5"] = inputs["sfx_sound_ids"][31:24]
    inputs["sound8"] = inputs["sfx_sound_ids"][7:0]
    for name in ("hardware_envelopes", "hardware_duty"):
        inputs[name] = claripy.BVS(f"{prefix}_{name}", 32)
    inputs["hardware_frequency"] = claripy.BVS(
        f"{prefix}_hardware_frequency", 64
    )
    inputs["wave_ram"] = claripy.BVS(f"{prefix}_wave_ram", 128)
    for name in (
        "audio_terminal", "stereo_panning", "music_instrument",
        "sfx_instrument", "frequency_modifier", "audio3_enable",
    ):
        inputs[name] = claripy.BVS(f"{prefix}_{name}", 8)
    inputs["slide_outputs"] = {
        name: (
            claripy.Concat(
                claripy.BVS(f"{prefix}_slide_flags", 4), claripy.BVV(0, 4)
            )
            if name == "f"
            else claripy.BVS(f"{prefix}_slide_{name}", 8)
        )
        for name in (
            "a", "f", "b", "d", "e", "h", "l", "flags1",
            "length_modifiers", "frequency_steps",
            "frequency_steps_fractional", "current_frequency_fractional",
            "current_frequency_high", "current_frequency_low",
        )
    }
    observables = (
        *REGISTERS, "octaves", "flags1", "sfx_sound_ids", "volumes",
        "note_delays", "duty_cycles", "hardware_envelopes", "hardware_duty",
        "audio_terminal", "stereo_panning", "frequency_low_bytes",
        "music_instrument", "sfx_instrument", "sound5", "sound8",
        "frequency_modifier", "audio3_enable", "wave_ram",
        "hardware_frequency", "length_modifiers", "frequency_steps",
        "frequency_steps_fractional", "current_frequency_fractional",
        "current_frequency_high", "current_frequency_low",
        "target_frequency_high", "target_frequency_low",
    )
    assert_pathwise_equivalent(
        _note_pitch_assembly(
            assembly_symbol, inputs, channel, pitch_slide, rest
        ),
        _note_pitch_native(c_symbol, inputs, channel, pitch_slide, rest),
        observables,
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("assembly_symbol", "c_symbol", "channel"),
    [
        (
            f"Audio{variant}_PlayNextNote",
            f"port_audio{variant}_play_next_note",
            channel,
        )
        for variant in (1, 2, 3)
        for channel in range(8)
    ],
)
def test_audio_play_next_note_symbolic_equivalence(
    assembly_symbol: str, c_symbol: str, channel: int
) -> None:
    prefix = f"{assembly_symbol}_{channel}"
    inputs = symbolic_registers(prefix)
    inputs["b"] = claripy.BVV(0, 8)
    inputs["c"] = claripy.BVV(channel, 8)
    for name in ("vibrato_delay_reloads", "vibrato_delay_counters", "flags1"):
        inputs[name] = claripy.BVS(f"{prefix}_{name}", 64)
    inputs["low_health_alarm"] = claripy.BVS(f"{prefix}_low_health", 8)
    inputs["continuation"] = claripy.BVS(f"{prefix}_continuation", 8)
    assert_pathwise_equivalent(
        _play_next_note_assembly(assembly_symbol, inputs),
        _play_next_note_native(c_symbol, inputs),
        (
            *REGISTERS,
            "vibrato_delay_reloads",
            "vibrato_delay_counters",
            "flags1",
            "low_health_alarm",
            "continuation",
        ),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("assembly_symbol", "c_symbol", "channel"),
    [
        (f"Audio{variant}_sound_ret", f"port_audio{variant}_sound_ret", channel)
        for variant in (1, 2, 3)
        for channel in range(8)
    ],
)
def test_audio_sound_ret_symbolic_equivalence(
    assembly_symbol: str, c_symbol: str, channel: int
) -> None:
    prefix = f"{assembly_symbol}_{channel}"
    inputs = symbolic_registers(prefix)
    inputs["b"] = claripy.BVV(0, 8)
    inputs["c"] = claripy.BVV(channel, 8)
    inputs["command_pointers"] = claripy.BVS(f"{prefix}_pointers", 128)
    inputs["command_bytes"] = claripy.BVS(f"{prefix}_commands", 16)
    inputs["return_addresses"] = claripy.BVS(f"{prefix}_returns", 128)
    inputs["flags1"] = claripy.BVS(f"{prefix}_flags1", 64)
    inputs["flags2"] = claripy.BVS(f"{prefix}_flags2", 64)
    inputs["sound_ids"] = claripy.BVS(f"{prefix}_sound_ids", 64)
    for name in (
        "disable_channel_output", "audio3_enable", "audio_terminal",
        "saved_volume", "audio_volume", "continuation",
    ):
        inputs[name] = claripy.BVS(f"{prefix}_{name}", 8)
    assert_pathwise_equivalent(
        _sound_ret_assembly(assembly_symbol, inputs, channel),
        _sound_ret_native(c_symbol, inputs),
        (
            *REGISTERS, "command_pointers", "command_bytes",
            "return_addresses", "flags1", "flags2",
            "disable_channel_output", "audio3_enable", "audio_terminal",
            "sound_ids", "saved_volume", "audio_volume", "continuation",
        ),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("assembly_symbol", "c_symbol", "channel"),
    [
        (f"Audio{variant}_sfx_note", f"port_audio{variant}_sfx_note", channel)
        for variant in (1, 2, 3)
        for channel in range(8)
    ],
)
def test_audio_sfx_note_symbolic_equivalence(
    assembly_symbol: str, c_symbol: str, channel: int
) -> None:
    prefix = f"{assembly_symbol}_{channel}"
    inputs: dict[str, object] = symbolic_registers(prefix)
    inputs["b"] = claripy.BVV(0, 8)
    inputs["c"] = claripy.BVV(channel, 8)
    inputs["command_pointers"] = claripy.BVS(f"{prefix}_pointers", 128)
    inputs["command_bytes"] = claripy.BVS(f"{prefix}_commands", 24)
    for name in (
        "note_speeds", "fractional_note_delays", "note_delays", "flags2",
        "flags1", "sound_ids", "duty_cycles",
    ):
        inputs[name] = claripy.BVS(f"{prefix}_{name}", 64)
    inputs["music_tempo"] = claripy.BVS(f"{prefix}_music_tempo", 16)
    inputs["sfx_tempo"] = claripy.BVS(f"{prefix}_sfx_tempo", 16)
    for name in ("hardware_envelopes", "hardware_duty"):
        inputs[name] = claripy.BVS(f"{prefix}_{name}", 32)
    inputs["wave_ram"] = claripy.BVS(f"{prefix}_wave_ram", 128)
    inputs["hardware_frequency"] = claripy.BVS(
        f"{prefix}_hardware_frequency", 64
    )
    for name in (
        "tempo_modifier", "audio_terminal", "stereo_panning",
        "music_instrument", "sfx_instrument", "frequency_modifier",
        "audio3_enable", "continuation",
    ):
        inputs[name] = claripy.BVS(f"{prefix}_{name}", 8)
    length_outputs: dict[str, claripy.ast.BV] = symbolic_registers(
        f"{prefix}_length_post"
    )
    # note_length preserves the selected channel in C on every return path.
    length_outputs["c"] = claripy.BVV(channel, 8)
    for name, bits in (
        ("note_speeds", 64), ("music_tempo", 16), ("sfx_tempo", 16),
        ("fractional_note_delays", 64), ("note_delays", 64),
        ("flags2", 64), ("flags1", 64), ("sound5", 8), ("sound8", 8),
        ("tempo_modifier", 8),
    ):
        length_outputs[name] = claripy.BVS(f"{prefix}_length_post_{name}", bits)
    inputs["length_outputs"] = length_outputs
    assert_pathwise_equivalent(
        _sfx_note_assembly(assembly_symbol, inputs, channel),
        _sfx_note_native(c_symbol, inputs, channel),
        (
            *REGISTERS, "command_pointers", "command_bytes", "note_speeds",
            "music_tempo", "sfx_tempo", "fractional_note_delays",
            "note_delays", "flags2", "flags1", "sound_ids",
            "tempo_modifier", "duty_cycles", "hardware_envelopes",
            "hardware_duty", "audio_terminal", "stereo_panning",
            "music_instrument", "sfx_instrument", "frequency_modifier",
            "audio3_enable", "wave_ram", "hardware_frequency", "continuation",
        ),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("assembly_symbol", "c_symbol", "channel"),
    [
        (
            f"Audio{variant}_ApplyMusicAffects",
            f"port_audio{variant}_apply_music_affects",
            channel,
        )
        for variant in (1, 2, 3)
        for channel in range(8)
    ],
)
def test_audio_apply_music_affects_symbolic_equivalence(
    assembly_symbol: str, c_symbol: str, channel: int
) -> None:
    prefix = f"{assembly_symbol}_{channel}"
    inputs = symbolic_registers(prefix)
    inputs["b"] = claripy.BVV(0, 8)
    inputs["c"] = claripy.BVV(channel, 8)
    for name in (
        "note_delays", "sound_ids", "flags1", "flags2", "duty_patterns",
        "vibrato_delay_counters", "vibrato_extents", "vibrato_rates",
        "frequency_low_bytes",
    ):
        inputs[name] = claripy.BVS(f"{prefix}_{name}", 64)
    for name in ("hardware_duty", "hardware_frequency_low"):
        inputs[name] = claripy.BVS(f"{prefix}_{name}", 32)
    inputs["continuation"] = claripy.BVS(f"{prefix}_continuation", 8)
    assert_pathwise_equivalent(
        _apply_music_affects_assembly(assembly_symbol, inputs, channel),
        _apply_music_affects_native(c_symbol, inputs),
        (
            *REGISTERS, "note_delays", "sound_ids", "flags1", "flags2",
            "duty_patterns", "hardware_duty", "vibrato_delay_counters",
            "vibrato_extents", "vibrato_rates", "frequency_low_bytes",
            "hardware_frequency_low", "continuation",
        ),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("assembly_symbol", "c_symbol"),
    [
        (f"Audio{variant}_UpdateMusic", f"port_audio{variant}_update_music")
        for variant in (1, 2, 3)
    ],
)
def test_audio_update_music_symbolic_equivalence(
    assembly_symbol: str, c_symbol: str
) -> None:
    inputs = symbolic_registers(assembly_symbol)
    inputs["sound_ids"] = claripy.BVS(f"{assembly_symbol}_sound_ids", 64)
    for name in (
        "mute_audio_and_pause_music", "audio_terminal", "audio3_enable",
        "continuation",
    ):
        inputs[name] = claripy.BVS(f"{assembly_symbol}_{name}", 8)
    domains = [(target, "zero", 0) for target in (*range(8), -1)]
    domains.extend(
        (target, mute_mode, music_mask)
        for mute_mode in ("high", "low")
        for target in (4, 5, 6, 7, -1)
        for music_mask in range(16)
    )
    observables = (
        *REGISTERS, "sound_ids", "mute_audio_and_pause_music",
        "audio_terminal", "audio3_enable", "continuation",
    )
    for target_channel, mute_mode, music_mask in domains:
        try:
            assert_pathwise_equivalent(
                _update_music_assembly(
                    assembly_symbol,
                    inputs,
                    target_channel,
                    mute_mode,
                    music_mask,
                ),
                _update_music_native(
                    c_symbol,
                    inputs,
                    target_channel,
                    mute_mode,
                    music_mask,
                ),
                observables,
            )
        except AssertionError as error:
            raise AssertionError(
                f"target={target_channel}, mute={mute_mode}, "
                f"music_mask={music_mask:#x}: {error}"
            ) from error


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("assembly_symbol", "c_symbol", "sound_id"),
    [
        ("Audio1_PlaySound", "port_audio1_play_sound", 0xFF),
        ("Audio1_PlaySound", "port_audio1_play_sound", 0xBA),
        ("Audio1_PlaySound", "port_audio1_play_sound", 0xFE),
        ("Audio1_PlaySound", "port_audio1_play_sound", 0x01),
        ("Audio1_PlaySound", "port_audio1_play_sound", 0x14),
        ("Audio1_PlaySound", "port_audio1_play_sound", 0xB9),
        ("Audio1_PlaySound", "port_audio1_play_sound", 0x15),
        ("Audio1_PlaySound", "port_audio1_play_sound", 0x86),
        ("Audio1_PlaySound", "port_audio1_play_sound", 0x88),
        ("Audio1_PlaySound", "port_audio1_play_sound", 0x8C),
        ("Audio1_PlaySound", "port_audio1_play_sound", 0xA5),
        ("Audio1_PlaySound", "port_audio1_play_sound", 0xB8),
        ("Audio1_PlaySound", "port_audio1_play_sound", 0xBB),
        ("Audio1_PlaySound", "port_audio1_play_sound", 0xC3),
        ("Audio1_PlaySound", "port_audio1_play_sound", 0xC6),
        ("Audio1_PlaySound", "port_audio1_play_sound", 0x13),
        ("Audio1_PlaySound", "port_audio1_play_sound", 0x85),
        ("Audio1_PlaySound", "port_audio1_play_sound", 0xCD),
        ("Audio2_PlaySound", "port_audio2_play_sound", 0x01),
        ("Audio2_PlaySound", "port_audio2_play_sound", 0x14),
        ("Audio2_PlaySound", "port_audio2_play_sound", 0x15),
        ("Audio2_PlaySound", "port_audio2_play_sound", 0x86),
        ("Audio2_PlaySound", "port_audio2_play_sound", 0x88),
        ("Audio2_PlaySound", "port_audio2_play_sound", 0x8C),
        ("Audio2_PlaySound", "port_audio2_play_sound", 0x91),
        ("Audio2_PlaySound", "port_audio2_play_sound", 0x93),
        ("Audio2_PlaySound", "port_audio2_play_sound", 0xEA),
        ("Audio2_PlaySound", "port_audio2_play_sound", 0xEB),
        ("Audio2_PlaySound", "port_audio2_play_sound", 0xEC),
        ("Audio2_PlaySound", "port_audio2_play_sound", 0x13),
        ("Audio2_PlaySound", "port_audio2_play_sound", 0x85),
        ("Audio2_PlaySound", "port_audio2_play_sound", 0xE9),
        ("Audio2_PlaySound", "port_audio2_play_sound", 0xF0),
        ("Audio2_PlaySound", "port_audio2_play_sound", 0xFE),
        ("Audio2_PlaySound", "port_audio2_play_sound", 0xFF),
        ("Audio3_PlaySound", "port_audio3_play_sound", 0x01),
        ("Audio3_PlaySound", "port_audio3_play_sound", 0x14),
        ("Audio3_PlaySound", "port_audio3_play_sound", 0x15),
        ("Audio3_PlaySound", "port_audio3_play_sound", 0x86),
        ("Audio3_PlaySound", "port_audio3_play_sound", 0x88),
        ("Audio3_PlaySound", "port_audio3_play_sound", 0x8C),
        ("Audio3_PlaySound", "port_audio3_play_sound", 0xA5),
        ("Audio3_PlaySound", "port_audio3_play_sound", 0xC3),
        ("Audio3_PlaySound", "port_audio3_play_sound", 0xC4),
        ("Audio3_PlaySound", "port_audio3_play_sound", 0xC5),
        ("Audio3_PlaySound", "port_audio3_play_sound", 0xC6),
        ("Audio3_PlaySound", "port_audio3_play_sound", 0xC7),
        ("Audio3_PlaySound", "port_audio3_play_sound", 0xD0),
        ("Audio3_PlaySound", "port_audio3_play_sound", 0x13),
        ("Audio3_PlaySound", "port_audio3_play_sound", 0x85),
        ("Audio3_PlaySound", "port_audio3_play_sound", 0xC2),
        ("Audio3_PlaySound", "port_audio3_play_sound", 0xD4),
        ("Audio3_PlaySound", "port_audio3_play_sound", 0xFE),
        ("Audio3_PlaySound", "port_audio3_play_sound", 0xFF),
    ],
)
def test_audio_play_sound_symbolic_equivalence(
    assembly_symbol: str, c_symbol: str, sound_id: int
) -> None:
    prefix = f"{assembly_symbol}_{sound_id:02x}"
    inputs = symbolic_registers(prefix)
    inputs["a"] = claripy.BVV(sound_id, 8)
    inputs["audio_ram"] = claripy.BVS(f"{prefix}_audio_ram", 243 * 8)
    inputs["hardware_audio"] = claripy.BVS(
        f"{prefix}_hardware_audio", 23 * 8
    )
    assert_pathwise_equivalent(
        _play_sound_assembly(assembly_symbol, inputs, sound_id),
        _play_sound_native(c_symbol, assembly_symbol, inputs, sound_id),
        (*REGISTERS, "audio_ram", "hardware_audio"),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("assembly_symbol", "c_symbol", "channel", "matched"),
    [
        (
            f"Audio{variant}_unknownmusic0xef",
            f"port_audio{variant}_unknownmusic0xef",
            channel,
            matched,
        )
        for variant in (1, 2, 3)
        for channel in range(8)
        for matched in (False, True)
    ],
)
def test_audio_unknown_ef_symbolic_equivalence(
    assembly_symbol: str, c_symbol: str, channel: int, matched: bool
) -> None:
    prefix = f"{assembly_symbol}_{channel}_{matched}"
    inputs: dict[str, object] = symbolic_registers(prefix)
    inputs["c"] = claripy.BVV(channel, 8)
    inputs["audio_ram"] = claripy.BVS(f"{prefix}_audio_ram", 243 * 8)
    inputs["hardware_audio"] = claripy.BVS(
        f"{prefix}_hardware_audio", 23 * 8
    )
    inputs["command_byte"] = claripy.BVS(f"{prefix}_command_byte", 8)
    inputs["continuation"] = claripy.BVS(f"{prefix}_continuation", 8)
    play_outputs: dict[str, claripy.ast.BV] = symbolic_registers(
        f"{prefix}_play_post"
    )
    play_outputs["audio_ram"] = claripy.BVS(
        f"{prefix}_play_post_audio_ram", 243 * 8
    )
    play_outputs["hardware_audio"] = claripy.BVS(
        f"{prefix}_play_post_hardware", 23 * 8
    )
    inputs["play_outputs"] = play_outputs
    assert_pathwise_equivalent(
        _unknown_ef_assembly(assembly_symbol, inputs, channel, matched),
        _unknown_ef_native(c_symbol, inputs, channel, matched),
        (
            *REGISTERS,
            *(f"audio_ram_{index}" for index in range(8)),
            "hardware_audio", "command_byte",
            "continuation",
        ),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    (
        "assembly_symbol", "c_symbol", "channel", "category",
        "command_high", "play_enabled",
    ),
    [
        (
            f"Audio{variant}_note",
            f"port_audio{variant}_note",
            channel,
            "ordinary",
            None,
            None,
        )
        for variant in (1, 2, 3)
        for channel in (*range(3), *range(4, 8))
    ]
    + [
        (
            f"Audio{variant}_note",
            f"port_audio{variant}_note",
            3,
            "short",
            command_high,
            play_enabled,
        )
        for variant in (1, 2, 3)
        for command_high in range(0x00, 0xB0, 0x10)
        for play_enabled in (False, True)
    ]
    + [
        (
            f"Audio{variant}_note",
            f"port_audio{variant}_note",
            3,
            "drum",
            0xB0,
            play_enabled,
        )
        for variant in (1, 2, 3)
        for play_enabled in (False, True)
    ]
    + [
        (
            f"Audio{variant}_note",
            f"port_audio{variant}_note",
            3,
            "high",
            command_high,
            None,
        )
        for variant in (1, 2, 3)
        for command_high in range(0xC0, 0x100, 0x10)
    ],
)
def test_audio_note_symbolic_equivalence(
    assembly_symbol: str,
    c_symbol: str,
    channel: int,
    category: str,
    command_high: int | None,
    play_enabled: bool | None,
) -> None:
    prefix = (
        f"{assembly_symbol}_{channel}_{category}_{command_high}_{play_enabled}"
    )
    inputs: dict[str, object] = symbolic_registers(prefix)
    inputs["c"] = claripy.BVV(channel, 8)
    if command_high is not None:
        inputs["d"] = claripy.Concat(
            claripy.BVV(command_high >> 4, 4),
            claripy.BVS(f"{prefix}_command_low", 4),
        )
    inputs["audio_ram"] = claripy.BVS(f"{prefix}_audio_ram", 243 * 8)
    inputs["hardware_audio"] = claripy.BVS(
        f"{prefix}_hardware_audio", 23 * 8
    )
    inputs["command_byte"] = claripy.BVS(f"{prefix}_command_byte", 8)
    inputs["continuation"] = claripy.BVS(f"{prefix}_continuation", 8)
    play_outputs: dict[str, claripy.ast.BV] = symbolic_registers(
        f"{prefix}_play_post"
    )
    play_outputs["audio_ram"] = claripy.BVS(
        f"{prefix}_play_post_audio_ram", 243 * 8
    )
    play_outputs["hardware_audio"] = claripy.BVS(
        f"{prefix}_play_post_hardware", 23 * 8
    )
    inputs["play_outputs"] = play_outputs
    assert_pathwise_equivalent(
        _note_assembly(
            assembly_symbol,
            inputs,
            channel,
            category,
            command_high,
            play_enabled,
        ),
        _note_native(
            c_symbol,
            inputs,
            channel,
            category,
            command_high,
            play_enabled,
        ),
        (
            *REGISTERS,
            *(f"audio_ram_{index}" for index in range(8)),
            "hardware_audio", "command_byte",
            "continuation",
        ),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("symbol", ["Audio1_IsCry", "Audio2_IsCry", "Audio3_IsCry"])
def test_audio_is_cry_code_is_accounted_for(symbol: str) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, 20) == bytes.fromhex(
        "fa2ac0fe1430021806fe8628023803373fc937c9"
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_audio2_is_battle_sfx_code_is_accounted_for() -> None:
    location = symbol_location(SYMBOLS, "Audio2_IsBattleSFX")
    assert linked_bytes(ROM, location, 25) == bytes.fromhex(
        "fa2dc047fa2ac0b0fe9d30021806feea28023803373fc937c9"
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "expected"),
    [
        (
            "Audio1_EnableChannelOutput",
            "060021275b09f025b65779fe07280cfe04301a212ac0097ea72012fa04c021275b09a657f025211f5b09a6b2577ae025c9",
        ),
        (
            "Audio2_EnableChannelOutput",
            "060021e66209f025b65779fe07280cfe04301a212ac0097ea72012fa04c021e66209a657f02521de6209a6b2577ae025c9",
        ),
        (
            "Audio3_EnableChannelOutput",
            "0600219b5b09f025b65779fe07280cfe04301a212ac0097ea72012fa04c0219b5b09a657f02521935b09a6b2577ae025c9",
        ),
    ],
)
def test_enable_channel_output_code_is_accounted_for(
    symbol: str, expected: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, 49) == bytes.fromhex(expected)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "expected"),
    [
        ("Audio1_HWChannelEnableMasks", "1122448811224488"),
        ("Audio1_HWChannelDisableMasks", "eeddbb77eeddbb77"),
        ("Audio2_HWChannelEnableMasks", "1122448811224488"),
        ("Audio2_HWChannelDisableMasks", "eeddbb77eeddbb77"),
        ("Audio3_HWChannelEnableMasks", "1122448811224488"),
        ("Audio3_HWChannelDisableMasks", "eeddbb77eeddbb77"),
    ],
)
def test_channel_output_mask_table_is_accounted_for(
    symbol: str, expected: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, 8) == bytes.fromhex(expected)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    "symbol", ["Audio1_MultiplyAdd", "Audio2_MultiplyAdd", "Audio3_MultiplyAdd"]
)
def test_audio_multiply_add_code_is_accounted_for(symbol: str) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, 17) == bytes.fromhex(
        "2600cb3f300119cb23cb12a7280218f2c9"
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "expected"),
    [
        ("Audio1_GetRegisterPointer", "7921175b853001246f7e806f26ffc9"),
        ("Audio2_GetRegisterPointer", "7921d662853001246f7e806f26ffc9"),
        ("Audio3_GetRegisterPointer", "79218b5b853001246f7e806f26ffc9"),
    ],
)
def test_audio_get_register_pointer_code_is_accounted_for(
    symbol: str, expected: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, 15) == bytes.fromhex(expected)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    "symbol",
    [
        "Audio1_HWChannelBaseAddresses",
        "Audio2_HWChannelBaseAddresses",
        "Audio3_HWChannelBaseAddresses",
    ],
)
def test_audio_hardware_channel_base_table_is_accounted_for(symbol: str) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, 8) == bytes.fromhex("10151a1f10151a1f")


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "expected"),
    [
        (
            "Audio1_CalculateFrequency",
            "26006f29545d212f5b195e235678fe072807cb2acb1b3c18f53e088257c9",
        ),
        (
            "Audio2_CalculateFrequency",
            "26006f29545d21ee62195e235678fe072807cb2acb1b3c18f53e088257c9",
        ),
        (
            "Audio3_CalculateFrequency",
            "26006f29545d21a35b195e235678fe072807cb2acb1b3c18f53e088257c9",
        ),
    ],
)
def test_audio_calculate_frequency_code_is_accounted_for(
    symbol: str, expected: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, 30) == bytes.fromhex(expected)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    "symbol", ["Audio1_Pitches", "Audio2_Pitches", "Audio3_Pitches"]
)
def test_audio_pitch_table_is_accounted_for(symbol: str) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, 24) == bytes.fromhex(
        "2cf89df807f96bf9caf923fa77fac7fa12fb58fb9bfbdafb"
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "expected"),
    [
        (
            "Audio1_ApplyDutyCyclePattern",
            "06002146c0097e070777e6c0570601cd38587ee63fb277c9",
        ),
        (
            "Audio2_ApplyDutyCyclePattern",
            "06002146c0097e070777e6c0570601cdf75f7ee63fb277c9",
        ),
        (
            "Audio3_ApplyDutyCyclePattern",
            "06002146c0097e070777e6c0570601cdac587ee63fb277c9",
        ),
    ],
)
def test_audio_apply_duty_cycle_pattern_code_is_accounted_for(
    symbol: str, expected: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, 24) == bytes.fromhex(expected)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "expected"),
    [
        (
            "Audio1_ApplyDutyCycleAndSoundLength",
            "060021b6c0095679fe02280ffe06280b7ae63f57213ec0097eb2570601cd385872c9",
        ),
        (
            "Audio2_ApplyDutyCycleAndSoundLength",
            "060021b6c0095679fe02280ffe06280b7ae63f57213ec0097eb2570601cdf75f72c9",
        ),
        (
            "Audio3_ApplyDutyCycleAndSoundLength",
            "060021b6c0095679fe02280ffe06280b7ae63f57213ec0097eb2570601cdac5872c9",
        ),
    ],
)
def test_audio_apply_duty_cycle_and_sound_length_code_is_accounted_for(
    symbol: str, expected: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, 34) == bytes.fromhex(expected)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_audio2_reset_cry_modifiers_code_is_accounted_for() -> None:
    location = symbol_location(SYMBOLS, "Audio2_ResetCryModifiers")
    assert linked_bytes(ROM, location, 22) == bytes.fromhex(
        "79fe042010fa83d0cb7f2809afeaf1c03e80eaf2c0c9"
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "expected"),
    [
        (
            "Audio1_SetSfxTempo",
            "cde55630131600faf2c0c680300114eaebc07aeaeac01809afeaebc03e01eaeac0c9",
        ),
        (
            "Audio2_SetSfxTempo",
            "cd8b5e3805cd9f5e30131600faf2c0c680300114eaebc07aeaeac01809afeaebc03e01eaeac0c9",
        ),
        (
            "Audio3_SetSfxTempo",
            "cd595730131600faf2c0c680300114eaebc07aeaeac01809afeaebc03e01eaeac0c9",
        ),
    ],
)
def test_audio_set_sfx_tempo_code_is_accounted_for(
    symbol: str, expected: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, len(bytes.fromhex(expected))) == bytes.fromhex(
        expected
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "expected"),
    [
        (
            "Audio1_ApplyFrequencyModifier",
            "cde556300cfaf1c0833001142b5f732372c9",
        ),
        (
            "Audio2_ApplyFrequencyModifier",
            "cd8b5e3805cd9f5e300cfaf1c0833001142b5f732372c9",
        ),
        (
            "Audio3_ApplyFrequencyModifier",
            "cd5957300cfaf1c0833001142b5f732372c9",
        ),
    ],
)
def test_audio_apply_frequency_modifier_code_is_accounted_for(
    symbol: str, expected: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, len(bytes.fromhex(expected))) == bytes.fromhex(
        expected
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "expected"),
    [
        (
            "Audio1_ApplyWavePatternAndFrequency",
            "79fe022804fe06202dd511e6c0fe02280311e7c01a8716005f216143195e23562130ff060f3e00e01a1a13227805a720f83e80e01ad17af680e6c7570603cd3858732372cdb556c9",
        ),
        (
            "Audio2_ApplyWavePatternAndFrequency",
            "79fe022804fe06202dd511e6c0fe02280311e7c01a8716005f216143195e23562130ff060f3e00e01a1a13227805a720f83e80e01ad17af680e6c7570603cdf75f73237279fe043803cd565ec9",
        ),
        (
            "Audio3_ApplyWavePatternAndFrequency",
            "79fe022804fe06202dd511e6c0fe02280311e7c01a8716005f216143195e23562130ff060f3e00e01a1a13227805a720f83e80e01ad17af680e6c7570603cdac58732372cd2957c9",
        ),
    ],
)
def test_audio_apply_wave_pattern_and_frequency_code_is_accounted_for(
    symbol: str, expected: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, len(bytes.fromhex(expected))) == bytes.fromhex(
        expected
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "expected"),
    [
        (
            "Audio1_WavePointers",
            "734383439343a343b343c343c343c343c34302468acefffeeddccba987654433221102468aceeffffeeeddcba987654322111369bdeeeeffffeddeffffeeeedb963102468acdeffedeffeedcba9876543210012345678acdeef77feedca87654321021e23328e122ffea1014dc10e3415173",
        ),
        (
            "Audio2_WavePointers",
            "734383439343a343b343c343c343c343c34302468acefffeeddccba987654433221102468aceeffffeeeddcba987654322111369bdeeeeffffeddeffffeeeedb963102468acdeffedeffeedcba9876543210012345678acdeef77feedca876543210ec022091c0072081d0072091c0072ca1",
        ),
        (
            "Audio3_WavePointers",
            "734383439343a343b343c343c343c343c34302468acefffeeddccba987654433221102468aceeffffeeeddcba987654322111369bdeeeeffffeddeffffeeeedb963102468acdeffedeffeedcba9876543210012345678acdeef77feedca87654321021e23328e122ff22f72422f73424f744",
        ),
    ],
)
def test_audio_wave_pointer_and_sample_data_is_accounted_for(
    symbol: str, expected: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, 114) == bytes.fromhex(expected)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "expected"),
    [
        (
            "Audio1_GoBackOneCommandIfCry",
            "cde55630162106c0591600cb23cb12197ed60177237ede007737c9373fc9",
        ),
        (
            "Audio2_GoBackOneCommandIfCry",
            "cd8b5e30162106c0591600cb23cb12197ed60177237ede007737c9373fc9",
        ),
        (
            "Audio3_GoBackOneCommandIfCry",
            "cd595730162106c0591600cb23cb12197ed60177237ede007737c9373fc9",
        ),
    ],
)
def test_audio_go_back_one_command_if_cry_code_is_accounted_for(
    symbol: str, expected: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, 30) == bytes.fromhex(expected)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    "symbol",
    ["Audio1_GetNextMusicByte", "Audio2_GetNextMusicByte", "Audio3_GetNextMusicByte"],
)
def test_audio_get_next_music_byte_code_is_accounted_for(symbol: str) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, 19) == bytes.fromhex(
        "160079875f2106c0192a5f3a571a13732372c9"
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "expected"),
    [
        (
            "Audio1_ApplyPitchSlide",
            "212ec009cb6ec24057219ec0095e2196c00956217ec0096e6019545d218ec009e52186c0097ee186773e008b5f3e008a5721a6c0097ebada8657203e21aec0097ebbda86571833219ec0097e2196c00956217ec0095e935f7a98572186c0097e87777b985f7a985721a6c0097abe381d200821aec0097bbe3813219ec009732196c009720603cd38587b2272c9212ec009cba6cbaec9",
        ),
        (
            "Audio2_ApplyPitchSlide",
            "212ec009cb6ec2ff5e219ec0095e2196c00956217ec0096e6019545d218ec009e52186c0097ee186773e008b5f3e008a5721a6c0097ebada455f203e21aec0097ebbda455f1833219ec0097e2196c00956217ec0095e935f7a98572186c0097e87777b985f7a985721a6c0097abe381d200821aec0097bbe3813219ec009732196c009720603cdf75f7b2272c9212ec009cba6cbaec9",
        ),
        (
            "Audio3_ApplyPitchSlide",
            "212ec009cb6ec2b457219ec0095e2196c00956217ec0096e6019545d218ec009e52186c0097ee186773e008b5f3e008a5721a6c0097ebadafa57203e21aec0097ebbdafa571833219ec0097e2196c00956217ec0095e935f7a98572186c0097e87777b985f7a985721a6c0097abe381d200821aec0097bbe3813219ec009732196c009720603cdac587b2272c9212ec009cba6cbaec9",
        ),
    ],
)
def test_audio_apply_pitch_slide_code_is_accounted_for(
    symbol: str, expected: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, 150) == bytes.fromhex(expected)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    "symbol",
    [
        "Audio1_InitPitchSlideVars",
        "Audio2_InitPitchSlideVars",
        "Audio3_InitPitchSlideVars",
    ],
)
def test_audio_init_pitch_slide_vars_code_is_accounted_for(symbol: str) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, 126) == bytes.fromhex(
        "2196c00972219ec0097321b6c0097e2176c0099630023e017721aec0097b965f7a9821a6c00996380b570600212ec009cbee18232196c00956219ec0095e21aec0097e935f7a985721a6c0097e92570600212ec009cbae2176c009047b965f30fa7aa728043d5718f27b86500600217ec009722186c00977218ec00977c9"
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "expected"),
    [
        ("Audio1_execute_music", "fef8200b06002136c009cbc6c3e651"),
        ("Audio2_execute_music", "fef8200b06002136c009cbc6c36759"),
        ("Audio3_execute_music", "fef8200b06002136c009cbc6c35a52"),
    ],
)
def test_audio_execute_music_code_is_accounted_for(
    symbol: str, expected: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, 15) == bytes.fromhex(expected)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "expected"),
    [
        ("Audio1_octave", "e6f0fee0200d21d6c00600097ae60f77c3e651"),
        ("Audio2_octave", "e6f0fee0200d21d6c00600097ae60f77c36759"),
        ("Audio3_octave", "e6f0fee0200d21d6c00600097ae60f77c35a52"),
    ],
)
def test_audio_octave_code_is_accounted_for(symbol: str, expected: str) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, 19) == bytes.fromhex(expected)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "expected"),
    [
        ("Audio1_duty_cycle", "feec2011cd25580f0fe6c00600213ec00977c3e651"),
        ("Audio2_duty_cycle", "feec2011cde45f0f0fe6c00600213ec00977c36759"),
        ("Audio3_duty_cycle", "feec2011cd99580f0fe6c00600213ec00977c35a52"),
    ],
)
def test_audio_duty_cycle_command_code_is_accounted_for(
    symbol: str, expected: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, 21) == bytes.fromhex(expected)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "expected"),
    [
        ("Audio1_stereo_panning", "feee2009cd2558ea04c0c3e651"),
        ("Audio2_stereo_panning", "feee2009cde45fea04c0c36759"),
        ("Audio3_stereo_panning", "feee2009cd9958ea04c0c35a52"),
    ],
)
def test_audio_stereo_panning_code_is_accounted_for(
    symbol: str, expected: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, 13) == bytes.fromhex(expected)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "expected"),
    [
        ("Audio1_volume", "fef02008cd2558e024c3e651"),
        ("Audio2_volume", "fef02008cde45fe024c36759"),
        ("Audio3_volume", "fef02008cd9958e024c35a52"),
    ],
)
def test_audio_volume_command_code_is_accounted_for(
    symbol: str, expected: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, 12) == bytes.fromhex(expected)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "expected"),
    [
        (
            "Audio1_duty_cycle_pattern",
            "fefc201acd255806002146c00977e6c0213ec00977212ec009cbf6c3e651",
        ),
        (
            "Audio2_duty_cycle_pattern",
            "fefc201acde45f06002146c00977e6c0213ec00977212ec009cbf6c36759",
        ),
        (
            "Audio3_duty_cycle_pattern",
            "fefc201acd995806002146c00977e6c0213ec00977212ec009cbf6c35a52",
        ),
    ],
)
def test_audio_duty_pattern_command_code_is_accounted_for(
    symbol: str, expected: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, 30) == bytes.fromhex(expected)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "expected"),
    [
        (
            "Audio1_tempo",
            "feed203c79fe04301bcd2558eae8c0cd2558eae9c0afeacec0eacfc0ead0c0ead1c01819cd2558eaeac0cd2558eaebc0afead2c0ead3c0ead4c0ead5c0c3e651",
        ),
        (
            "Audio2_tempo",
            "feed203c79fe04301bcde45feae8c0cde45feae9c0afeacec0eacfc0ead0c0ead1c01819cde45feaeac0cde45feaebc0afead2c0ead3c0ead4c0ead5c0c36759",
        ),
        (
            "Audio3_tempo",
            "feed203c79fe04301bcd9958eae8c0cd9958eae9c0afeacec0eacfc0ead0c0ead1c01819cd9958eaeac0cd9958eaebc0afead2c0ead3c0ead4c0ead5c0c35a52",
        ),
    ],
)
def test_audio_tempo_command_code_is_accounted_for(
    symbol: str, expected: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, 64) == bytes.fromhex(expected)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "expected"),
    [
        ("Audio1_toggle_perfect_pitch", "7afee8200d0600212ec0097eee0177c3e651"),
        ("Audio2_toggle_perfect_pitch", "7afee8200d0600212ec0097eee0177c36759"),
        ("Audio3_toggle_perfect_pitch", "7afee8200d0600212ec0097eee0177c35a52"),
    ],
)
def test_audio_toggle_perfect_pitch_code_is_accounted_for(
    symbol: str, expected: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, 18) == bytes.fromhex(expected)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "expected"),
    [
        (
            "Audio1_vibrato",
            "feea2034cd25580600214ec00977216ec00977cd255857e6f0cb3706002156c009cb3f5f88cb37b3777ae60f57215ec009cb37b277c3e651",
        ),
        (
            "Audio2_vibrato",
            "feea2034cde45f0600214ec00977216ec00977cde45f57e6f0cb3706002156c009cb3f5f88cb37b3777ae60f57215ec009cb37b277c36759",
        ),
        (
            "Audio3_vibrato",
            "feea2034cd99580600214ec00977216ec00977cd995857e6f0cb3706002156c009cb3f5f88cb37b3777ae60f57215ec009cb37b277c35a52",
        ),
    ],
)
def test_audio_vibrato_command_code_is_accounted_for(
    symbol: str, expected: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, 56) == bytes.fromhex(expected)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "expected"),
    [
        ("Audio1_pitch_sweep", "79fe0438177afe10201206002136c009cb462008cd2558e010c3e651"),
        ("Audio2_pitch_sweep", "79fe0438177afe10201206002136c009cb462008cde45fe010c36759"),
        ("Audio3_pitch_sweep", "79fe0438177afe10201206002136c009cb462008cd9958e010c35a52"),
    ],
)
def test_audio_pitch_sweep_code_is_accounted_for(
    symbol: str, expected: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, 28) == bytes.fromhex(expected)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "expected"),
    [
        (
            "Audio1_pitch_slide",
            "feeb2034cd255806002176c00977cd255857e6f0cb37477ae60fcd5858060021a6c0097221aec009730600212ec009cbe6cd255857c30a55",
        ),
        (
            "Audio2_pitch_slide",
            "feeb2034cde45f06002176c00977cde45f57e6f0cb37477ae60fcd1760060021a6c0097221aec009730600212ec009cbe6cde45f57c38b5c",
        ),
        (
            "Audio3_pitch_slide",
            "feeb2034cd995806002176c00977cd995857e6f0cb37477ae60fcdcc58060021a6c0097221aec009730600212ec009cbe6cd995857c37e55",
        ),
    ],
)
def test_audio_pitch_slide_command_code_is_accounted_for(
    symbol: str, expected: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, 56) == bytes.fromhex(expected)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "expected"),
    [
        (
            "Audio1_note_type",
            "e6f0fed0c223537ae60f060021c6c0097779fe032826cd25585779fe022809fe06201221e7c0180321e6c07ae60f777ae630cb2757060021dec00972c3e651",
        ),
        (
            "Audio2_note_type",
            "e6f0fed0c2a45a7ae60f060021c6c0097779fe032826cde45f5779fe022809fe06201221e7c0180321e6c07ae60f777ae630cb2757060021dec00972c36759",
        ),
        (
            "Audio3_note_type",
            "e6f0fed0c297537ae60f060021c6c0097779fe032826cd99585779fe022809fe06201221e7c0180321e6c07ae60f777ae630cb2757060021dec00972c35a52",
        ),
    ],
)
def test_audio_note_type_code_is_accounted_for(
    symbol: str, expected: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, 63) == bytes.fromhex(expected)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "expected"),
    [
        (
            "Audio1_sound_call",
            "fefdc2a952cd2558f5cd255857f15fd5160079875f2106c019e52116c0195d54e12a12133a12d17323720600212ec009cbcec3e651",
        ),
        (
            "Audio2_sound_call",
            "fefdc22a5acde45ff5cde45f57f15fd5160079875f2106c019e52116c0195d54e12a12133a12d17323720600212ec009cbcec36759",
        ),
        (
            "Audio3_sound_call",
            "fefdc21d53cd9958f5cd995857f15fd5160079875f2106c019e52116c0195d54e12a12133a12d17323720600212ec009cbcec35a52",
        ),
    ],
)
def test_audio_sound_call_code_is_accounted_for(
    symbol: str, expected: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, 53) == bytes.fromhex(expected)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "expected"),
    [
        (
            "Audio1_sound_loop",
            "fefec2e452cd25585fa72818060021bec0097ebb200c3e0177cd2558cd2558c3e6513c77cd2558f5cd255847160079875f2106c019f12270c3e651",
        ),
        (
            "Audio2_sound_loop",
            "fefec2655acde45f5fa72818060021bec0097ebb200c3e0177cde45fcde45fc367593c77cde45ff5cde45f47160079875f2106c019f12270c36759",
        ),
        (
            "Audio3_sound_loop",
            "fefec25853cd99585fa72818060021bec0097ebb200c3e0177cd9958cd9958c35a523c77cd9958f5cd995847160079875f2106c019f12270c35a52",
        ),
    ],
)
def test_audio_sound_loop_code_is_accounted_for(
    symbol: str, expected: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, 59) == bytes.fromhex(expected)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "expected"),
    [
        (
            "Audio1_note_length",
            "7af5e60f3c06005f5021c6c0097e68cd475879fe04300afae8c057fae9c05f181316011e00fe07280bcd9356faeac057faebc05f7d060021cec0096ecd47585d5421cec009737a21b6c009772136c009cb46200a212ec009cb562802e1c9",
        ),
        (
            "Audio2_note_length",
            "7af5e60f3c06005f5021c6c0097e68cd066079fe04300afae8c057fae9c05f181316011e00fe07280bcd2f5efaeac057faebc05f7d060021cec0096ecd06605d5421cec009737a21b6c009772136c009cb46200a212ec009cb562802e1c9",
        ),
        (
            "Audio3_note_length",
            "7af5e60f3c06005f5021c6c0097e68cdbb5879fe04300afae8c057fae9c05f181316011e00fe07280bcd0757faeac057faebc05f7d060021cec0096ecdbb585d5421cec009737a21b6c009772136c009cb46200a212ec009cb562802e1c9",
        ),
    ],
)
def test_audio_note_length_code_is_accounted_for(
    symbol: str, expected: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, 94) == bytes.fromhex(expected)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "expected"),
    [
        (
            "Audio1_note_pitch",
            "f1e6f0fec0203079fe043008212ac0097ea7202279fe022804fe06200d0600211f5b09f025a6e025180c0602cd38583e0822233e8077c9cb37060021d6c00946cd58580600212ec009cb662803cd8f57d579fe04300f212ac016005f197ea720021802d1c9060021dec009560602cd385872cd2956cdf855d10600212ec009cb4628041c3001142166c00973cd4b56c9",
        ),
        (
            "Audio2_note_pitch",
            "f1e6f0fec0203079fe043008212ac0097ea7202279fe022804fe06200d060021de6209f025a6e025180c0602cdf75f3e0822233e8077c9cb37060021d6c00946cd17600600212ec009cb662803cd4e5fd579fe04300f212ac016005f197ea720021802d1c9060021dec009560602cdf75f72cdaa5dcd795dd10600212ec009cb4628041c3001142166c00973cdcc5dc9",
        ),
        (
            "Audio3_note_pitch",
            "f1e6f0fec0203079fe043008212ac0097ea7202279fe022804fe06200d060021935b09f025a6e025180c0602cdac583e0822233e8077c9cb37060021d6c00946cdcc580600212ec009cb662803cd0358d579fe04300f212ac016005f197ea720021802d1c9060021dec009560602cdac5872cd9d56cd6c56d10600212ec009cb4628041c3001142166c00973cdbf56c9",
        ),
    ],
)
def test_audio_note_pitch_code_is_accounted_for(
    symbol: str, expected: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, 144) == bytes.fromhex(expected)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "expected"),
    [
        (
            "Audio1_PlayNextNote",
            "216ec0097e214ec00977212ec009cba6cbaecde651c9",
        ),
        (
            "Audio2_PlayNextNote",
            "216ec0097e214ec00977212ec009cba6cbae79fe042006fa83d0cb7fc0cd6759c9",
        ),
        (
            "Audio3_PlayNextNote",
            "216ec0097e214ec00977212ec009cba6cbaecd5a52c9",
        ),
    ],
)
def test_audio_play_next_note_code_is_accounted_for(
    symbol: str, expected: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, len(bytes.fromhex(expected))) == bytes.fromhex(
        expected
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "expected"),
    [
        (
            "Audio1_sound_ret",
            "cd255857feffc274520600212ec009cb4e202b79fe033002183fcb962136c009cb86fe0620083e00e01a3e80e01a200cfa03c0a72806afea03c0181d1824cb8e160079875f2106c019e52116c0195d54e11a22131a77c3e651211f5b09f025a6e025fa2ac0fe143002181dfa2ac0fe8628163802181279fe042804cdc756d8fa05c0e024afea05c02126c00970c9",
        ),
        (
            "Audio2_sound_ret",
            "cde45f57feffc2f5590600212ec009cb4e202b79fe033002183fcb962136c009cb86fe0620083e00e01a3e80e01a200cfa03c0a72806afea03c0181d1824cb8e160079875f2106c019e52116c0195d54e11a22131a77c3675921de6209f025a6e025fa2ac0fe143002181dfa2ac0fe8628163802181279fe042804cd6d5ed8fa05c0e024afea05c02126c00970c9",
        ),
        (
            "Audio3_sound_ret",
            "cd995857feffc2e8520600212ec009cb4e202b79fe033002183fcb962136c009cb86fe0620083e00e01a3e80e01a200cfa03c0a72806afea03c0181d1824cb8e160079875f2106c019e52116c0195d54e11a22131a77c35a5221935b09f025a6e025fa2ac0fe143002181dfa2ac0fe8628163802181279fe042804cd3b57d8fa05c0e024afea05c02126c00970c9",
        ),
    ],
)
def test_audio_sound_ret_code_is_accounted_for(
    symbol: str, expected: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, 142) == bytes.fromhex(expected)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "expected"),
    [
        (
            "Audio1_sfx_note",
            "fe20204979fe03384406002136c009cb46203acd0a55570600213ec0097eb2570601cd385872cd2558570602cd385872cd25585f79fe073e002805d5cd2558d157d5cd2956cdf855d1cd4b56c9",
        ),
        (
            "Audio2_sfx_note",
            "fe20204979fe03384406002136c009cb46203acd8b5c570600213ec0097eb2570601cdf75f72cde45f570602cdf75f72cde45f5f79fe073e002805d5cde45fd157d5cdaa5dcd795dd1cdcc5dc9",
        ),
        (
            "Audio3_sfx_note",
            "fe20204979fe03384406002136c009cb46203acd7e55570600213ec0097eb2570601cdac5872cd9958570602cdac5872cd99585f79fe073e002805d5cd9958d157d5cd9d56cd6c56d1cdbf56c9",
        ),
    ],
)
def test_audio_sfx_note_code_is_accounted_for(
    symbol: str, expected: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, 77) == bytes.fromhex(expected)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "expected"),
    [
        (
            "Audio1_ApplyMusicAffects",
            "060021b6c0097efe01cad0513d7779fe043009212ac0097ea72801c9212ec009cb762803cd0d5806002136c009cb462008212ec009cb562014212ec009cb662803c3f956214ec0097ea7280235c92156c0097ea72001c957215ec0097ee60fa7280235c97ecb36b6772166c0095e212ec009cb5e280ecb9e7ae60f577b9230023e00180ccbde7ae6f0cb378330023eff570603cd385872c9",
        ),
        (
            "Audio2_ApplyMusicAffects",
            "060021b6c0097efe01ca46593d7779fe043009212ac0097ea72801c9212ec009cb762803cdcc5f06002136c009cb462008212ec009cb562014212ec009cb662803c3b85e214ec0097ea7280235c92156c0097ea72001c957215ec0097ee60fa7280235c97ecb36b6772166c0095e212ec009cb5e280ecb9e7ae60f577b9230023e00180ccbde7ae6f0cb378330023eff570603cdf75f72c9",
        ),
        (
            "Audio3_ApplyMusicAffects",
            "060021b6c0097efe01ca44523d7779fe043009212ac0097ea72801c9212ec009cb762803cd815806002136c009cb462008212ec009cb562014212ec009cb662803c36d57214ec0097ea7280235c92156c0097ea72001c957215ec0097ee60fa7280235c97ecb36b6772166c0095e212ec009cb5e280ecb9e7ae60f577b9230023e00180ccbde7ae6f0cb378330023eff570603cdac5872c9",
        ),
    ],
)
def test_audio_apply_music_affects_code_is_accounted_for(
    symbol: str, expected: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, 152) == bytes.fromhex(expected)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "expected"),
    [
        (
            "Audio1_UpdateMusic",
            "0e0006002126c0097ea7282279fe04301afa02c0a72814cb7f2013cbffea02c0afe025e01a3e80e01a1803cd3851790cfe0720cec9",
        ),
        (
            "Audio2_UpdateMusic",
            "0e0006002126c0097ea7282279fe04301afa02c0a72814cb7f2013cbffea02c0afe025e01a3e80e01a1803cdae58790cfe0720cec9",
        ),
        (
            "Audio3_UpdateMusic",
            "0e0006002126c0097ea7282279fe04301afa02c0a72814cb7f2013cbffea02c0afe025e01a3e80e01a1803cdac51790cfe0720cec9",
        ),
    ],
)
def test_audio_update_music_code_is_accounted_for(
    symbol: str, expected: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, 53) == bytes.fromhex(expected)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("variant", "code_hash", "header_hash"),
    [
        (
            1,
            "394423f97e49208acc60dc731f5721625e60df09ebe086cd0f4ca4a200c027a9",
            "3ba9b5735e94893bd580d924b1f36fe8f3d6664be1267c338993f7af6a0b1ffd",
        ),
        (
            2,
            "56d6d10975f237f5a8386554f488a6d7e50cb3bb2ff95859d96feb98e79988aa",
            "c65cc67ce9de871d4087eee6d563e896132ce2d7bb123f34e4f8041da90c6c53",
        ),
        (
            3,
            "55674c0afdb990561335d627b1990e7e66f1b8c0c07633be51b507db381840ca",
            "b44381dcaa6958bfa9bcfcbd0209c7e45dd9e68a081d83f7dc283128e00103e8",
        ),
    ],
)
def test_audio_play_sound_code_and_header_rom_are_accounted_for(
    variant: int, code_hash: str, header_hash: str
) -> None:
    function = symbol_location(SYMBOLS, f"Audio{variant}_PlaySound")
    header = symbol_location(SYMBOLS, f"SFX_Headers_{variant}")
    cry_ret = symbol_location(SYMBOLS, f"Audio{variant}_CryRet")
    code = linked_bytes(ROM, function, 672)
    header_data = rom_window(ROM, header.bank).getvalue()[0x4000 : 0x4310]
    assert hashlib.sha256(code).hexdigest() == code_hash
    assert hashlib.sha256(header_data).hexdigest() == header_hash
    assert linked_bytes(ROM, cry_ret, 1) == b"\xff"


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "expected"),
    [
        (
            "Audio1_unknownmusic0xef",
            "feef201bcd2558c5cd7658c1fa03c0a7200afa2dc0ea03c0afea2dc0c3e651",
        ),
        (
            "Audio2_unknownmusic0xef",
            "feef201bcde45fc5cd3560c1fa03c0a7200afa2dc0ea03c0afea2dc0c36759",
        ),
        (
            "Audio3_unknownmusic0xef",
            "feef201bcd9958c5cdea58c1fa03c0a7200afa2dc0ea03c0afea2dc0c35a52",
        ),
    ],
)
def test_audio_unknown_ef_code_is_accounted_for(
    symbol: str, expected: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, 31) == bytes.fromhex(expected)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "expected"),
    [
        (
            "Audio1_note",
            "79fe03202a7ae6f0feb0280e3021cb37477ae60f5778d5c518087ae60ff5c5cd255857fa03c0a720047acd7658c1d1",
        ),
        (
            "Audio2_note",
            "79fe03202a7ae6f0feb0280e3021cb37477ae60f5778d5c518087ae60ff5c5cde45f57fa03c0a720047acd3560c1d1",
        ),
        (
            "Audio3_note",
            "79fe03202a7ae6f0feb0280e3021cb37477ae60f5778d5c518087ae60ff5c5cd995857fa03c0a720047acdea58c1d1",
        ),
    ],
)
def test_audio_note_code_is_accounted_for(symbol: str, expected: str) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, 47) == bytes.fromhex(expected)
