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
from verification.harness.rom import collect_returns, linked_bytes, rom_window, symbol_location

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
    "audio_saved_rom_bank",
    "status_flags2",
    "audio_volume",
)

EXPECTED_BODY = bytes.fromhex(
    "fac7cfa7200bfa2cd7cb4fc03e77e024c9fac9cfa728053deac9cfc9fac8cf"
    "eac9cff024a7281147e60f3d4f78e6f0cb373dcb37b1e024c9fac7cf47afea"
    "c7cf3effeaeec0cdb123faf0c0eaefc078eaeec0c3b123"
)


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


class LoadField(angr.SimProcedure):
    def __init__(self, field: str, continuation: int) -> None:
        super().__init__()
        self.field = field
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals[self.field]
        self.jump(self.continuation)


class StoreField(angr.SimProcedure):
    def __init__(self, field: str, continuation: int) -> None:
        super().__init__()
        self.field = field
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.globals[self.field] = self.state.regs.a
        self.jump(self.continuation)


class AndA(angr.SimProcedure):
    def __init__(self, mask: int, continuation: int) -> None:
        super().__init__()
        self.mask = mask
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a &= self.mask
        self.state.regs.f = claripy.BVV(0x10, 8) | claripy.If(
            self.state.regs.a == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)
        )
        self.jump(self.continuation)


class BitA(angr.SimProcedure):
    def __init__(self, bit: int, continuation: int) -> None:
        super().__init__()
        self.bit = bit
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        flags = (self.state.regs.f & 1) | claripy.BVV(0x10, 8)
        flags |= claripy.If(
            self.state.regs.a & (1 << self.bit) == 0,
            claripy.BVV(0x40, 8),
            claripy.BVV(0, 8),
        )
        self.state.regs.f = flags
        self.jump(self.continuation)


class DecA(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        before = self.state.regs.a
        result = before - 1
        flags = (self.state.regs.f & 1) | claripy.BVV(0x02, 8)
        flags |= claripy.If(result == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        flags |= claripy.If(
            before & 0x0F == 0, claripy.BVV(0x10, 8), claripy.BVV(0, 8)
        )
        self.state.regs.a = result
        self.state.regs.f = flags
        self.jump(self.continuation)


class SwapA(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        value = self.state.regs.a
        self.state.regs.a = (value << 4) | claripy.LShR(value, 4)
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)
        )
        self.jump(self.continuation)


class OrC(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a |= self.state.regs.c
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)
        )
        self.jump(self.continuation)


class XorA(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x40, 8)
        self.jump(self.continuation)


class PlaySoundStart(angr.SimProcedure):
    """No-fade, nonzero-ID transition of the independently proven PlaySound."""

    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        for index in range(4):
            self.state.globals[f"channel_{index}"] = claripy.BVV(0, 8)
        self.state.globals["new_sound_id"] = claripy.BVV(0, 8)
        self.state.globals["saved_rom_bank"] = self.state.globals["loaded_rom_bank"]
        self.state.globals["loaded_rom_bank"] = self.state.globals["audio_rom_bank"]
        self.state.globals["rom_bank"] = self.state.globals["audio_rom_bank"]
        self.state.globals["dispatch_called"] = claripy.BVV(1, 8)
        self.state.globals["loaded_rom_bank"] = self.state.globals["saved_rom_bank"]
        self.state.globals["rom_bank"] = self.state.globals["saved_rom_bank"]
        self.jump(self.continuation)


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for field in STATE_FIELDS:
        values[field] = claripy.BVS(f"{prefix}_{field}", 8)
    return values


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "FadeOutAudio")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY
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
    for offset, field, length in (
        (0, "fade_control", 3),
        (6, "status_flags2", 3),
        (17, "fade_counter", 3),
        (28, "fade_reload", 3),
        (34, "audio_volume", 2),
        (56, "fade_control", 3),
        (72, "audio_saved_rom_bank", 3),
    ):
        project.hook(base + offset, LoadField(field, base + offset + length), length=length)
    for offset, field, length in (
        (14, "audio_volume", 2),
        (24, "fade_counter", 3),
        (31, "fade_counter", 3),
        (53, "audio_volume", 2),
        (61, "fade_control", 3),
        (66, "new_sound_id", 3),
        (75, "audio_rom_bank", 3),
        (79, "new_sound_id", 3),
    ):
        project.hook(base + offset, StoreField(field, base + offset + length), length=length)
    for offset, mask, length in (
        (3, 0xFF, 1),
        (20, 0xFF, 1),
        (36, 0xFF, 1),
        (40, 0x0F, 2),
        (45, 0xF0, 2),
    ):
        project.hook(base + offset, AndA(mask, base + offset + length), length=length)
    project.hook(base + 9, BitA(1, base + 11), length=2)
    for offset in (23, 42, 49):
        project.hook(base + offset, DecA(base + offset + 1), length=1)
    for offset in (47, 50):
        project.hook(base + offset, SwapA(base + offset + 2), length=2)
    project.hook(base + 52, OrC(base + 53), length=1)
    project.hook(base + 60, XorA(base + 61), length=1)
    project.hook(base + 69, PlaySoundStart(base + 72), length=3)
    project.hook(base + 82, PlaySoundStart(RETURN), length=3)

    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    for field in STATE_FIELDS:
        state.globals[field] = values[field]
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    return [
        Endpoint(
            **assembly_registers(end),
            memory=claripy.Concat(*(end.globals[field] for field in STATE_FIELDS)),
            constraints=tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, RETURN)
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_fade_out_audio")
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
def test_fade_out_audio_pathwise_equivalence() -> None:
    values = _inputs("fade_out_audio")
    assert_pathwise_equivalent(
        _assembly(values), _native(values), (*REGISTERS, "memory")
    )
