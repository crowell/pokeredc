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
    sm83_flags_to_z80,
    symbol_location,
)
from verification.harness.sm83_shims import (
    Sm83CpImmediate,
    Sm83LoadAImmediate,
    Sm83StoreAImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
STACK = 0xD000
RETURN = 0xFFFF
EXPECTED = bytes.fromhex(
    "cd4837fa5bd0e67fc8fe0a3e2006300ea6280e3ee006ff0eb030063e5006010e"
    "a7eaf1c078eaf2c079c3b123"
)
W_DAMAGE = 0xD05B
FREQUENCY = 0xC0F1
TEMPO = 0xC0F2
SOUND_FIELDS = (
    "new_sound_id",
    "audio_rom_bank",
    "fade_control",
    "fade_reload",
    "fade_counter",
    "last_music_sound_id",
    "channel0",
    "channel1",
    "channel2",
    "channel3",
    "saved_rom_bank",
    "loaded_rom_bank",
    "rom_bank",
    "dispatch_called",
    "low_health_alarm",
    "audio_saved_rom_bank",
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
    state: claripy.ast.BV
    wait_call: claripy.ast.BV
    play_called: claripy.ast.BV
    play_call: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _assembly_state(state: angr.SimState) -> claripy.ast.BV:
    return claripy.Concat(
        *(assembly_registers(state)[name] for name in REGISTERS),
        *(state.globals[name] for name in SOUND_FIELDS),
        state.memory.load(W_DAMAGE, 1),
        state.memory.load(FREQUENCY, 1),
        state.memory.load(TEMPO, 1),
    )


class AssemblyWaitSummary(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:
        self.state.globals["wait_call"] = claripy.Concat(
            *(assembly_registers(self.state)[name] for name in REGISTERS),
            self.state.globals["low_health_alarm"],
            self.state.globals["channel0"],
            self.state.globals["channel1"],
            self.state.globals["channel2"],
        )
        for name in REGISTERS:
            value = self.state.globals[f"wait_out_{name}"]
            if name == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, name, value)
        for index in range(3):
            self.state.globals[f"channel{index}"] = self.state.globals[
                f"wait_out_channel{index}"
            ]
        self.jump(self._next_address)


class NativeWaitSummary(angr.SimProcedure):
    def run(self) -> None:
        address = self.state.regs.rdi
        self.state.globals["wait_call"] = self.state.memory.load(address, 12)
        self.state.memory.store(
            address,
            claripy.Concat(
                *(self.state.globals[f"wait_out_{name}"] for name in REGISTERS)
            ),
        )
        for index in range(3):
            self.state.memory.store(
                address + 9 + index,
                self.state.globals[f"wait_out_channel{index}"],
            )


class AssemblyPlaySummary(angr.SimProcedure):
    def run(self) -> None:
        self.state.globals["play_called"] = claripy.BVV(1, 8)
        self.state.globals["play_call"] = claripy.Concat(
            *(assembly_registers(self.state)[name] for name in REGISTERS),
            *(self.state.globals[name] for name in SOUND_FIELDS),
        )
        for name in REGISTERS:
            value = self.state.globals[f"play_out_{name}"]
            if name == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, name, value)
        for name in SOUND_FIELDS:
            self.state.globals[name] = self.state.globals[f"play_out_{name}"]
        return_address = self.state.memory.load(
            self.state.regs.sp, 2, endness="Iend_LE"
        )
        self.state.regs.sp += 2
        self.jump(return_address)


class NativePlaySummary(angr.SimProcedure):
    def run(self) -> None:
        address = self.state.regs.rdi
        self.state.globals["play_called"] = claripy.BVV(1, 8)
        self.state.globals["play_call"] = self.state.memory.load(address, 24)
        self.state.memory.store(
            address,
            claripy.Concat(
                *(self.state.globals[f"play_out_{name}"] for name in REGISTERS),
                *(self.state.globals[f"play_out_{name}"] for name in SOUND_FIELDS),
            ),
        )


class LoadImmediatePreserveFlags(angr.SimProcedure):
    def __init__(self, register: str, value: int, next_address: int) -> None:
        super().__init__()
        self._register = register
        self._value = value
        self._next_address = next_address

    def run(self) -> None:
        setattr(self.state.regs, self._register, claripy.BVV(self._value, 8))
        self.jump(self._next_address)


class CopyRegisterPreserveFlags(angr.SimProcedure):
    def __init__(self, source: str, target: str, next_address: int) -> None:
        super().__init__()
        self._source = source
        self._target = target
        self._next_address = next_address

    def run(self) -> None:
        setattr(self.state.regs, self._target, getattr(self.state.regs, self._source))
        self.jump(self._next_address)


class AndImmediate(angr.SimProcedure):
    """SM83 AND n: set H, clear N/C, and set Z from the result."""

    def __init__(self, immediate: int, next_address: int) -> None:
        super().__init__()
        self._immediate = immediate
        self._next_address = next_address

    def run(self) -> None:
        result = self.state.regs.a & self._immediate
        self.state.regs.a = result
        self.state.regs.f = claripy.If(
            result == 0, claripy.BVV(0x50, 8), claripy.BVV(0x10, 8)
        )
        self.jump(self._next_address)


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for name in SOUND_FIELDS:
        values[name] = claripy.BVS(f"{prefix}_{name}", 8)
        values[f"play_out_{name}"] = claripy.BVS(f"{prefix}_play_out_{name}", 8)
    for name in ("damage", "frequency", "tempo"):
        values[name] = claripy.BVS(f"{prefix}_{name}", 8)
    for name in REGISTERS:
        if name == "f":
            values[f"wait_out_{name}"] = claripy.Concat(
                claripy.BVS(f"{prefix}_wait_out_flags", 4), claripy.BVV(0, 4)
            )
            values[f"play_out_{name}"] = claripy.Concat(
                claripy.BVS(f"{prefix}_play_out_flags", 4), claripy.BVV(0, 4)
            )
        else:
            values[f"wait_out_{name}"] = claripy.BVS(
                f"{prefix}_wait_out_{name}", 8
            )
            values[f"play_out_{name}"] = claripy.BVS(
                f"{prefix}_play_out_{name}", 8
            )
    for index in range(3):
        values[f"wait_out_channel{index}"] = claripy.BVS(
            f"{prefix}_wait_out_channel{index}", 8
        )
    return values


def _setup_globals(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    state.globals["wait_call"] = claripy.BVV(0, 12 * 8)
    state.globals["play_called"] = claripy.BVV(0, 8)
    state.globals["play_call"] = claripy.BVV(0, 24 * 8)
    for name in SOUND_FIELDS:
        state.globals[name] = values[name]
        state.globals[f"play_out_{name}"] = values[f"play_out_{name}"]
    for name in REGISTERS:
        state.globals[f"wait_out_{name}"] = values[f"wait_out_{name}"]
        state.globals[f"play_out_{name}"] = values[f"play_out_{name}"]
    for index in range(3):
        state.globals[f"wait_out_channel{index}"] = values[
            f"wait_out_channel{index}"
        ]


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "PlayApplyingAttackSound")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    base = location.address
    project = angr.Project(
        rom_window(ROM, location.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": base,
        },
    )
    project.hook(base, AssemblyWaitSummary(base + 3), length=3)
    project.hook(base + 3, Sm83LoadAImmediate(W_DAMAGE, base + 6), length=3)
    project.hook(base + 6, AndImmediate(0x7F, base + 8), length=2)
    project.hook(base + 9, Sm83CpImmediate(10, base + 11), length=2)
    project.hook(base + 11, LoadImmediatePreserveFlags("a", 0x20, base + 13), length=2)
    project.hook(base + 13, LoadImmediatePreserveFlags("b", 0x30, base + 15), length=2)
    project.hook(base + 15, LoadImmediatePreserveFlags("c", 0xA6, base + 17), length=2)
    project.hook(base + 19, LoadImmediatePreserveFlags("a", 0xE0, base + 21), length=2)
    project.hook(base + 21, LoadImmediatePreserveFlags("b", 0xFF, base + 23), length=2)
    project.hook(base + 23, LoadImmediatePreserveFlags("c", 0xB0, base + 25), length=2)
    project.hook(base + 27, LoadImmediatePreserveFlags("a", 0x50, base + 29), length=2)
    project.hook(base + 29, LoadImmediatePreserveFlags("b", 1, base + 31), length=2)
    project.hook(base + 31, LoadImmediatePreserveFlags("c", 0xA7, base + 33), length=2)
    project.hook(base + 33, Sm83StoreAImmediate(FREQUENCY, base + 36), length=3)
    project.hook(base + 36, CopyRegisterPreserveFlags("b", "a", base + 37), length=1)
    project.hook(base + 37, Sm83StoreAImmediate(TEMPO, base + 40), length=3)
    project.hook(base + 40, CopyRegisterPreserveFlags("c", "a", base + 41), length=1)
    project.hook(base + 41, AssemblyPlaySummary(), length=3)

    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.regs.sp = claripy.BVV(STACK, 16)
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    state.memory.store(W_DAMAGE, values["damage"])
    state.memory.store(FREQUENCY, values["frequency"])
    state.memory.store(TEMPO, values["tempo"])
    _setup_globals(state, values)
    ends = collect_returns(project, state, RETURN)
    assert len(ends) == 4
    return [
        Endpoint(
            **assembly_registers(end),
            state=_assembly_state(end),
            wait_call=end.globals["wait_call"],
            play_called=end.globals["play_called"],
            play_call=end.globals["play_call"],
            constraints=tuple(end.solver.constraints),
        )
        for end in ends
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_play_applying_attack_sound")
    wait = project.loader.find_symbol("port_wait_for_sound_to_finish")
    play = project.loader.find_symbol("port_play_sound")
    assert function is not None and wait is not None and play is not None
    project.hook(wait.rebased_addr, NativeWaitSummary())
    project.hook(play.rebased_addr, NativePlaySummary())
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(
        NATIVE_STATE + 8,
        claripy.Concat(*(values[name] for name in SOUND_FIELDS)),
    )
    state.memory.store(NATIVE_STATE + 24, values["damage"])
    state.memory.store(NATIVE_STATE + 25, values["frequency"])
    state.memory.store(NATIVE_STATE + 26, values["tempo"])
    _setup_globals(state, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) >= 2
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            state=end.memory.load(NATIVE_STATE, 27),
            wait_call=end.globals["wait_call"],
            play_called=end.globals["play_called"],
            play_call=end.globals["play_call"],
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_play_applying_attack_sound_pathwise_equivalence() -> None:
    values = _inputs("play_applying_attack_sound")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "state", "wait_call", "play_called", "play_call"),
    )
