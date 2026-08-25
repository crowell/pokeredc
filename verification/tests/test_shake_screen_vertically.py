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

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
STACK = 0xD000
RETURN = 0xFFFF
EXPECTED = bytes.fromhex("cd6a5e0608c30952")

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
EXTRA_FIELDS = (
    "damage",
    "frequency",
    "tempo",
    "predef0",
    "predef1",
    "predef2",
    "predef3",
    "predef4",
    "predef5",
    "disable",
    "mutate_wy",
    "wy",
    "predef_id",
    "predef_parent_bank",
    "predef_bank",
)
STATE_FIELDS = (*SOUND_FIELDS, *EXTRA_FIELDS)
SOUND_CALL_FIELDS = (*SOUND_FIELDS, "damage", "frequency", "tempo")
VERTICAL_FIELDS = (
    "predef0",
    "predef1",
    "predef2",
    "predef3",
    "predef4",
    "predef5",
    "disable",
    "mutate_wy",
    "wy",
    "predef_id",
    "predef_parent_bank",
    "predef_bank",
    "loaded_rom_bank",
    "rom_bank",
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
    sound_call: claripy.ast.BV
    vertical_call: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _assembly_state(state: angr.SimState) -> claripy.ast.BV:
    return claripy.Concat(
        *(assembly_registers(state)[name] for name in REGISTERS),
        *(state.globals[name] for name in STATE_FIELDS),
    )


class AssemblySoundSummary(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:
        self.state.globals["sound_call"] = claripy.Concat(
            *(assembly_registers(self.state)[name] for name in REGISTERS),
            *(self.state.globals[name] for name in SOUND_CALL_FIELDS),
        )
        for name in REGISTERS:
            value = self.state.globals[f"sound_out_{name}"]
            if name == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, name, value)
        for name in SOUND_CALL_FIELDS:
            self.state.globals[name] = self.state.globals[f"sound_out_{name}"]
        self.jump(self._next_address)


class NativeSoundSummary(angr.SimProcedure):
    def run(self) -> None:
        address = self.state.regs.rdi
        self.state.globals["sound_call"] = self.state.memory.load(address, 27)
        self.state.memory.store(
            address,
            claripy.Concat(
                *(self.state.globals[f"sound_out_{name}"] for name in REGISTERS),
                *(
                    self.state.globals[f"sound_out_{name}"]
                    for name in SOUND_CALL_FIELDS
                ),
            ),
        )


class AssemblyVerticalSummary(angr.SimProcedure):
    def run(self) -> None:
        self.state.globals["vertical_call"] = claripy.Concat(
            *(assembly_registers(self.state)[name] for name in REGISTERS),
            *(self.state.globals[name] for name in VERTICAL_FIELDS),
        )
        for name in REGISTERS:
            value = self.state.globals[f"vertical_out_{name}"]
            if name == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, name, value)
        for name in VERTICAL_FIELDS:
            self.state.globals[name] = self.state.globals[f"vertical_out_{name}"]
        return_address = self.state.memory.load(
            self.state.regs.sp, 2, endness="Iend_LE"
        )
        self.state.regs.sp += 2
        self.jump(return_address)


class NativeVerticalSummary(angr.SimProcedure):
    def run(self) -> None:
        address = self.state.regs.rdi
        self.state.globals["vertical_call"] = self.state.memory.load(address, 22)
        self.state.memory.store(
            address,
            claripy.Concat(
                *(
                    self.state.globals[f"vertical_out_{name}"]
                    for name in REGISTERS
                ),
                *(
                    self.state.globals[f"vertical_out_{name}"]
                    for name in VERTICAL_FIELDS
                ),
            ),
        )


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for name in STATE_FIELDS:
        values[name] = claripy.BVS(f"{prefix}_{name}", 8)
    for family, fields in (
        ("sound", (*REGISTERS, *SOUND_CALL_FIELDS)),
        ("vertical", (*REGISTERS, *VERTICAL_FIELDS)),
    ):
        for name in fields:
            key = f"{family}_out_{name}"
            if name == "f":
                values[key] = claripy.Concat(
                    claripy.BVS(f"{prefix}_{family}_out_flags", 4),
                    claripy.BVV(0, 4),
                )
            else:
                values[key] = claripy.BVS(f"{prefix}_{key}", 8)
    return values


def _setup_globals(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    state.globals["sound_call"] = claripy.BVV(0, 27 * 8)
    state.globals["vertical_call"] = claripy.BVV(0, 22 * 8)
    for name in STATE_FIELDS:
        state.globals[name] = values[name]
    for family, fields in (
        ("sound", (*REGISTERS, *SOUND_CALL_FIELDS)),
        ("vertical", (*REGISTERS, *VERTICAL_FIELDS)),
    ):
        for name in fields:
            state.globals[f"{family}_out_{name}"] = values[
                f"{family}_out_{name}"
            ]


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    function = symbol_location(SYMBOLS, "ShakeScreenVertically")
    vertical = symbol_location(SYMBOLS, "AnimationShakeScreenVertically")
    assert linked_bytes(ROM, function, len(EXPECTED)) == EXPECTED
    project = angr.Project(
        rom_window(ROM, function.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": function.address,
        },
    )
    project.hook(
        function.address, AssemblySoundSummary(function.address + 3), length=3
    )
    project.hook(vertical.address, AssemblyVerticalSummary(), length=1)
    state = project.factory.blank_state(addr=function.address)
    set_assembly_registers(state, values)
    state.regs.sp = claripy.BVV(STACK, 16)
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    _setup_globals(state, values)
    ends = collect_returns(project, state, RETURN)
    assert len(ends) == 1
    return [
        Endpoint(
            **assembly_registers(end),
            state=_assembly_state(end),
            sound_call=end.globals["sound_call"],
            vertical_call=end.globals["vertical_call"],
            constraints=tuple(end.solver.constraints),
        )
        for end in ends
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_shake_screen_vertically")
    sound = project.loader.find_symbol("port_play_applying_attack_sound")
    vertical = project.loader.find_symbol("port_animation_shake_screen_vertically")
    assert function is not None and sound is not None and vertical is not None
    project.hook(sound.rebased_addr, NativeSoundSummary())
    project.hook(vertical.rebased_addr, NativeVerticalSummary())
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(
        NATIVE_STATE + 8,
        claripy.Concat(*(values[name] for name in STATE_FIELDS)),
    )
    _setup_globals(state, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            state=end.memory.load(NATIVE_STATE, 39),
            sound_call=end.globals["sound_call"],
            vertical_call=end.globals["vertical_call"],
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_shake_screen_vertically_pathwise_equivalence() -> None:
    values = _inputs("shake_screen_vertically")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "state", "sound_call", "vertical_call"),
    )
