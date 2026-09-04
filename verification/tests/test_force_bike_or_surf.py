from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
    REGISTERS, assembly_registers, native_registers, set_assembly_registers,
    store_native_registers, symbolic_registers,
)
from verification.harness.rom import (
    linked_bytes, rom_window, sm83_flags_to_z80, symbol_location,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xEFFF
H_LOADED_ROM_BANK = 0xFFB8
R_ROMB = 0x2000
W_STATUS_FLAGS4 = 0xD72E
W_LOW_HEALTH_ALARM = 0xD083
W_CHANNEL_SOUND_IDS = 0xC026
W_LAST_MUSIC_SOUND_ID = 0xCFCA
RED_SPRITE_BANK = 5
LOAD_PLAYER_SPRITE_GRAPHICS = 0x0997
EXPECTED = bytes.fromhex("0605219709cdd635")


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
    loader_call: claripy.ast.BV
    music_call: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _register_concat(state: angr.SimState, *, native: bool, pointer: int | None = None) -> claripy.ast.BV:
    registers = (native_registers(state, pointer) if native else
                 assembly_registers(state))
    return claripy.Concat(*(registers[name] for name in REGISTERS))


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        state.memory.load(base + H_LOADED_ROM_BANK, 1),
        state.memory.load(base + R_ROMB, 1),
        state.memory.load(base + W_STATUS_FLAGS4, 1),
        state.memory.load(base + W_LAST_MUSIC_SOUND_ID, 1),
        state.memory.load(base + W_LOW_HEALTH_ALARM, 1),
        state.memory.load(base + W_CHANNEL_SOUND_IDS, 3),
    )


class BankswitchAndLoaderBoundary(angr.SimProcedure):
    """Full Bankswitch transition with LoadPlayerSpriteGraphics as its callee."""

    def __init__(self, values: dict[str, claripy.ast.BV]) -> None:
        super().__init__()
        self.values = values

    def run(self) -> None:  # type: ignore[override]
        old_bank = self.state.memory.load(H_LOADED_ROM_BANK, 1)
        old_f = assembly_registers(self.state)["f"]
        self.state.regs.a = claripy.BVV(RED_SPRITE_BANK, 8)
        self.state.regs.b = claripy.BVV(0x35, 8)
        self.state.regs.c = claripy.BVV(0xE4, 8)
        self.state.memory.store(H_LOADED_ROM_BANK, claripy.BVV(RED_SPRITE_BANK, 8))
        self.state.memory.store(R_ROMB, claripy.BVV(RED_SPRITE_BANK, 8))
        self.state.globals["loader_call"] = claripy.Concat(
            _register_concat(self.state, native=False),
            self.state.memory.load(H_LOADED_ROM_BANK, 1),
            self.state.memory.load(R_ROMB, 1),
        )
        for name in REGISTERS:
            value = self.values[f"loader_{name}"]
            setattr(self.state.regs, name,
                    sm83_flags_to_z80(value) if name == "f" else value)
        self.state.memory.store(H_LOADED_ROM_BANK, self.values["loader_bank"])
        self.state.memory.store(R_ROMB, self.values["loader_romb"])
        self.state.regs.a = old_bank
        self.state.regs.b = old_bank
        self.state.regs.c = old_f
        self.state.memory.store(H_LOADED_ROM_BANK, old_bank)
        self.state.memory.store(R_ROMB, old_bank)
        ret = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp += 2
        self.jump(ret)


class NativeLoaderBoundary(angr.SimProcedure):
    def __init__(self, values: dict[str, claripy.ast.BV]) -> None:
        super().__init__()
        self.values = values

    def run(self, pointer: claripy.ast.BV, memory: claripy.ast.BV) -> None:  # type: ignore[override]
        self.state.globals["loader_call"] = claripy.Concat(
            _register_concat(self.state, native=True, pointer=pointer),
            self.state.memory.load(memory + H_LOADED_ROM_BANK, 1),
            self.state.memory.load(memory + R_ROMB, 1),
        )
        for offset, name in enumerate(REGISTERS):
            self.state.memory.store(pointer + offset, self.values[f"loader_{name}"])
        self.state.memory.store(memory + H_LOADED_ROM_BANK,
                                self.values["loader_bank"])
        self.state.memory.store(memory + R_ROMB, self.values["loader_romb"])
        self.ret()


class MusicBoundary(angr.SimProcedure):
    def __init__(self, values: dict[str, claripy.ast.BV], *, native: bool) -> None:
        super().__init__()
        self.values = values
        self.native = native

    def _finish(self, pointer: claripy.ast.BV | None,
                callback: claripy.ast.BV | None = None,
                callback_globals: claripy.ast.BV | None = None) -> None:
        if self.native:
            assert pointer is not None
            self.state.globals["music_call"] = claripy.Concat(
                _register_concat(self.state, native=True, pointer=pointer),
                self.state.memory.load(pointer + 8, 1),
                self.state.memory.load(pointer + 9, 1),
                self.state.memory.load(pointer + 11, 1),
                self.state.memory.load(pointer + 12, 3),
            )
            assert callback is not None and callback_globals is not None
            for offset, name in enumerate(REGISTERS):
                self.state.memory.store(pointer + offset,
                                        self.state.memory.load(callback + offset, 1))
            self.state.memory.store(pointer + 8,
                                    self.state.memory.load(callback_globals, 1))
            self.state.memory.store(pointer + 9,
                                    self.state.memory.load(callback_globals + 1, 1))
        else:
            self.state.globals["music_call"] = claripy.Concat(
                _register_concat(self.state, native=False),
                self.values["music_status_flags4"],
                self.values["music_last_music_sound_id"],
                self.values["low_health_alarm"],
                self.values["channel_0"], self.values["channel_1"],
                self.values["channel_2"],
            )
            for name in REGISTERS:
                value = self.values[f"music_{name}"]
                setattr(self.state.regs, name,
                        sm83_flags_to_z80(value) if name == "f" else value)
            self.state.memory.store(W_STATUS_FLAGS4,
                                    self.values["music_callback_status_flags4"])
            self.state.memory.store(W_LAST_MUSIC_SOUND_ID,
                                    self.values["music_callback_last_music_sound_id"])
        if self.state.solver.eval(self.values["low_health_alarm"]) == 0:
            for i in range(3):
                self.state.memory.store((pointer + 12 + i) if self.native
                                        else W_CHANNEL_SOUND_IDS + i,
                                        claripy.BVV(0, 8))
        if self.native:
            self.ret()
        else:
            self.inhibit_autoret = True
            self.jump(RETURN)

    def run(self, *args: claripy.ast.BV) -> None:  # type: ignore[override]
        self._finish(self.state.regs.rdi if self.native else None,
                     self.state.regs.rsi if self.native else None,
                     self.state.regs.rdx if self.native else None)


def _values(prefix: str, low_health_alarm: int) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for name in REGISTERS:
        if name == "f":
            values[f"loader_{name}"] = claripy.Concat(
                claripy.BVS(f"{prefix}_loader_{name}", 4), claripy.BVV(0, 4))
            values[f"music_{name}"] = claripy.Concat(
                claripy.BVS(f"{prefix}_music_{name}", 4), claripy.BVV(0, 4))
        else:
            values[f"loader_{name}"] = claripy.BVS(f"{prefix}_loader_{name}", 8)
            values[f"music_{name}"] = claripy.BVS(f"{prefix}_music_{name}", 8)
    values["bank"] = claripy.BVS(f"{prefix}_bank", 8)
    values["romb"] = claripy.BVS(f"{prefix}_romb", 8)
    values["loader_bank"] = claripy.BVS(f"{prefix}_loader_bank", 8)
    values["loader_romb"] = claripy.BVS(f"{prefix}_loader_romb", 8)
    values["music_status_flags4"] = claripy.BVS(f"{prefix}_status4", 8)
    values["music_last_music_sound_id"] = claripy.BVS(f"{prefix}_last_music", 8)
    values["music_callback_status_flags4"] = claripy.BVS(f"{prefix}_callback_status4", 8)
    values["music_callback_last_music_sound_id"] = claripy.BVS(f"{prefix}_callback_last_music", 8)
    values["low_health_alarm"] = claripy.BVV(low_health_alarm, 8)
    for i in range(3):
        values[f"channel_{i}"] = claripy.BVS(f"{prefix}_channel_{i}", 8)
    return values


def _setup(state: angr.SimState, values: dict[str, claripy.ast.BV], base: int) -> None:
    state.memory.store(base + H_LOADED_ROM_BANK, values["bank"])
    state.memory.store(base + R_ROMB, values["romb"])
    state.memory.store(base + W_STATUS_FLAGS4, values["music_status_flags4"])
    state.memory.store(base + W_LAST_MUSIC_SOUND_ID,
                       values["music_last_music_sound_id"])
    state.memory.store(base + W_LOW_HEALTH_ALARM, values["low_health_alarm"])
    for i in range(3):
        state.memory.store(base + W_CHANNEL_SOUND_IDS + i, values[f"channel_{i}"])


def _endpoint(state: angr.SimState, *, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    return Endpoint(
        **(native_registers(state, NATIVE_STATE) if native
           else assembly_registers(state)),
        memory=_memory(state, base),
        loader_call=state.globals["loader_call"],
        music_call=state.globals["music_call"],
        constraints=tuple(state.solver.constraints),
    )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "ForceBikeOrSurf")
    bankswitch = symbol_location(SYMBOLS, "Bankswitch")
    music = symbol_location(SYMBOLS, "PlayDefaultMusic")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    project.hook(bankswitch.address, BankswitchAndLoaderBoundary(values), length=1)
    project.hook(music.address, MusicBoundary(values, native=False), length=1)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    _setup(state, values, 0)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN)
    assert not manager.errored and len(manager.found) == 1
    return [_endpoint(manager.found[0], native=False)]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_force_bike_or_surf")
    loader = project.loader.find_symbol("port_load_player_sprite_graphics")
    music = project.loader.find_symbol("port_play_default_music")
    assert function is not None and loader is not None and music is not None
    project.hook(loader.rebased_addr, NativeLoaderBoundary(values))
    project.hook(music.rebased_addr, MusicBoundary(values, native=True))
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    store_native_registers(state, NATIVE_STATE + 8,
                           {name: values[f"music_{name}"] for name in REGISTERS})
    state.memory.store(NATIVE_STATE + 16, values["music_callback_status_flags4"])
    state.memory.store(NATIVE_STATE + 17,
                       values["music_callback_last_music_sound_id"])
    _setup(state, values, NATIVE_MEMORY)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [_endpoint(manager.deadended[0], native=True)]


@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),
                    reason="run `make red`")
@pytest.mark.parametrize("low_health_alarm", (0, 0x80))
def test_force_bike_or_surf_pathwise_equivalence(low_health_alarm: int) -> None:
    values = _values(f"force_bike_or_surf_{low_health_alarm}", low_health_alarm)
    assert_pathwise_equivalent(
        _assembly(values), _native(values),
        (*REGISTERS, "memory", "loader_call", "music_call"),
    )
