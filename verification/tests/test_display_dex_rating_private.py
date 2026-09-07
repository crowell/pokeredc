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
    linked_bytes,
    rom_window,
    sm83_flags_to_z80,
    symbol_location,
    z80_flags_to_sm83,
)
from verification.harness.sm83_shims import (
    Sm83CpImmediate,
    Sm83CpRegister,
    Sm83LoadAHighImmediate,
    Sm83LoadAImmediate,
    Sm83ResRegister,
    Sm83StoreAHighImmediate,
    Sm83StoreAImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
RETURN = 0xEFFF
STACK = 0xD000

W_TEXT_BOX_ID = 0xD125
W_NUM_SET_BITS = 0xD11E
W_POKEDEX_OWNED = 0xD2F7
W_POKEDEX_SEEN = 0xD30A
W_EVENT_FLAGS = 0xD747
W_DEX_RATING = 0xCC5B
H_DEX_SEEN = 0xFFDB
H_DEX_OWNED = 0xFFDC
H_LOADED_BANK = 0xFFB8
R_ROMB = 0x2000
POKEDEX_BYTES = 19

STATE_FIELDS = (
    "new_sound_id",
    "audio_fade_out_control",
    "audio_rom_bank",
    "audio_saved_bank",
    "last_music_sound_id",
    "stop_sound_called",
    "rating_sound_called",
    "default_music_called",
    "wait_joy5",
    "wait_down_arrow_blink1",
    "wait_down_arrow_blink2",
    "wait_b",
    "wait_c",
    "wait_d",
    "wait_e",
    "wait_h",
    "wait_l",
)

EXPECTED_BODY = bytes.fromhex(
    "210ad30613cd7f2bfa1ed1e0db21f7d20613cd7f2bfa1ed1e0dc21d1412a47"
    "f0dcb83804232318f52a666ffa47d7cb5fcb9fea47d72016e521cc41cd493ce1"
    "cd493c061f213b51cdd635c36538115bccf0db1213f0dc12132afe5028041213"
    "18f712c9"
)

TIERS = tuple(range(0, 151, 10))
SFX = (
    (10, 0xA5, 0x1F),
    (40, 0x91, 2),
    (60, 0x86, 2),
    (90, 0x9A, 8),
    (120, 0x86, 8),
    (150, 0x94, 2),
    (256, 0x89, 2),
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
    fields: claripy.ast.BV
    calls: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _sfx_for(owned: int) -> tuple[int, int]:
    for limit, sound, bank in SFX:
        if owned < limit:
            return sound, bank
    raise AssertionError("unreachable")


class PrintTextSummary(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.state.memory.store(W_TEXT_BOX_ID, claripy.BVV(1, 8))
        self.state.regs.b = claripy.BVV(0xC4, 8)
        self.state.regs.c = claripy.BVV(0xB9, 8)
        self.jump(self.next_address)


class LoadHLImmediate(angr.SimProcedure):
    def __init__(self, value: int, next_address: int) -> None:
        super().__init__()
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.state.regs.h = claripy.BVV(self.value >> 8, 8)
        self.state.regs.l = claripy.BVV(self.value & 0xFF, 8)
        self.jump(self.next_address)


class LoadDEImmediate(angr.SimProcedure):
    def __init__(self, value: int, next_address: int) -> None:
        super().__init__()
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.state.regs.d = claripy.BVV(self.value >> 8, 8)
        self.state.regs.e = claripy.BVV(self.value & 0xFF, 8)
        self.jump(self.next_address)


class LoadAAtHLIncrement(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        address = claripy.Concat(self.state.regs.h, self.state.regs.l)
        self.state.regs.a = self.state.memory.load(address, 1)
        incremented = address + 1
        self.state.regs.h = incremented[15:8]
        self.state.regs.l = incremented[7:0]
        self.jump(self.next_address)


class LoadHAtHL(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        address = claripy.Concat(self.state.regs.h, self.state.regs.l)
        self.state.regs.h = self.state.memory.load(address, 1)
        self.jump(self.next_address)


class IncrementPair(angr.SimProcedure):
    def __init__(self, high: str, low: str, next_address: int) -> None:
        super().__init__()
        self.high = high
        self.low = low
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        value = claripy.Concat(getattr(self.state.regs, self.high),
                               getattr(self.state.regs, self.low)) + 1
        setattr(self.state.regs, self.high, value[15:8])
        setattr(self.state.regs, self.low, value[7:0])
        self.jump(self.next_address)


class StoreAAtDE(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        address = claripy.Concat(self.state.regs.d, self.state.regs.e)
        self.state.memory.store(address, self.state.regs.a)
        self.jump(self.next_address)


class BitA(angr.SimProcedure):
    def __init__(self, bit: int, next_address: int) -> None:
        super().__init__()
        self.bit = bit
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        carry = self.state.regs.f & 1
        zero = ((self.state.regs.a >> self.bit) & 1) == 0
        self.state.regs.f = carry | 0x10 | claripy.If(
            zero, claripy.BVV(0x40, 8), claripy.BVV(0, 8)
        )
        self.jump(self.next_address)


class AssemblyCountSummary(angr.SimProcedure):
    def __init__(self, next_address: int, key: str, count: int) -> None:
        super().__init__()
        self.next_address = next_address
        self.key = key
        self.count = count

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        registers = assembly_registers(self.state)
        address = claripy.Concat(registers["h"], registers["l"])
        concrete_address = self.state.solver.eval(address)
        bitmap = self.state.memory.load(concrete_address, POKEDEX_BYTES)
        call = claripy.Concat(
            *(registers[name] for name in REGISTERS), bitmap
        )
        self.state.globals[self.key] = call
        count = claripy.BVV(self.count, 8)
        end = concrete_address + POKEDEX_BYTES
        self.state.regs.a = count
        self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0xC0, 8))
        self.state.regs.b = claripy.BVV(0, 8)
        self.state.regs.c = count
        self.state.regs.d = claripy.BVV(0, 8)
        self.state.regs.e = claripy.BVV(0, 8)
        self.state.regs.h = claripy.BVV(end >> 8, 8)
        self.state.regs.l = claripy.BVV(end & 0xFF, 8)
        self.state.memory.store(W_NUM_SET_BITS, count)
        self.jump(self.next_address)


class NativeCountSummary(angr.SimProcedure):
    def run(self, state_address: claripy.ast.BV,
            memory_address: claripy.ast.BV) -> None:  # type: ignore[override]
        registers = native_registers(self.state, state_address)
        address = claripy.Concat(registers["h"], registers["l"])
        concrete_address = self.state.solver.eval(address)
        memory_base = self.state.solver.eval(memory_address)
        bitmap = self.state.memory.load(
            memory_base + concrete_address, POKEDEX_BYTES
        )
        call = claripy.Concat(
            *(registers[name] for name in REGISTERS), bitmap
        )
        self.state.globals[
            "count_seen_call" if concrete_address == W_POKEDEX_SEEN
            else "count_owned_call"
        ] = call
        concrete_bitmap = self.state.solver.eval(bitmap)
        count = claripy.BVV(concrete_bitmap.bit_count(), 8)
        end = concrete_address + POKEDEX_BYTES
        output = (
            count, claripy.BVV(0xC0, 8), claripy.BVV(0, 8), count,
            claripy.BVV(0, 8), claripy.BVV(0, 8),
            claripy.BVV(end >> 8, 8), claripy.BVV(end & 0xFF, 8),
        )
        for offset, value in enumerate(output):
            self.state.memory.store(state_address + offset, value)
        self.state.memory.store(state_address + 8, count)


class BankswitchSfxSummary(angr.SimProcedure):
    def __init__(self, owned: int, next_address: int) -> None:
        super().__init__()
        self.owned = owned
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        assert self.state.solver.eval(self.state.regs.b) == 0x1F
        assert self.state.solver.eval(self.state.regs.h) == 0x51
        assert self.state.solver.eval(self.state.regs.l) == 0x3B
        saved_bank = self.state.memory.load(H_LOADED_BANK, 1)
        saved_f = z80_flags_to_sm83(self.state.regs.f)
        sound, bank = _sfx_for(self.owned)
        self.state.globals["new_sound_id"] = claripy.BVV(sound, 8)
        self.state.globals["audio_fade_out_control"] = claripy.BVV(0, 8)
        self.state.globals["audio_rom_bank"] = claripy.BVV(bank, 8)
        self.state.globals["audio_saved_bank"] = claripy.BVV(bank, 8)
        self.state.globals["last_music_sound_id"] = claripy.BVV(0, 8)
        self.state.globals["stop_sound_called"] = claripy.BVV(1, 8)
        self.state.globals["rating_sound_called"] = claripy.BVV(1, 8)
        self.state.globals["default_music_called"] = claripy.BVV(1, 8)
        self.state.regs.a = saved_bank
        self.state.regs.b = saved_bank
        self.state.regs.c = saved_f
        self.state.memory.store(H_LOADED_BANK, saved_bank)
        self.state.memory.store(R_ROMB, saved_bank)
        self.jump(self.next_address)


class WaitSummary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        if self.state.solver.eval(self.state.globals["wait_joy5"] & 3) != 0:
            self.state.regs.a = self.state.globals["wait_down_arrow_blink1"]
            for register in ("b", "c", "d", "e", "h", "l"):
                setattr(self.state.regs, register, self.state.globals["wait_" + register])
        self.state.regs.sp = claripy.BVV(STACK + 2, 16)
        self.inhibit_autoret = True
        self.jump(RETURN)


def _bitmap(count: int) -> bytes:
    return bytes(0xFF if i < count // 8 else
                 ((1 << (count % 8)) - 1 if i == count // 8 else 0)
                 for i in range(POKEDEX_BYTES))


def _setup_memory(state: angr.SimState, base: int, owned: int, hall: bool) -> None:
    state.memory.store(base + W_POKEDEX_SEEN, _bitmap(37))
    state.memory.store(base + W_POKEDEX_OWNED, _bitmap(owned))
    state.memory.store(base + W_EVENT_FLAGS, claripy.BVV(0xA5 | (8 if hall else 0), 8))
    state.memory.store(base + W_NUM_SET_BITS, claripy.BVV(0x6D, 8))
    state.memory.store(base + W_TEXT_BOX_ID, claripy.BVV(0xBE, 8))
    state.memory.store(base + H_DEX_SEEN, claripy.BVV(0xAD, 8))
    state.memory.store(base + H_DEX_OWNED, claripy.BVV(0xDE, 8))
    state.memory.store(base + H_LOADED_BANK, claripy.BVV(7, 8))
    state.memory.store(base + R_ROMB, claripy.BVV(7, 8))
    state.memory.store(base + W_DEX_RATING, bytes.fromhex("c0c1c2c3c4c5c6"))


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        state.memory.load(base + W_NUM_SET_BITS, 1),
        state.memory.load(base + W_EVENT_FLAGS, 1),
        state.memory.load(base + H_DEX_SEEN, 1),
        state.memory.load(base + H_DEX_OWNED, 1),
        state.memory.load(base + W_TEXT_BOX_ID, 1),
        state.memory.load(base + H_LOADED_BANK, 1),
        state.memory.load(base + R_ROMB, 1),
        state.memory.load(base + W_DEX_RATING, 7),
    )


def _assembly(inputs: dict[str, claripy.ast.BV], owned: int, hall: bool) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "DisplayDexRating")
    window = rom_window(ROM, location.bank)
    project = angr.Project(
        window,
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    project.hook(0x416E, AssemblyCountSummary(0x4171, "count_seen_call", 37), length=3)
    project.hook(0x4174, Sm83StoreAHighImmediate(0xDB, 0x4176), length=2)
    project.hook(0x417B, AssemblyCountSummary(0x417E, "count_owned_call", owned), length=3)
    project.hook(0x4181, Sm83StoreAHighImmediate(0xDC, 0x4183), length=2)
    project.hook(0x4183, LoadHLImmediate(0x41D1, 0x4186), length=3)
    project.hook(0x4186, LoadAAtHLIncrement(0x4187), length=1)
    project.hook(0x4188, Sm83LoadAHighImmediate(0xDC, 0x418A), length=2)
    project.hook(0x418A, Sm83CpRegister("b", 0x418B), length=1)
    project.hook(0x418D, IncrementPair("h", "l", 0x418E), length=1)
    project.hook(0x418E, IncrementPair("h", "l", 0x418F), length=1)
    project.hook(0x4191, LoadAAtHLIncrement(0x4192), length=1)
    project.hook(0x4192, LoadHAtHL(0x4193), length=1)
    project.hook(0x4194, Sm83LoadAImmediate(W_EVENT_FLAGS, 0x4197), length=3)
    project.hook(0x4197, BitA(3, 0x4199), length=2)
    project.hook(0x4199, Sm83ResRegister(3, "a", 0x419B), length=2)
    project.hook(0x419B, Sm83StoreAImmediate(W_EVENT_FLAGS, 0x419E), length=3)
    project.hook(0x41A4, PrintTextSummary(0x41A7), length=3)
    project.hook(0x41A8, PrintTextSummary(0x41AB), length=3)
    project.hook(0x41B0, BankswitchSfxSummary(owned, 0x41B3), length=3)
    project.hook(0x3865, WaitSummary())
    project.hook(0x41B6, LoadDEImmediate(W_DEX_RATING, 0x41B9), length=3)
    project.hook(0x41B9, Sm83LoadAHighImmediate(0xDB, 0x41BB), length=2)
    project.hook(0x41BB, StoreAAtDE(0x41BC), length=1)
    project.hook(0x41BC, IncrementPair("d", "e", 0x41BD), length=1)
    project.hook(0x41BD, Sm83LoadAHighImmediate(0xDC, 0x41BF), length=2)
    project.hook(0x41BF, StoreAAtDE(0x41C0), length=1)
    project.hook(0x41C0, IncrementPair("d", "e", 0x41C1), length=1)
    project.hook(0x41C1, LoadAAtHLIncrement(0x41C2), length=1)
    project.hook(0x41C2, Sm83CpImmediate(0x50, 0x41C4), length=2)
    project.hook(0x41C6, StoreAAtDE(0x41C7), length=1)
    project.hook(0x41C7, IncrementPair("d", "e", 0x41C8), length=1)
    project.hook(0x41CA, StoreAAtDE(0x41CB), length=1)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    state.regs.sp = claripy.BVV(STACK, 16)
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    _setup_memory(state, 0, owned, hall)
    for field in STATE_FIELDS:
        state.globals[field] = inputs[field]
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN, num_find=1)
    assert not manager.errored and len(manager.found) == 1
    result = manager.found[0]
    assert "count_owned_call" in result.globals, (
        list(result.globals.keys()), [hex(x) for x in result.history.bbl_addrs]
    )
    return [Endpoint(
        **assembly_registers(result),
        memory=_memory(result, 0),
        fields=claripy.Concat(*(result.globals[f] for f in STATE_FIELDS)),
        calls=claripy.Concat(result.globals["count_seen_call"],
                             result.globals["count_owned_call"]),
        constraints=tuple(result.solver.constraints),
    )]


def _native(inputs: dict[str, claripy.ast.BV], owned: int, hall: bool) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_display_dex_rating_private")
    count = project.loader.find_symbol("port_count_set_bits")
    assert function is not None and count is not None
    project.hook(count.rebased_addr, NativeCountSummary())
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, inputs)
    for offset, field in enumerate(STATE_FIELDS, 8):
        state.memory.store(NATIVE_STATE + offset, inputs[field])
    _setup_memory(state, NATIVE_MEMORY, owned, hall)
    window = rom_window(ROM, 0x11).getvalue()
    state.memory.store(NATIVE_MEMORY + 0x41CC, window[0x41CC:0x4251])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    result = manager.deadended[0]
    return [Endpoint(
        **native_registers(result, NATIVE_STATE),
        memory=_memory(result, NATIVE_MEMORY),
        fields=result.memory.load(NATIVE_STATE + 8, len(STATE_FIELDS)),
        calls=claripy.Concat(result.globals["count_seen_call"],
                             result.globals["count_owned_call"]),
        constraints=tuple(result.solver.constraints),
    )]


@pytest.mark.skipif(not ELF.exists(), reason="native ports not built")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="ROM not built")
@pytest.mark.parametrize("owned", TIERS)
@pytest.mark.parametrize("hall", (False, True), ids=("normal", "hall-of-fame"))
def test_display_dex_rating_private_pathwise_equivalence(owned: int, hall: bool) -> None:
    inputs = symbolic_registers(f"dex_{owned}_{int(hall)}")
    for field in STATE_FIELDS:
        inputs[field] = claripy.BVS(f"dex_{owned}_{int(hall)}_{field}", 8)
    inputs["wait_joy5"] = claripy.BVV(1, 8)
    assert linked_bytes(ROM, symbol_location(SYMBOLS, "DisplayDexRating"),
                        len(EXPECTED_BODY)) == EXPECTED_BODY
    assert_pathwise_equivalent(
        _assembly(inputs, owned, hall),
        _native(inputs, owned, hall),
        (*REGISTERS, "memory", "fields", "calls"),
    )
