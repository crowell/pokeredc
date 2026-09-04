"""Path-equivalence proof for PrintNamingText."""

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
from verification.harness.sm83_shims import (
    Sm83AddHlRegisterPair,
    Sm83AndRegister,
    Sm83DecRegister,
    Sm83LoadAImmediate,
    Sm83StoreAImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_ELF = ROOT / "verification/build/ports.elf"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD800
RETURN = 0xFFFF
W_TILE_MAP = 0xC3A0
W_NAMING_TYPE = 0xD07D
W_CUR_SPECIES = 0xCF91
W_MON_SPECIES = 0xCD5D
W_NAMED = 0xD11E
W_POKEDEX = 0xD11E
W_NAME_BUFFER = 0xCD6D
YOUR = 0x693F
RIVAL = 0x6945
NAME = 0x694D
NICKNAME = 0x6953

EXPECTED = bytes.fromhex(
    "21b4c3fa7dd0113f69a728301145693d282afa91cfea5dcdf5061c218258cdd635f1ea1ed1cd9e2f21b8c3cd55192101000936c921ddc31153691808cd55196960114d69c355"
)
TEXT = {
    YOUR: bytes.fromhex("988e94917f50"),
    RIVAL: bytes.fromhex("918895808bbd7f50"),
    NAME: bytes.fromhex("8d808c84e650"),
    NICKNAME: bytes.fromhex("8d88828a8d808c84e650"),
}


@dataclass(frozen=True)
class Endpoint:
    registers: claripy.ast.BV
    memory: claripy.ast.BV
    sprite_call: claripy.ast.BV
    name_call: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _reg_concat(state: angr.SimState, native: bool) -> claripy.ast.BV:
    values = native_registers(state, NATIVE_STATE) if native else assembly_registers(state)
    return claripy.Concat(*(values[name] for name in REGISTERS))


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        state.memory.load(base + W_TILE_MAP, 80),
        state.memory.load(base + W_MON_SPECIES, 1),
        state.memory.load(base + W_POKEDEX, 1),
        state.memory.load(base + W_NAMED, 1),
        state.memory.load(base + W_NAME_BUFFER, 11),
    )


def _read_reg(state: angr.SimState, base: int | None, name: str):
    if base is None:
        return getattr(state.regs, name)
    return state.memory.load(base + {"a": 0, "f": 1, "b": 2, "c": 3,
                                   "d": 4, "e": 5, "h": 6, "l": 7}[name], 1)


def _write_reg(state: angr.SimState, base: int | None, name: str, value) -> None:
    if base is None:
        setattr(state.regs, name, value)
    else:
        if isinstance(value, int):
            value = claripy.BVV(value, 8)
        state.memory.store(base + {"a": 0, "f": 1, "b": 2, "c": 3,
                                   "d": 4, "e": 5, "h": 6, "l": 7}[name],
                           value)


class PlaceStringSummary(angr.SimProcedure):
    def __init__(self, next_address: int | None = None) -> None:
        super().__init__()
        self._next = next_address

    def _apply(self, registers=None, memory=None) -> None:
        base = None if registers is None else registers
        mem = 0 if memory is None else memory
        if base is None:
            saved_hl = self.state.regs.hl
            source = self.state.regs.de
        else:
            high_h = _read_reg(self.state, base, "h")
            low_l = _read_reg(self.state, base, "l")
            high_d = _read_reg(self.state, base, "d")
            low_e = _read_reg(self.state, base, "e")
            saved_hl = (claripy.ZeroExt(8, high_h) << 8) | \
                claripy.ZeroExt(8, low_l)
            source = (claripy.ZeroExt(8, high_d) << 8) | \
                claripy.ZeroExt(8, low_e)
        dest = saved_hl
        source_int = int(self.state.solver.eval(source))
        source_int = {
            0x3f: YOUR, 0x45: RIVAL, 0x4d: NAME, 0x53: NICKNAME,
            0x6d: W_NAME_BUFFER,
        }.get(source_int, source_int)
        source = claripy.BVV(source_int, 16)
        lengths = {YOUR: 6, RIVAL: 8, NAME: 6, NICKNAME: 10,
                   W_NAME_BUFFER: 11}
        def address(value):
            if base is None:
                return value
            return mem + claripy.ZeroExt(64 - value.size(), value)

        for _ in range(lengths[source_int]):
            char = self.state.memory.load(address(source), 1)
            self.state.memory.store(address(dest), char)
            dest = dest + 1
            source = source + 1
        _write_reg(self.state, base, "a", 0x50)
        _write_reg(self.state, base, "b", dest[15:8])
        _write_reg(self.state, base, "c", dest[7:0])
        _write_reg(self.state, base, "d", source[15:8])
        _write_reg(self.state, base, "e", source[7:0])
        _write_reg(self.state, base, "h", saved_hl[15:8])
        _write_reg(self.state, base, "l", saved_hl[7:0])
        _write_reg(self.state, base, "f",
                   0x42 if base is None else 0xC0)

    def run(self, registers=None, memory=None) -> None:  # type: ignore[override]
        self._apply(registers, memory)
        if self._next is not None:
            self.jump(self._next)


class GetMonNameSummary(angr.SimProcedure):
    def __init__(self, next_address: int | None = None) -> None:
        super().__init__()
        self._next = next_address

    def run(self, state_ptr=None, memory=None) -> None:  # type: ignore[override]
        base = 0 if memory is None else memory
        if state_ptr is None:
            name = self.state.globals["name_bytes"]
            self.state.globals["name_call"] = self.state.memory.load(
                base + W_NAMED, 1)
            regs_base = None
        else:
            name = self.state.globals["name_bytes"]
            self.state.globals["name_call"] = self.state.memory.load(
                base + W_NAMED, 1)
            regs_base = state_ptr
        for index, value in enumerate(name):
            self.state.memory.store(base + W_NAME_BUFFER + index, value)
        _write_reg(self.state, regs_base, "d", 0xCD)
        _write_reg(self.state, regs_base, "e", 0x6D)
        if self._next is not None:
            self.jump(self._next)
class NativePlaceStringSummary(PlaceStringSummary):
    def run(self, registers, memory) -> None:  # type: ignore[override]
        self._apply(registers, memory)


class NativeGetMonNameSummary(GetMonNameSummary):
    def run(self, state_ptr, memory) -> None:  # type: ignore[override]
        super().run(state_ptr, memory)





class SpriteSummary(angr.SimProcedure):
    def __init__(self, next_address: int | None = None) -> None:
        super().__init__()
        self._next = next_address

    def run(self, state_ptr=None, memory=None) -> None:  # type: ignore[override]
        base = 0 if memory is None else memory
        if state_ptr is None:
            self.state.globals["sprite_call"] = self.state.memory.load(
                base + W_MON_SPECIES, 1)
            sprite_id = self.state.globals["sprite_id"]
            flags = self.state.globals["sprite_flags"]
        else:
            self.state.globals["sprite_call"] = self.state.memory.load(
                base + W_MON_SPECIES, 1)
            sprite_id = self.state.memory.load(state_ptr + 10, 1)
            flags = self.state.memory.load(state_ptr + 12, 1)
        self.state.memory.store(base + W_POKEDEX, self.state.globals["pokedex_num"])
        self.state.memory.store(base + W_MON_SPECIES,
                                self.state.memory.load(base + W_CUR_SPECIES, 1))
        _write_reg(self.state, None if state_ptr is None else state_ptr, "a", sprite_id)
        _write_reg(self.state, None if state_ptr is None else state_ptr, "f", flags)
        if self._next is not None:
            self.jump(self._next)

class NativeSpriteSummary(SpriteSummary):
    def run(self, state_ptr, memory) -> None:  # type: ignore[override]
        super().run(state_ptr, memory)

class LoadPair(angr.SimProcedure):
    def __init__(self, high: int, low: int, next_address: int,
                 high_register: str = "h", low_register: str = "l") -> None:
        super().__init__()
        self.high = high
        self.low = low
        self._next = next_address
        self.high_register = high_register
        self.low_register = low_register

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.high_register, self.high)
        setattr(self.state.regs, self.low_register, self.low)
        pair = (self.high << 8) | self.low
        if self.high_register == "d":
            self.state.regs.de = pair
        else:
            self.state.regs.hl = pair
        self.jump(self._next)
class LoadAConstant(angr.SimProcedure):
    def __init__(self, value: int, next_address: int) -> None:
        super().__init__()
        self.value = value
        self._next = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.value
        self.jump(self._next)


def _setup(state: angr.SimState, values, base: int) -> None:
    state.memory.store(base + W_NAMING_TYPE, values["type"])
    state.memory.store(base + W_CUR_SPECIES, values["species"])
    for address, data in TEXT.items():
        for offset, byte in enumerate(data):
            state.memory.store(base + address + offset, claripy.BVV(byte, 8))

    for offset, byte in enumerate(values["tile_map"]):
        state.memory.store(base + W_TILE_MAP + offset, byte)
    state.memory.store(base + W_MON_SPECIES, values["species"])
    state.memory.store(base + W_POKEDEX, values["pokedex_num"])
    state.memory.store(base + W_NAMED, values["named_initial"])
    for offset, byte in enumerate(values["name"]):
        state.memory.store(base + W_NAME_BUFFER + offset, byte)
    state.globals["name_bytes"] = tuple(
        values["name"][offset] for offset in range(11))
    state.globals["sprite_id"] = values["sprite_id"]
    state.globals["pokedex_num"] = values["pokedex_num"]
    state.globals["sprite_flags"] = values["sprite_flags"]
    state.globals["sprite_call"] = claripy.BVV(0, 8)
    state.globals["name_call"] = claripy.BVV(0, 8)


def _values(prefix: str, naming_type: int):
    values = symbolic_registers(prefix)
    values["type"] = claripy.BVV(naming_type, 8)
    values["species"] = claripy.BVS(f"{prefix}_species", 8)
    values["sprite_id"] = claripy.BVS(f"{prefix}_sprite_id", 8)
    values["pokedex_num"] = claripy.BVS(f"{prefix}_pokedex_num", 8)
    values["sprite_flags"] = claripy.Concat(
        claripy.BVS(f"{prefix}_sprite_flags", 4), claripy.BVV(0, 4))
    values["named_initial"] = claripy.BVS(f"{prefix}_named_initial", 8)
    values["tile_map"] = tuple(
        claripy.BVS(f"{prefix}_tile_{i}", 8) for i in range(80))
    values["name"] = tuple(
        [claripy.BVS(f"{prefix}_name_{i}", 8) for i in range(10)]
        + [claripy.BVV(0x50, 8)])
    return values

def _hook_assembly(project: angr.Project, base: int, naming_type: int) -> None:
    project.hook(base + 0x06, LoadPair(0x69, 0x3f, base + 0x09, "d", "e"),
                 length=3)
    project.hook(base + 0x00, LoadPair(0xc3, 0xb4, base + 0x03), length=3)
    project.hook(base + 0x03, LoadAConstant(naming_type, base + 0x06), length=3)
    project.hook(base + 0x0c, LoadPair(0x69, 0x45, base + 0x0f, "d", "e"),
                 length=3)
    project.hook(base + 0x28, LoadPair(0xc3, 0xb8, base + 0x2b), length=3)
    project.hook(base + 0x2e, LoadPair(0, 1, base + 0x31), length=3)
    project.hook(base + 0x34, LoadPair(0xc3, 0xdd, base + 0x37), length=3)
    project.hook(base + 0x37, LoadPair(0x69, 0x53, base + 0x3a, "d", "e"),
                 length=3)
    project.hook(base + 0x41, LoadPair(0x69, 0x4d, base + 0x44, "d", "e"),
                 length=3)
    project.hook(base + 0x09, Sm83AndRegister("a", base + 0x0a), length=1)
    project.hook(base + 0x0f, Sm83DecRegister("a", base + 0x10), length=1)
    project.hook(base + 0x18, SpriteSummary(base + 0x22), length=10)
    project.hook(base + 0x22, Sm83StoreAImmediate(W_NAMED, base + 0x25),
                 length=3)
    project.hook(base + 0x25, GetMonNameSummary(base + 0x28), length=3)
    project.hook(base + 0x2b, PlaceStringSummary(base + 0x2e), length=3)
    project.hook(base + 0x31, Sm83AddHlRegisterPair("bc", base + 0x32),
                 length=1)
    project.hook(base + 0x3c, PlaceStringSummary(base + 0x3f), length=3)
    project.hook(base + 0x44, PlaceStringSummary(RETURN), length=3)


def _assembly(values):
    location = symbol_location(SYMBOLS, "PrintNamingText")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    _hook_assembly(project, location.address, values["type"].args[0])
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    _setup(state, values, 0)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    state.globals["sprite_id"] = values["sprite_id"]
    state.globals["pokedex_num"] = values["pokedex_num"]
    state.globals["sprite_flags"] = values["sprite_flags"]
    ends = collect_returns(project, state, RETURN)
    return [Endpoint(_reg_concat(end, False), _memory(end, 0),
                     end.globals["sprite_call"], end.globals["name_call"],
                     tuple(end.solver.constraints)) for end in ends]


def _native(values):
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_print_naming_text")
    sprite = project.loader.find_symbol("port_write_mon_party_sprite_oam_by_species_private")
    get_name = project.loader.find_symbol("port_get_mon_name")
    place = project.loader.find_symbol("port_place_string")
    assert function and sprite and get_name and place
    project.hook(sprite.rebased_addr, NativeSpriteSummary())
    project.hook(get_name.rebased_addr, NativeGetMonNameSummary())
    project.hook(place.rebased_addr, NativePlaceStringSummary())
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, values["species"])
    state.memory.store(NATIVE_STATE + 9, values["sprite_id"])
    state.memory.store(NATIVE_STATE + 10, values["pokedex_num"])
    state.memory.store(NATIVE_STATE + 11, values["sprite_flags"])
    _setup(state, values, NATIVE_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [Endpoint(_reg_concat(end, True), _memory(end, NATIVE_MEMORY),
                     end.globals["sprite_call"], end.globals["name_call"],
                     tuple(end.solver.constraints)) for end in manager.deadended]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
@pytest.mark.parametrize("naming_type", (0, 1, 2))
def test_print_naming_text_pathwise_equivalence(naming_type: int) -> None:
    values = _values(f"naming_{naming_type}", naming_type)
    assert_pathwise_equivalent(
        _assembly(values), _native(values),
        ("registers", "memory", "sprite_call", "name_call"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_print_naming_text_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "PrintNamingText")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
