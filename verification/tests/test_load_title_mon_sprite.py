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
from verification.harness.rom import linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import Sm83StoreAImmediate

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xFFFF

W_CUR_PARTY_SPECIES = 0xCF91
W_SPRITE_FLIPPED = 0xD0AA
W_CUR_SPECIES = 0xD0B5
W_MON_HEADER = 0xD0B8
W_POKEDEX_NUM = 0xD11E
H_LOADED_ROM_BANK = 0xFFB8
H_START_TILE_ID = 0xFFE1
R_ROMB = 0x2000
TITLE_SPRITE_HL = 0xC46D
BASE_STATS_HL = 0x43DE
BASE_DATA_SIZE = 0x1C
HEADER_SIZE = 0x1C

# Red's TitleMons table, including the three starters and the 13 random
# title-screen choices. Values are the internal species IDs, not dex numbers.
TITLE_SPECIES = (
    0xB0,  # CHARMANDER / STARTER1
    0xB1,  # SQUIRTLE / STARTER2
    0x99,  # BULBASAUR / STARTER3
    0x70,  # WEEDLE
    0x03,  # NIDORAN_M
    0x1A,  # SCYTHER
    0x54,  # PIKACHU
    0x04,  # CLEFAIRY
    0x01,  # RHYDON
    0x94,  # ABRA
    0x19,  # GASTLY
    0x4C,  # DITTO
    0x96,  # PIDGEOTTO
    0x22,  # ONIX
    0xA3,  # PONYTA
    0x85,  # MAGIKARP
)

HANDLER_EXPECTED = bytes.fromhex(
    "ea91cfeab5d0216dc4cd3715c38913"
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
    cur_party_species: claripy.ast.BV
    cur_species: claripy.ast.BV
    pokedex_num: claripy.ast.BV
    mon_header: claripy.ast.BV
    start_tile_id: claripy.ast.BV
    sprite_flipped: claripy.ast.BV
    loaded_bank: claripy.ast.BV
    romb: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["pokedex_num"] = claripy.BVS(f"{prefix}_pokedex_num", 8)
    values["start_tile_id"] = claripy.BVS(f"{prefix}_start_tile_id", 8)
    values["sprite_flipped"] = claripy.BVS(f"{prefix}_sprite_flipped", 8)
    values["loaded_bank"] = claripy.BVS(f"{prefix}_loaded_bank", 8)
    values["romb"] = claripy.BVS(f"{prefix}_romb", 8)
    for index in range(HEADER_SIZE):
        values[f"header{index}"] = claripy.BVS(f"{prefix}_header{index}", 8)
    return values


def _title_dex_number(species: int) -> int:
    return {
        0xB0: 4,
        0xB1: 7,
        0x99: 1,
        0x70: 13,
        0x03: 32,
        0x1A: 123,
        0x54: 25,
        0x04: 35,
        0x01: 112,
        0x94: 63,
        0x19: 92,
        0x4C: 132,
        0x96: 17,
        0x22: 95,
        0xA3: 77,
        0x85: 129,
    }[species]


def _setup(
    state: angr.SimState,
    values: dict[str, claripy.ast.BV],
    species: int,
    native: bool,
) -> None:
    base = NATIVE_MEMORY if native else 0
    state.memory.store(base + W_POKEDEX_NUM, values["pokedex_num"])
    state.memory.store(base + W_SPRITE_FLIPPED, values["sprite_flipped"])
    state.memory.store(base + H_START_TILE_ID, values["start_tile_id"])
    state.memory.store(base + H_LOADED_ROM_BANK, values["loaded_bank"])
    state.memory.store(base + R_ROMB, values["romb"])
    state.memory.store(base + W_CUR_PARTY_SPECIES, claripy.BVV(species, 8))
    state.memory.store(base + W_CUR_SPECIES, claripy.BVV(species, 8))
    for index in range(HEADER_SIZE):
        state.memory.store(base + W_MON_HEADER + index, values[f"header{index}"])

    dex = _title_dex_number(species)
    source = BASE_STATS_HL + (dex - 1) * BASE_DATA_SIZE
    for index in range(HEADER_SIZE):
        state.memory.store(base + source + index, values[f"header{index}"])


def _endpoint(state: angr.SimState, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    registers = native_registers(state, NATIVE_STATE) if native else assembly_registers(state)
    return Endpoint(
        **registers,
        cur_party_species=state.memory.load(base + W_CUR_PARTY_SPECIES, 1),
        cur_species=state.memory.load(base + W_CUR_SPECIES, 1),
        pokedex_num=state.memory.load(base + W_POKEDEX_NUM, 1),
        mon_header=claripy.Concat(
            *(state.memory.load(base + W_MON_HEADER + i, 1) for i in range(HEADER_SIZE))
        ),
        start_tile_id=state.memory.load(base + H_START_TILE_ID, 1),
        sprite_flipped=state.memory.load(base + W_SPRITE_FLIPPED, 1),
        loaded_bank=state.memory.load(base + H_LOADED_ROM_BANK, 1),
        romb=state.memory.load(base + R_ROMB, 1),
        constraints=tuple(state.solver.constraints),
    )


class LoadHLImmediate(angr.SimProcedure):
    def __init__(self, value: int, next_address: int) -> None:
        super().__init__()
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.hl = claripy.BVV(self.value, 16)
        self.jump(self.next_address)


class GetMonHeaderBoundary(angr.SimProcedure):
    """Complete normal-species transition of the proven GetMonHeader port."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        species = self.state.memory.load(W_CUR_SPECIES, 1)
        saved_bank = self.state.memory.load(H_LOADED_ROM_BANK, 1)
        saved_dex = self.state.memory.load(W_POKEDEX_NUM, 1)
        for index in range(HEADER_SIZE):
            self.state.memory.store(
                W_MON_HEADER + index,
                self.state.globals[f"header{index}"],
            )
        self.state.memory.store(W_MON_HEADER, species)
        self.state.memory.store(W_POKEDEX_NUM, saved_dex)
        self.state.memory.store(H_LOADED_ROM_BANK, saved_bank)
        self.state.memory.store(R_ROMB, saved_bank)
        self.state.regs.a = saved_bank
        self.jump(self.next_address)


class LoadFrontSpriteBoundary(angr.SimProcedure):
    """Complete valid-dex transition of the proven LoadFrontSprite port."""

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        # The p-code state uses Z80 flag positions; canonical SM83 Z is bit 7.
        self.state.regs.f = claripy.BVV(0x40, 8)
        self.state.memory.store(H_START_TILE_ID, claripy.BVV(0, 8))
        self.state.memory.store(W_SPRITE_FLIPPED, claripy.BVV(0, 8))
        self.jump(DONE)



def _assembly(values: dict[str, claripy.ast.BV], species: int) -> list[Endpoint]:
    handler = symbol_location(SYMBOLS, "LoadTitleMonSprite")
    get_header = symbol_location(SYMBOLS, "GetMonHeader")
    load_front = symbol_location(SYMBOLS, "LoadFrontSpriteByMonIndex")
    assert handler.bank == 1
    assert handler.address == 0x4524
    assert get_header.address == 0x1537
    assert load_front.address == 0x1389
    assert linked_bytes(ROM, handler, len(HANDLER_EXPECTED)) == HANDLER_EXPECTED

    project = angr.Project(
        rom_window(ROM, handler.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": handler.address,
        },
    )
    base = handler.address
    project.hook(base + 0x00, Sm83StoreAImmediate(W_CUR_PARTY_SPECIES, base + 0x03), length=3)
    project.hook(base + 0x03, Sm83StoreAImmediate(W_CUR_SPECIES, base + 0x06), length=3)
    project.hook(base + 0x06, LoadHLImmediate(TITLE_SPRITE_HL, base + 0x09), length=3)
    project.hook(base + 0x09, GetMonHeaderBoundary(base + 0x0C), length=3)
    project.hook(base + 0x0C, LoadFrontSpriteBoundary(), length=3)

    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _setup(state, values, species, native=False)
    state.regs.a = claripy.BVV(species, 8)
    for index in range(HEADER_SIZE):
        state.globals[f"header{index}"] = values[f"header{index}"]
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored, manager.errored
    assert len(manager.found) == 1, len(manager.found)
    return [_endpoint(final, native=False) for final in manager.found]


def _native(values: dict[str, claripy.ast.BV], species: int) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_load_title_mon_sprite")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 0, claripy.BVV(species, 8))
    _setup(state, values, species, native=True)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored, manager.errored
    assert len(manager.deadended) == 1, len(manager.deadended)
    return [_endpoint(final, native=True) for final in manager.deadended]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(
    not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`"
)
@pytest.mark.parametrize("species", TITLE_SPECIES, ids=lambda value: f"{value:#04x}")
def test_load_title_mon_sprite_pathwise_equivalence(species: int) -> None:
    values = _inputs(f"load_title_mon_sprite_{species:#04x}")
    assert_pathwise_equivalent(
        _assembly(values, species),
        _native(values, species),
        (
            *REGISTERS,
            "cur_party_species",
            "cur_species",
            "pokedex_num",
            "mon_header",
            "start_tile_id",
            "sprite_flipped",
            "loaded_bank",
            "romb",
        ),
    )
