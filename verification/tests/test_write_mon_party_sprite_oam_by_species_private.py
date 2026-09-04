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
    Sm83AddImmediate,
    Sm83AddRegister,
    Sm83CpImmediate,
    Sm83DecRegister,
    Sm83IncRegister,
    Sm83LoadAAtHlIncrement,
    Sm83LoadAHighImmediate,
    Sm83LoadAImmediate,
    Sm83OrRegister,
    Sm83StoreAAtHlIncrement,
    Sm83StoreAHighImmediate,
    Sm83StoreAImmediate,
    Sm83SwapRegister,
    Sm83XorA,
    Sm83XorImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xFFFF

SPECIES = 0xCD5D  # wMonPartySpriteSpecies
PINDEX = 0xFF8C  # hPartyMonIndex
BASE_TILE = 0xCD5B  # wOAMBaseTile
ATTRS = 0xCD5C  # wSymmetricSpriteOAMAttributes
POKEDEX = 0xD11E  # wPokedexNum
OAM = 0xC300  # wShadowOAM
SAVED = 0xCC5B  # wMonPartySpritesSavedOAM
SAVED_LEN = 0x60

# WriteMonPartySpriteOAMBySpecies body (xor a through jr WriteMonPartySpriteOAM).
EXPECTED_BYSPECIES = bytes.fromhex("afe08cfa5dcdcde958ea5bcd1833")
# WriteMonPartySpriteOAM body (push af through jp CopyData).
EXPECTED_OAM = bytes.fromhex(
    "f50e1026c3f08ccb376fc61047f1fe082805cda6521803cd8152"
    "2100c3115bcc016000c3b500"
)
EXPECTED_COPYDATA = bytes.fromhex("2a12130b79b020f8c9")


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


class SpeciesIdBoundary(angr.SimProcedure):
    """Proven GetPartyMonSpriteID composition at the call site: snapshot
    the species input, apply the shared lookup transition, continue."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["species_in"] = self.state.regs.a
        self.state.memory.store(
            POKEDEX, self.state.globals["pokedex_num"])
        self.state.regs.a = self.state.globals["sprite_id"]
        self.state.regs.f = sm83_flags_to_z80(
            self.state.globals["sprite_flags"])
        self.jump(self._next)


class IncTileTwice(angr.SimProcedure):
    """Exact ``inc [hl]`` pair over wOAMBaseTile."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(
            BASE_TILE, self.state.memory.load(BASE_TILE, 1) + 2)
        self.jump(self._next)


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["species"] = claripy.BVS(f"{prefix}_species", 8)
    values["pindex"] = claripy.BVS(f"{prefix}_pindex", 8)
    values["pokedex_seed"] = claripy.BVS(f"{prefix}_pokedex_seed", 8)
    values["sprite_id"] = claripy.BVS(f"{prefix}_sprite_id", 8)
    values["pokedex_num"] = claripy.BVS(f"{prefix}_pokedex_num", 8)
    values["sprite_flags"] = claripy.Concat(
        claripy.BVS(f"{prefix}_sprite_flags", 4), claripy.BVV(0, 4))
    values["base_tile"] = claripy.BVS(f"{prefix}_base_tile", 8)
    values["attrs"] = claripy.BVS(f"{prefix}_attrs", 8)
    values["oam"] = claripy.Concat(
        *(claripy.BVS(f"{prefix}_oam_{i}", 8) for i in range(SAVED_LEN)))
    values["saved"] = claripy.Concat(
        *(claripy.BVS(f"{prefix}_saved_{i}", 8)
          for i in range(SAVED_LEN)))
    return values


def _setup(state: angr.SimState, values: dict[str, claripy.ast.BV],
           base: int = 0) -> None:
    state.memory.store(base + SPECIES, values["species"])
    state.memory.store(base + PINDEX, values["pindex"])
    state.memory.store(base + POKEDEX, values["pokedex_seed"])
    state.memory.store(base + BASE_TILE, values["base_tile"])
    state.memory.store(base + ATTRS, values["attrs"])
    state.memory.store(base + OAM, values["oam"])
    state.memory.store(base + SAVED, values["saved"])
    state.globals["species_in"] = values["species"]
    for key in ("sprite_id", "pokedex_num", "sprite_flags"):
        state.globals[key] = values[key]


def _memory(state: angr.SimState, base: int = 0) -> claripy.ast.BV:
    return claripy.Concat(
        state.memory.load(base + PINDEX, 1),
        state.memory.load(base + SPECIES, 1),
        state.memory.load(base + POKEDEX, 1),
        state.memory.load(base + BASE_TILE, 1),
        state.memory.load(base + ATTRS, 1),
        state.memory.load(base + OAM, 16),
        state.memory.load(base + SAVED, SAVED_LEN),
        state.globals["species_in"],
    )


def _hook(project: angr.Project) -> None:
    by_species = symbol_location(SYMBOLS, "WriteMonPartySpriteOAMBySpecies")
    oam = symbol_location(SYMBOLS, "WriteMonPartySpriteOAM")
    sym = symbol_location(SYMBOLS, "WriteSymmetricMonPartySpriteOAM")
    asym = symbol_location(SYMBOLS, "WriteAsymmetricMonPartySpriteOAM")
    copy = symbol_location(SYMBOLS, "CopyData")
    s = by_species.address
    w = oam.address
    q = sym.address
    q2 = asym.address
    d = copy.address

    def hook(addr: int, shim: angr.SimProcedure, length: int) -> None:
        project.hook(addr, shim, length=length)

    # BySpecies prefix: party-index reset, species load, lookup boundary,
    # base-tile store. The jr falls through to WriteMonPartySpriteOAM.
    hook(s + 0, Sm83XorA(s + 1), 1)
    hook(s + 1, Sm83StoreAHighImmediate(0x8C, s + 3), 2)
    hook(s + 3, Sm83LoadAImmediate(SPECIES, s + 6), 3)
    hook(s + 6, SpeciesIdBoundary(s + 9), 3)
    hook(s + 9, Sm83StoreAImmediate(BASE_TILE, s + 12), 3)
    # OAM pointer setup, helix tile selection.
    hook(w + 5, Sm83LoadAHighImmediate(0x8C, w + 7), 2)
    hook(w + 7, Sm83SwapRegister("a", w + 9), 2)
    hook(w + 10, Sm83AddImmediate(0x10, w + 12), 2)
    hook(w + 14, Sm83CpImmediate(0x08, w + 16), 2)
    # Symmetric writer (same-bank call, real 2x2 loop).
    hook(q + 0, Sm83XorA(q + 1), 1)
    hook(q + 1, Sm83StoreAImmediate(ATTRS, q + 4), 3)
    for offset in (10, 12, 16, 20):
        hook(q + offset, Sm83StoreAAtHlIncrement(q + offset + 1), 1)
    hook(q + 13, Sm83LoadAImmediate(BASE_TILE, q + 16), 3)
    hook(q + 17, Sm83LoadAImmediate(ATTRS, q + 20), 3)
    hook(q + 21, Sm83XorImmediate(0x20, q + 23), 2)
    hook(q + 23, Sm83StoreAImmediate(ATTRS, q + 26), 3)
    hook(q + 29, Sm83AddRegister("c", q + 30), 1)
    hook(q + 31, Sm83DecRegister("e", q + 32), 1)
    hook(q + 40, IncTileTwice(q + 42), 2)
    hook(q + 45, Sm83AddRegister("b", q + 46), 1)
    hook(q + 47, Sm83DecRegister("d", q + 48), 1)
    # Asymmetric writer (same-bank call, real 2x2 loop).
    for offset in (6, 8, 12, 18):
        hook(q2 + offset, Sm83StoreAAtHlIncrement(q2 + offset + 1), 1)
    hook(q2 + 9, Sm83LoadAImmediate(BASE_TILE, q2 + 12), 3)
    hook(q2 + 13, Sm83IncRegister("a", q2 + 14), 1)
    hook(q2 + 14, Sm83StoreAImmediate(BASE_TILE, q2 + 17), 3)
    hook(q2 + 17, Sm83XorA(q2 + 18), 1)
    hook(q2 + 22, Sm83AddRegister("c", q2 + 23), 1)
    hook(q2 + 24, Sm83DecRegister("e", q2 + 25), 1)
    hook(q2 + 31, Sm83AddRegister("b", q2 + 32), 1)
    hook(q2 + 33, Sm83DecRegister("d", q2 + 34), 1)
    # CopyData tail: real 96-byte saved-OAM copy.
    hook(d + 0, Sm83LoadAAtHlIncrement(d + 1), 1)
    hook(d + 5, Sm83OrRegister("b", d + 6), 1)


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "WriteMonPartySpriteOAMBySpecies")
    assert linked_bytes(ROM, location, len(EXPECTED_BYSPECIES)) == (
        EXPECTED_BYSPECIES)
    oam = symbol_location(SYMBOLS, "WriteMonPartySpriteOAM")
    assert linked_bytes(ROM, oam, len(EXPECTED_OAM)) == EXPECTED_OAM
    copy = symbol_location(SYMBOLS, "CopyData")
    assert linked_bytes(ROM, copy, len(EXPECTED_COPYDATA)) == (
        EXPECTED_COPYDATA)
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
    _hook(project)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    _setup(state, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    ends = collect_returns(project, state, RETURN)
    # Helix versus symmetric tile selection.
    assert len(ends) == 2
    return [
        Endpoint(
            **assembly_registers(end),
            memory=_memory(end),
            constraints=tuple(end.solver.constraints),
        )
        for end in ends
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(
        "port_write_mon_party_sprite_oam_by_species_private")
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, values["species"])
    state.memory.store(NATIVE_STATE + 9, values["pindex"])
    state.memory.store(NATIVE_STATE + 10, values["sprite_id"])
    state.memory.store(NATIVE_STATE + 11, values["pokedex_num"])
    state.memory.store(NATIVE_STATE + 12, values["sprite_flags"])
    _setup(state, values, NATIVE_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=_memory(end, NATIVE_MEMORY),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run red")
def test_write_mon_party_sprite_oam_by_species_private_pathwise_equivalence() \
        -> None:
    values = _inputs("species_oam")
    assert_pathwise_equivalent(
        _assembly(values), _native(values), (*REGISTERS, "memory"))


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run red")
def test_write_mon_party_sprite_oam_by_species_private_exact_linked_body() \
        -> None:
    location = symbol_location(SYMBOLS, "WriteMonPartySpriteOAMBySpecies")
    assert linked_bytes(ROM, location, len(EXPECTED_BYSPECIES)) == (
        EXPECTED_BYSPECIES)
    oam = symbol_location(SYMBOLS, "WriteMonPartySpriteOAM")
    assert linked_bytes(ROM, oam, len(EXPECTED_OAM)) == EXPECTED_OAM
