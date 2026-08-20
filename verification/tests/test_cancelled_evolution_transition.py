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
from verification.harness.rom import rom_window, sm83_flags_to_z80, symbol_location

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
DONE = 0xEFFF

MEMORY_FIELDS = (
    "tile_animations",
    "evolution_occurred",
    "which_pokemon",
    "party_species",
    "evo_old_species",
    "can_evolve",
    "link_state",
    "force_evolution",
    "loaded_mon_level",
    "evolution_type",
    "requirement",
    "level_requirement",
    "cur_item",
    "is_in_battle",
    "music_called",
    "cur_enemy_level",
    "evo_new_species",
    "fetched_species",
    "saved_entry_h",
    "saved_entry_l",
    "old_max_hp_high",
    "old_max_hp_low",
    "loaded_max_hp_high",
    "loaded_max_hp_low",
    "loaded_hp_high",
    "loaded_hp_low",
    "saved_copy_b",
    "saved_copy_c",
    *(f"saved_{register}" for register in REGISTERS),
    "evolution_cancelled",
    "auto_bg_transfer_enabled",
    "update_sprites_enabled",
    "cur_species",
    "loaded_mon_species",
    "name_list_type",
    "predef_bank",
    "pokedex_num",
    "mon_h_index",
    "mon_data_location",
    "party_species_write",
    "is_evolving_text_called",
    "evolved_text_called",
    "stopped_text_called",
    "into_text_called",
    "evolve_mon_called",
    "clear_screen_called",
    "clear_sprites_called",
    "rename_called",
    "calc_stats_called",
    "learn_move_called",
    "set_types_called",
    "reload_called",
    "owned_flag_called",
    "seen_flag_called",
    "saved_pokedex_num",
    "saved_pokedex_f",
    "saved_party_struct_h",
    "saved_party_struct_l",
    "copied_party_end_h",
    "copied_party_end_l",
    "saved_party_list_h",
    "saved_party_list_l",
    "index_to_pokedex_called",
    "copy_header_called",
    "copy_party_called",
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


class Mark(angr.SimProcedure):
    def __init__(self, key: str, continuation: int):
        super().__init__()
        self.key = key
        self.continuation = continuation

    def run(self) -> None:
        self.state.globals[self.key] = claripy.BVV(1, 8)
        self.jump(self.continuation)


class PopSavedEntry(angr.SimProcedure):
    def run(self) -> None:
        self.state.regs.h = self.state.globals["saved_entry_h"]
        self.state.regs.l = self.state.globals["saved_entry_l"]
        self.jump(self.addr + 1)


class ReloadTransition(angr.SimProcedure):
    def run(self) -> None:
        self.inhibit_autoret = True
        link_state = self.state.globals["link_state"]
        canonical_flags = claripy.Concat(
            claripy.If(link_state == 2, claripy.BVV(1, 1), claripy.BVV(0, 1)),
            claripy.BVV(1, 1),
            claripy.If(
                (link_state & 0x0F) < 2,
                claripy.BVV(1, 1),
                claripy.BVV(0, 1),
            ),
            claripy.If(
                link_state < 2,
                claripy.BVV(1, 1),
                claripy.BVV(0, 1),
            ),
            claripy.BVV(0, 4),
        )
        state = self.state.copy()
        state.regs.a = link_state
        state.regs.f = sm83_flags_to_z80(canonical_flags)
        self.successors.add_successor(
            state,
            DONE,
            link_state == 2,
            "Ijk_Boring",
        )
        reloaded = self.state.copy()
        reloaded.regs.a = link_state
        reloaded.regs.f = sm83_flags_to_z80(canonical_flags)
        reloaded.globals["reload_called"] = claripy.BVV(1, 8)
        self.successors.add_successor(
            reloaded,
            DONE,
            link_state != 2,
            "Ijk_Boring",
        )


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for name in MEMORY_FIELDS:
        values[name] = claripy.BVS(f"{prefix}_{name}", 8)
    return values


def _setup(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    set_assembly_registers(state, values)
    for name in MEMORY_FIELDS:
        state.globals[name] = values[name]


def _endpoint(state: angr.SimState) -> Endpoint:
    return Endpoint(
        **assembly_registers(state),
        memory=claripy.Concat(*(state.globals[name] for name in MEMORY_FIELDS)),
        constraints=tuple(state.solver.constraints),
    )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "CancelledEvolution")
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
    project.hook(base + 3, Mark("stopped_text_called", base + 6), length=3)
    project.hook(base + 6, Mark("clear_screen_called", base + 9), length=3)
    project.hook(base + 9, PopSavedEntry(), length=1)
    project.hook(base + 10, ReloadTransition(), length=3)
    state = project.factory.blank_state(addr=base)
    _setup(state, values)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=2)
    assert not manager.errored
    return [_endpoint(end) for end in manager.found]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_evolution_cancelled_transition")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(
        NATIVE_STATE + 8,
        claripy.Concat(*(values[name] for name in MEMORY_FIELDS)),
    )
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=end.memory.load(NATIVE_STATE + 8, len(MEMORY_FIELDS)),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_cancelled_evolution_transition_pathwise_equivalence() -> None:
    values = _inputs("cancelled")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "memory"),
    )
