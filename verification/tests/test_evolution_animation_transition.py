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
    continuation: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class CallBoundary(angr.SimProcedure):
    def __init__(self, continuation: int, marker: str | None = None):
        super().__init__()
        self.continuation = continuation
        self.marker = marker

    def run(self) -> None:
        if self.marker is not None:
            self.state.globals[self.marker] = claripy.BVV(1, 8)
        self.jump(self.continuation)


class StoreField(angr.SimProcedure):
    def __init__(self, field: str, continuation: int):
        super().__init__()
        self.field = field
        self.continuation = continuation

    def run(self) -> None:
        self.state.globals[self.field] = self.state.regs.a
        self.jump(self.continuation)


class EvolveMon(angr.SimProcedure):
    def __init__(self, continuation: int):
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:
        cancelled = self.state.globals["evolution_cancelled"]
        self.state.globals["evolve_mon_called"] = claripy.BVV(1, 8)
        self.state.regs.a = cancelled
        canonical_flags = claripy.Concat(
            claripy.If(cancelled == 0, claripy.BVV(1, 1), claripy.BVV(0, 1)),
            claripy.If(cancelled == 0, claripy.BVV(0, 1), claripy.BVV(0, 1)),
            claripy.If(cancelled == 0, claripy.BVV(1, 1), claripy.BVV(0, 1)),
            claripy.If(cancelled == 0, claripy.BVV(0, 1), claripy.BVV(1, 1)),
            claripy.BVV(0, 4),
        )
        self.state.regs.f = sm83_flags_to_z80(canonical_flags)
        self.jump(self.continuation)


class ReturnWithCancellation(angr.SimProcedure):
    def run(self) -> None:
        carry = (self.state.regs.f & 1) != 0
        self.state.globals["continuation"] = claripy.If(
            carry, claripy.BVV(1, 8), claripy.BVV(0, 8)
        )
        self.jump(DONE)


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
        continuation=state.globals["continuation"],
        constraints=tuple(state.solver.constraints),
    )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "EvolutionAfterBattle")
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
    base = location.address + 0xAD
    project.hook(base, CallBoundary(base + 3))
    project.hook(base + 3, CallBoundary(base + 6))
    project.hook(base + 9, CallBoundary(base + 0x0B, "is_evolving_text_called"))
    project.hook(base + 0x0B, CallBoundary(base + 0x0E))
    project.hook(base + 0x0E, CallBoundary(base + 0x11))
    project.hook(base + 0x12, StoreField("auto_bg_transfer_enabled", base + 0x14), length=2)
    project.hook(base + 0x1A, CallBoundary(base + 0x1D))
    project.hook(base + 0x1F, StoreField("auto_bg_transfer_enabled", base + 0x21), length=2)
    project.hook(base + 0x23, StoreField("update_sprites_enabled", base + 0x26), length=3)
    project.hook(base + 0x26, CallBoundary(base + 0x29, "clear_sprites_called"))
    project.hook(base + 0x2E, EvolveMon(base + 0x31), length=3)
    project.hook(base + 0x31, ReturnWithCancellation(), length=3)
    state = project.factory.blank_state(addr=base)
    _setup(state, values)
    state.globals["continuation"] = claripy.BVV(0, 8)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored
    return [_endpoint(end) for end in manager.found]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_evolution_animation_transition")
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
            continuation=end.regs.rax[7:0],
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_evolution_animation_transition_pathwise_equivalence() -> None:
    values = _inputs("animation")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "memory", "continuation"),
    )
