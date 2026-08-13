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
from verification.harness.sm83_shims import (
    Sm83AddHlRegisterPair,
    Sm83AndImmediate,
    Sm83CpImmediate,
    Sm83DecRegister,
)


ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
DONE = 0xEFF1

BASE_NAMES = (
    "tile_animations", "evolution_occurred", "which_pokemon", "party_species",
    "evo_old_species", "can_evolve", "link_state", "force_evolution",
    "loaded_mon_level", "evolution_type", "requirement", "level_requirement",
    "cur_item", "is_in_battle", "music_called", "cur_enemy_level",
    "evo_new_species", "fetched_species", "saved_entry_h", "saved_entry_l",
    "old_max_hp_high", "old_max_hp_low", "loaded_max_hp_high",
    "loaded_max_hp_low", "loaded_hp_high", "loaded_hp_low", "saved_copy_b",
    "saved_copy_c",
) + tuple("saved_" + register for register in REGISTERS)

TAIL_NAMES = (
    "evolution_cancelled", "auto_bg_transfer_enabled", "update_sprites_enabled",
    "cur_species", "loaded_mon_species", "name_list_type", "predef_bank",
    "pokedex_num", "mon_h_index", "mon_data_location", "party_species_write",
    "is_evolving_text_called", "evolved_text_called", "stopped_text_called",
    "into_text_called", "evolve_mon_called", "clear_screen_called",
    "clear_sprites_called", "rename_called", "calc_stats_called",
    "learn_move_called", "set_types_called", "reload_called",
    "owned_flag_called", "seen_flag_called",
    "saved_pokedex_num", "saved_pokedex_f", "saved_party_struct_h",
    "saved_party_struct_l", "copied_party_end_h", "copied_party_end_l",
)
NAMES = BASE_NAMES + TAIL_NAMES


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


class Boundary(angr.SimProcedure):
    def __init__(self, continuation: int, next_address: int = DONE) -> None:
        super().__init__()
        self.continuation = continuation
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["continuation"] = claripy.BVV(self.continuation, 8)
        self.jump(self.next_address)


class Mark(angr.SimProcedure):
    def __init__(self, key: str, next_address: int) -> None:
        super().__init__()
        self.key = key
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.globals[self.key] = claripy.BVV(1, 8)
        self.jump(self.next_address)


class Evolve(Mark):
    def run(self) -> None:  # type: ignore[override]
        self.state.globals[self.key] = claripy.BVV(1, 8)
        value = self.state.globals["evolution_cancelled"]
        cancelled = value != 0
        self.state.regs.a = value
        self.state.regs.f = claripy.If(cancelled, claripy.BVV(1, 8), claripy.BVV(0x50, 8))
        self.state.globals["continuation"] = claripy.If(cancelled, claripy.BVV(1, 8), claripy.BVV(0, 8))
        self.jump(DONE)


class Read(angr.SimProcedure):
    def __init__(self, key: str, next_address: int) -> None:
        super().__init__()
        self.key = key
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals[self.key]
        self.jump(self.next_address)


class Write(angr.SimProcedure):
    def __init__(self, key: str, next_address: int) -> None:
        super().__init__()
        self.key = key
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.globals[self.key] = self.state.regs.a
        self.jump(self.next_address)


class RestoreEntry(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = self.state.globals["saved_entry_h"]
        self.state.regs.l = self.state.globals["saved_entry_l"]
        self.jump(self.next_address)


class RestoreParty(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = self.state.globals["saved_party_struct_h"]
        self.state.regs.l = self.state.globals["saved_party_struct_l"]
        self.jump(self.next_address)


class XorA(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = 0
        self.state.regs.f = claripy.BVV(0x40, 8)
        self.jump(self.next_address)


class Reload(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        link = self.state.globals["link_state"]
        self.state.regs.a = link
        self.state.regs.f = (
            claripy.BVV(0x02, 8)
            | claripy.If(link == 2, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
            | claripy.If((link & 15).ULT(2), claripy.BVV(0x10, 8), claripy.BVV(0, 8))
            | claripy.If(link.ULT(2), claripy.BVV(1, 8), claripy.BVV(0, 8))
        )
        self.state.globals["reload_called"] = claripy.If(link == 2, self.state.globals["reload_called"], claripy.BVV(1, 8))
        self.jump(self.next_address)


class ReloadIfZero(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        zero = (self.state.regs.f & 0x40) != 0
        self.inhibit_autoret = True
        skipped = self.state.copy()
        skipped.globals["continuation"] = claripy.BVV(0, 8)
        self.successors.add_successor(skipped, DONE, claripy.Not(zero), "Ijk_Boring")
        called = self.state.copy()
        link = called.globals["link_state"]
        called.regs.a = link
        called.regs.f = (
            claripy.BVV(0x02, 8)
            | claripy.If(link == 2, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
            | claripy.If((link & 15).ULT(2), claripy.BVV(0x10, 8), claripy.BVV(0, 8))
            | claripy.If(link.ULT(2), claripy.BVV(1, 8), claripy.BVV(0, 8))
        )
        called.globals["reload_called"] = claripy.If(link == 2, called.globals["reload_called"], claripy.BVV(1, 8))
        called.globals["continuation"] = claripy.BVV(0, 8)
        self.successors.add_successor(called, DONE, zero, "Ijk_Boring")


def inputs(prefix: str):
    values = symbolic_registers(prefix)
    for name in NAMES:
        values[name] = claripy.BVS(prefix + "_" + name, 8)
    return values


def project():
    location = symbol_location(SYMBOLS, "EvolutionAfterBattle")
    return (
        angr.Project(
            rom_window(ROM, location.bank),
            auto_load_libs=False,
            rebase_granularity=0x100,
            main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0, "entry_point": location.address},
        ),
        location.address,
    )


def setup(state, values):
    set_assembly_registers(state, values)
    for name in NAMES:
        state.globals[name] = values[name]
    state.solver.add(values["which_pokemon"].ULE(5))


def endpoint(state, continuation=0):
    return Endpoint(
        **assembly_registers(state),
        memory=claripy.Concat(*(state.globals[name] for name in NAMES)),
        continuation=state.globals.get("continuation", claripy.BVV(continuation, 8)),
        constraints=tuple(state.solver.constraints),
    )


def collect(manager):
    manager.stashes["found"] = []
    while manager.active:
        manager.move(from_stash="active", to_stash="found", filter_func=lambda state: state.addr == DONE)
        if manager.active:
            manager.step()
    assert not manager.errored
    return [endpoint(state) for state in manager.found]


def assembly_animation(values):
    p, q = project()
    p.hook(q + 0xAD, Mark("is_evolving_text_called", q + 0xB9), length=12)
    p.hook(q + 0xBB, Boundary(0, q + 0xBE), length=3)
    p.hook(q + 0xBF, Write("auto_bg_transfer_enabled", q + 0xC1), length=2)
    p.hook(q + 0xC7, Boundary(0, q + 0xCA), length=3)
    p.hook(q + 0xCC, Write("auto_bg_transfer_enabled", q + 0xCE), length=2)
    p.hook(q + 0xD0, Write("update_sprites_enabled", q + 0xD3), length=3)
    p.hook(q + 0xD3, Mark("clear_sprites_called", q + 0xD6), length=3)
    p.hook(q + 0xD6, Evolve("evolve_mon_called", DONE), length=8)
    state = p.factory.blank_state(addr=q + 0xAD)
    setup(state, values)
    return collect(p.factory.simulation_manager(state))


def assembly_cancel(values):
    p, q = project()
    cancelled = symbol_location(SYMBOLS, "CancelledEvolution").address
    p.hook(cancelled, Mark("stopped_text_called", cancelled + 6), length=6)
    p.hook(cancelled + 6, Mark("clear_screen_called", cancelled + 9), length=3)
    p.hook(cancelled + 9, RestoreEntry(cancelled + 10), length=1)
    p.hook(cancelled + 10, Reload(cancelled + 13), length=3)
    p.hook(cancelled + 13, Boundary(0), length=3)
    state = p.factory.blank_state(addr=cancelled)
    setup(state, values)
    return collect(p.factory.simulation_manager(state))


def assembly_success_species(values):
    p, q = project()
    p.hook(q + 0xE7, RestoreEntry(q + 0xE8), length=1)
    p.hook(q + 0xE8, Read("fetched_species", q + 0xE9), length=1)
    p.hook(q + 0xE9, Write("cur_species", q + 0xEC), length=3)
    p.hook(q + 0xEC, Write("loaded_mon_species", q + 0xEF), length=3)
    p.hook(q + 0xEF, Write("evo_new_species", q + 0xF2), length=3)
    p.hook(q + 0xF4, Write("name_list_type", q + 0xF7), length=3)
    p.hook(q + 0xF9, Write("predef_bank", q + 0xFC), length=3)
    p.hook(q + 0xFC, Boundary(0), length=3)
    state = p.factory.blank_state(addr=q + 0xE7)
    setup(state, values)
    state.globals["evolved_text_called"] = claripy.BVV(1, 8)
    return collect(p.factory.simulation_manager(state))


def assembly_post_copy(values):
    p, q = project()
    p.hook(q + 0x17E, Read("cur_species", q + 0x181), length=3)
    p.hook(q + 0x181, Write("pokedex_num", q + 0x184), length=3)
    p.hook(q + 0x184, XorA(q + 0x185), length=1)
    p.hook(q + 0x185, Write("mon_data_location", q + 0x188), length=3)
    p.hook(q + 0x188, Mark("learn_move_called", DONE), length=3)
    state = p.factory.blank_state(addr=q + 0x17E)
    setup(state, values)
    return collect(p.factory.simulation_manager(state))


def assembly_set_types(values):
    p, q = project()
    p.hook(q + 0x18B, RestoreParty(q + 0x18C), length=1)
    p.hook(q + 0x18E, Mark("set_types_called", DONE), length=3)
    state = p.factory.blank_state(addr=q + 0x18B)
    setup(state, values)
    return collect(p.factory.simulation_manager(state))


def assembly_success_reload(values):
    p, q = project()
    p.hook(q + 0x191, Read("is_in_battle", q + 0x194), length=3)
    p.hook(q + 0x194, Sm83AndImmediate(0xFF, q + 0x195), length=1)
    p.hook(q + 0x195, ReloadIfZero(), length=3)
    state = p.factory.blank_state(addr=q + 0x191)
    setup(state, values)
    return collect(p.factory.simulation_manager(state))


def assembly_success(values):
    p, q = project()
    p.hook(q + 0xE0, Mark("evolved_text_called", q + 0xE7), length=7)
    p.hook(q + 0xE7, RestoreEntry(q + 0xE8), length=1)
    p.hook(q + 0xE8, Read("fetched_species", q + 0xE9), length=1)
    p.hook(q + 0xE9, Write("cur_species", q + 0xEC), length=3)
    p.hook(q + 0xEC, Write("loaded_mon_species", q + 0xEF), length=3)
    p.hook(q + 0xEF, Write("evo_new_species", q + 0xF2), length=3)
    p.hook(q + 0xF4, Write("name_list_type", q + 0xF7), length=3)
    p.hook(q + 0xF9, Write("predef_bank", q + 0xFC), length=3)
    p.hook(q + 0xFC, Boundary(0, q + 0xFF), length=3)
    p.hook(q + 0xFF, Mark("into_text_called", q + 0x105), length=6)
    p.hook(q + 0x105, Boundary(0, q + 0x110), length=11)
    p.hook(q + 0x110, Mark("clear_screen_called", q + 0x113), length=3)
    p.hook(q + 0x113, Mark("rename_called", q + 0x116), length=3)
    p.hook(q + 0x116, Read("pokedex_num", q + 0x119), length=3)
    p.hook(q + 0x119, Read("cur_species", q + 0x11C), length=3)
    p.hook(q + 0x11C, Write("pokedex_num", q + 0x11F), length=3)
    p.hook(q + 0x11F, Boundary(0, q + 0x122), length=3)
    p.hook(q + 0x122, Read("pokedex_num", q + 0x125), length=3)
    p.hook(q + 0x125, Sm83DecRegister("a", q + 0x126), length=1)
    p.hook(q + 0x12C, Sm83AddHlRegisterPair("bc", q + 0x12D), length=1)
    p.hook(q + 0x12D, Boundary(0, q + 0x139), length=12)
    p.hook(q + 0x139, Read("cur_species", q + 0x13C), length=3)
    p.hook(q + 0x13C, Write("mon_h_index", q + 0x13F), length=3)
    p.hook(q + 0x13F, Read("pokedex_num", q + 0x142), length=3)
    p.hook(q + 0x142, Boundary(0, q + 0x14B), length=9)
    p.hook(q + 0x14B, Mark("calc_stats_called", q + 0x14E), length=3)
    p.hook(q + 0x14E, Read("which_pokemon", q + 0x151), length=3)
    p.hook(q + 0x157, Sm83AddHlRegisterPair("bc", q + 0x158), length=1)
    p.hook(q + 0x158, Boundary(0), length=1)
    state = p.factory.blank_state(addr=q + 0xE0)
    setup(state, values)
    state.regs.sp = 0xDFF0
    state.memory.store(0xDFF0, claripy.Concat(values["saved_entry_h"], values["saved_entry_l"]))
    return collect(p.factory.simulation_manager(state))


def assembly_finish(values):
    p, q = project()
    p.hook(q + 0x17B, Read("cur_species", q + 0x17E), length=3)
    p.hook(q + 0x17E, Write("pokedex_num", q + 0x181), length=3)
    p.hook(q + 0x181, Sm83AndImmediate(0xFF, q + 0x182), length=1)
    p.hook(q + 0x182, Write("mon_data_location", q + 0x185), length=3)
    p.hook(q + 0x185, Mark("learn_move_called", q + 0x188), length=3)
    p.hook(q + 0x188, RestoreEntry(q + 0x189), length=1)
    p.hook(q + 0x189, Mark("set_types_called", q + 0x18E), length=5)
    p.hook(q + 0x18E, Read("is_in_battle", q + 0x191), length=3)
    p.hook(q + 0x191, Sm83AndImmediate(0xFF, q + 0x192), length=1)
    p.hook(q + 0x194, Reload(q + 0x197), length=3)
    p.hook(q + 0x197, Boundary(0, q + 0x19A), length=3)
    p.hook(q + 0x19A, Read("pokedex_num", q + 0x19D), length=3)
    p.hook(q + 0x19D, Sm83DecRegister("a", q + 0x19E), length=1)
    p.hook(q + 0x1A5, Mark("owned_flag_called", q + 0x1AB), length=6)
    p.hook(q + 0x1AE, Mark("seen_flag_called", q + 0x1B1), length=3)
    p.hook(q + 0x1B3, RestoreEntry(q + 0x1B5), length=2)
    p.hook(q + 0x1B5, Read("loaded_mon_species", q + 0x1B8), length=3)
    p.hook(q + 0x1B8, Write("party_species_write", q + 0x1B9), length=1)
    p.hook(q + 0x1B9, Boundary(0), length=1)
    state = p.factory.blank_state(addr=q + 0x17B)
    setup(state, values)
    state.regs.sp = 0xDFF0
    state.memory.store(0xDFF0, claripy.Concat(values["saved_entry_h"], values["saved_entry_l"]))
    return collect(p.factory.simulation_manager(state))


def native(name: str, values, returns=False):
    p = angr.Project(ELF, auto_load_libs=False)
    function = p.loader.find_symbol(name)
    assert function is not None
    state = p.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, claripy.Concat(*(values[name] for name in NAMES)))
    state.solver.add(values["which_pokemon"].ULE(5))
    manager = p.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=end.memory.load(NATIVE_STATE + 8, len(NAMES)),
            continuation=end.regs.rax[7:0] if returns else claripy.BVV(0, 8),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.parametrize(
    "assembly_function,native_name,returns",
    (
        (assembly_animation, "port_evolution_animation_transition", True),
        (assembly_cancel, "port_evolution_cancelled_transition", False),
        (assembly_success_species, "port_evolution_success_species_transition", False),
        (assembly_post_copy, "port_evolution_post_copy_transition", False),
        (assembly_set_types, "port_evolution_set_types_transition", False),
        (assembly_success_reload, "port_evolution_success_reload_transition", False),
    ),
)
def test_evolution_side_effect_transition(assembly_function, native_name, returns):
    values = inputs(native_name)
    assert_pathwise_equivalent(
        assembly_function(values),
        native(native_name, values, returns),
        (*REGISTERS, "memory", "continuation"),
    )


def test_exact_cancelled_body():
    location = symbol_location(SYMBOLS, "CancelledEvolution")
    assert linked_bytes(ROM, location, 16) == bytes.fromhex("21486fcd493ccd0f19e1cd526fc32e6d")
