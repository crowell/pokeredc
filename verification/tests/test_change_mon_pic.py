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
from verification.harness.rom import rom_window, symbol_location
from verification.harness.sm83_shims import (
    Sm83LoadAHighImmediate,
    Sm83LoadAImmediate,
    Sm83StoreAImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF
H_WHOSE_TURN = 0xFFF3
W_CHANGE_ENEMY = 0xCEE9
W_CHANGE_PLAYER = 0xCEEA
W_CUR_PARTY = 0xCF91
W_BATTLE_SPECIES2 = 0xCFD9
W_CUR_SPECIES = 0xD0B5
W_SPRITE_FLIPPED = 0xD0AA


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
    whose_turn: claripy.ast.BV
    change_enemy: claripy.ast.BV
    change_player: claripy.ast.BV
    cur_party: claripy.ast.BV
    battle_species2: claripy.ast.BV
    cur_species: claripy.ast.BV
    sprite_flipped: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class AndA(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:
        self.state.regs.f = claripy.BVV(0x10, 8) | claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x40, 8),
            claripy.BVV(0, 8),
        )
        self.jump(self._next_address)


class XorA(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x40, 8)
        self.jump(self._next_address)


class ContinuationBoundary(angr.SimProcedure):
    def run(self) -> None:
        self.inhibit_autoret = True
        self.successors.add_successor(
            self.state.copy(), DONE, claripy.BoolV(True), "Ijk_Boring"
        )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "ChangeMonPic")
    continuation = symbol_location(SYMBOLS, "GetMonHeader")
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
    project.hook(location.address, Sm83LoadAHighImmediate(0xF3, location.address + 2), length=2)
    project.hook(location.address + 2, AndA(location.address + 3), length=1)
    project.hook(location.address + 5, Sm83LoadAImmediate(W_CHANGE_ENEMY, location.address + 8), length=3)
    project.hook(location.address + 8, Sm83StoreAImmediate(W_CUR_PARTY, location.address + 11), length=3)
    project.hook(location.address + 11, Sm83StoreAImmediate(W_CUR_SPECIES, location.address + 14), length=3)
    project.hook(location.address + 14, XorA(location.address + 15), length=1)
    project.hook(location.address + 15, Sm83StoreAImmediate(W_SPRITE_FLIPPED, location.address + 18), length=3)
    project.hook(location.address + 29, Sm83LoadAImmediate(W_BATTLE_SPECIES2, location.address + 32), length=3)
    project.hook(location.address + 33, Sm83LoadAImmediate(W_CHANGE_PLAYER, location.address + 36), length=3)
    project.hook(location.address + 36, Sm83StoreAImmediate(W_BATTLE_SPECIES2, location.address + 39), length=3)
    project.hook(location.address + 39, Sm83StoreAImmediate(W_CUR_SPECIES, location.address + 42), length=3)
    project.hook(continuation.address, ContinuationBoundary(), length=1)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    for address, name in (
        (H_WHOSE_TURN, "whose_turn"),
        (W_CHANGE_ENEMY, "change_enemy"),
        (W_CHANGE_PLAYER, "change_player"),
        (W_CUR_PARTY, "cur_party"),
        (W_BATTLE_SPECIES2, "battle_species2"),
        (W_CUR_SPECIES, "cur_species"),
        (W_SPRITE_FLIPPED, "sprite_flipped"),
    ):
        state.memory.store(address, values[name])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=2)
    assert not manager.errored
    return [_endpoint_assembly(end) for end in manager.found]


def _endpoint_assembly(end: angr.SimState) -> Endpoint:
    return Endpoint(
        **assembly_registers(end),
        whose_turn=end.memory.load(H_WHOSE_TURN, 1),
        change_enemy=end.memory.load(W_CHANGE_ENEMY, 1),
        change_player=end.memory.load(W_CHANGE_PLAYER, 1),
        cur_party=end.memory.load(W_CUR_PARTY, 1),
        battle_species2=end.memory.load(W_BATTLE_SPECIES2, 1),
        cur_species=end.memory.load(W_CUR_SPECIES, 1),
        sprite_flipped=end.memory.load(W_SPRITE_FLIPPED, 1),
        constraints=tuple(end.solver.constraints),
    )


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_change_mon_pic")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    for address, name in (
        (H_WHOSE_TURN, "whose_turn"),
        (W_CHANGE_ENEMY, "change_enemy"),
        (W_CHANGE_PLAYER, "change_player"),
        (W_CUR_PARTY, "cur_party"),
        (W_BATTLE_SPECIES2, "battle_species2"),
        (W_CUR_SPECIES, "cur_species"),
        (W_SPRITE_FLIPPED, "sprite_flipped"),
    ):
        state.memory.store(NATIVE_MEMORY + address, values[name])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            whose_turn=end.memory.load(NATIVE_MEMORY + H_WHOSE_TURN, 1),
            change_enemy=end.memory.load(NATIVE_MEMORY + W_CHANGE_ENEMY, 1),
            change_player=end.memory.load(NATIVE_MEMORY + W_CHANGE_PLAYER, 1),
            cur_party=end.memory.load(NATIVE_MEMORY + W_CUR_PARTY, 1),
            battle_species2=end.memory.load(NATIVE_MEMORY + W_BATTLE_SPECIES2, 1),
            cur_species=end.memory.load(NATIVE_MEMORY + W_CUR_SPECIES, 1),
            sprite_flipped=end.memory.load(NATIVE_MEMORY + W_SPRITE_FLIPPED, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_change_mon_pic_header_prefix_pathwise_equivalence() -> None:
    values = symbolic_registers("change_mon_pic")
    for name in (
        "whose_turn",
        "change_enemy",
        "change_player",
        "cur_party",
        "battle_species2",
        "cur_species",
        "sprite_flipped",
    ):
        values[name] = claripy.BVS(f"change_mon_pic_{name}", 8)
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (
            *REGISTERS,
            "whose_turn",
            "change_enemy",
            "change_player",
            "cur_party",
            "battle_species2",
            "cur_species",
            "sprite_flipped",
        ),
    )
