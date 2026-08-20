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
    Sm83AddAtHl,
    Sm83AndRegister,
    Sm83LoadAAtHlIncrement,
    Sm83LoadAHighImmediate,
    Sm83LoadAImmediate,
    Sm83StoreAImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
DONE = 0xEFFF
MOVE_SOUND_TABLE = 0x58BC
MOVE_SOUND_TABLE_SIZE = 3 * 256
FREQUENCY = 0xC0F1
TEMPO = 0xC0F2
H_WHose_TURN = 0xFFF3
BATTLE_MON_SPECIES = 0xD014
ENEMY_MON_SPECIES = 0xCFE5
GROWL = 0x2D
ROAR = 0x2E
TABLE_OFFSET = 19


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
    frequency: claripy.ast.BV
    tempo: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class CopyRegisterPreserveFlags(angr.SimProcedure):
    def __init__(self, source: str, target: str, next_address: int) -> None:
        super().__init__()
        self._source = source
        self._target = target
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self._target, getattr(self.state.regs, self._source))
        self.jump(self._next_address)
class GetMoveSoundSetup(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        move_id = self.state.regs.a
        self.state.regs.d = claripy.BVV(0, 8)
        self.state.regs.e = move_id
        pointer = claripy.ZeroExt(8, move_id) * 3 + 0x58BC
        self.state.regs.h = pointer[15:8]
        self.state.regs.l = pointer[7:0]
        self.jump(self._next_address)


class Jump(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.jump(self._next_address)




class IsCryMoveSummary(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        animation = self.state.globals["animation_id"]
        is_cry = (animation == GROWL) | (animation == ROAR)
        self.state.regs.f = claripy.If(
            is_cry,
            claripy.BVV(0x01, 8),
            claripy.If(animation == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)),
        )
        self.jump(self._next_address)
class GetCryDataSummary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals["cry_a"]
        self.state.regs.b = self.state.globals["cry_b"]
        self.state.regs.c = self.state.globals["cry_c"]
        self.state.memory.store(FREQUENCY, self.state.globals["cry_frequency"])
        self.state.memory.store(TEMPO, self.state.globals["cry_tempo"])
        self.jump(self.state.addr + 3)


class Boundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.successors.add_successor(
            self.state.copy(), DONE, claripy.BoolV(True), "Ijk_Boring"
        )


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for name in (
        "animation_id",
        "whose_turn",
        "battle_mon_species",
        "enemy_mon_species",
        "frequency",
        "tempo",
        "cry_a",
        "cry_b",
        "cry_c",
        "cry_frequency",
        "cry_tempo",
    ):
        values[name] = claripy.BVS(f"{prefix}_{name}", 8)
    return values


def _assembly(
    values: dict[str, claripy.ast.BV], animation_id: int
) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "GetMoveSound")
    base = location.address
    project = angr.Project(
        rom_window(ROM, location.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": base,
        },
    )
    project.hook(base, GetMoveSoundSetup(base + 0x09), length=9)
    project.hook(base + 0x09, Sm83LoadAAtHlIncrement(base + 0x0A), length=1)
    project.hook(
        base + 0x0B,
        IsCryMoveSummary(base + 0x0E),
        length=3,
    )
    project.hook(
        base + 0x0E,
        Jump(base + (0x10 if animation_id in (GROWL, ROAR) else 0x34)),
        length=2,
    )
    project.hook(base + 0x10, Sm83LoadAHighImmediate(0xF3, base + 0x12), length=2)
    project.hook(base + 0x12, Sm83AndRegister("a", base + 0x13), length=1)
    project.hook(base + 0x15, Sm83LoadAImmediate(BATTLE_MON_SPECIES, base + 0x18), length=3)
    project.hook(base + 0x1A, Sm83LoadAImmediate(ENEMY_MON_SPECIES, base + 0x1D), length=3)
    project.hook(base + 0x1E, GetCryDataSummary(), length=3)
    project.hook(
        base + 0x21,
        CopyRegisterPreserveFlags("a", "b", base + 0x22),
        length=1,
    )
    project.hook(base + 0x23, Sm83LoadAImmediate(FREQUENCY, base + 0x26), length=3)
    project.hook(base + 0x26, Sm83AddAtHl(base + 0x27), length=1)
    project.hook(base + 0x27, Sm83StoreAImmediate(FREQUENCY, base + 0x2A), length=3)
    project.hook(base + 0x2B, Sm83LoadAImmediate(TEMPO, base + 0x2E), length=3)
    project.hook(base + 0x2E, Sm83AddAtHl(base + 0x2F), length=1)
    project.hook(base + 0x2F, Sm83StoreAImmediate(TEMPO, base + 0x32), length=3)
    project.hook(base + 0x34, Sm83LoadAAtHlIncrement(base + 0x35), length=1)
    project.hook(base + 0x35, Sm83StoreAImmediate(FREQUENCY, base + 0x38), length=3)
    project.hook(base + 0x38, Sm83LoadAAtHlIncrement(base + 0x39), length=1)
    project.hook(base + 0x39, Sm83StoreAImmediate(TEMPO, base + 0x3C), length=3)
    project.hook(
        base + 0x3C,
        CopyRegisterPreserveFlags("b", "a", base + 0x3D),
        length=1,
    )
    project.hook(base + 0x3D, Boundary(), length=1)

    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.globals["animation_id"] = values["animation_id"]
    state.globals["cry_a"] = values["cry_a"]
    state.globals["cry_b"] = values["cry_b"]
    state.globals["cry_c"] = values["cry_c"]
    state.globals["cry_frequency"] = values["cry_frequency"]
    state.globals["cry_tempo"] = values["cry_tempo"]
    state.memory.store(H_WHose_TURN, values["whose_turn"])
    state.memory.store(BATTLE_MON_SPECIES, values["battle_mon_species"])
    state.memory.store(ENEMY_MON_SPECIES, values["enemy_mon_species"])
    state.memory.store(FREQUENCY, values["frequency"])
    state.memory.store(TEMPO, values["tempo"])

    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=8)
    assert not manager.errored
    return [
        Endpoint(
            **assembly_registers(end),
            frequency=end.memory.load(FREQUENCY, 1),
            tempo=end.memory.load(TEMPO, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_get_move_sound")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    fields = {
        8: "frequency",
        9: "tempo",
        10: "animation_id",
        11: "whose_turn",
        12: "battle_mon_species",
        13: "enemy_mon_species",
        14: "cry_a",
        15: "cry_b",
        16: "cry_c",
        17: "cry_frequency",
        18: "cry_tempo",
    }
    for offset, name in fields.items():
        state.memory.store(NATIVE_STATE + offset, values[name])
    table = linked_bytes(ROM, symbol_location(SYMBOLS, "MoveSoundTable"), MOVE_SOUND_TABLE_SIZE)
    state.memory.store(
        NATIVE_STATE + TABLE_OFFSET,
        claripy.BVV(int.from_bytes(table, "big"), len(table) * 8),
        endness="Iend_BE",
    )
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            frequency=end.memory.load(NATIVE_STATE + 8, 1),
            tempo=end.memory.load(NATIVE_STATE + 9, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
@pytest.mark.parametrize("animation_id", (0, 1))
def test_get_move_sound_pathwise_equivalence(animation_id: int) -> None:
    values = _inputs(f"get_move_sound_{animation_id:02x}")
    values["animation_id"] = claripy.BVV(animation_id, 8)
    assert_pathwise_equivalent(
        _assembly(values, animation_id),
        _native(values),
        (*REGISTERS, "frequency", "tempo"),
    )
