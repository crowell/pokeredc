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
from verification.harness.sm83_shims import Sm83LoadAHighImmediate, Sm83StoreAImmediate

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF
H_WHOSE_TURN = 0xFFF3
W_PLAYER_MOVE_EFFECT = 0xCFD3
W_ENEMY_MOVE_EFFECT = 0xCFCD
W_DAMAGE_MULTIPLIERS = 0xD05B
W_CRITICAL = 0xD05E
W_TEXT_BOX_ID = 0xD125
EXPECTED = bytes.fromhex(
    "11d3cff0f3a7280311cdcf21575cfa5bd0e67f280d21425cfa5ed0feff2003"
    "214c5cd5cd493cafea5ed0d11afe2d"
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
    critical: claripy.ast.BV
    text_box_id: claripy.ast.BV
    jump_kick: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class SetupPointers(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.d = claripy.BVV(0xCF, 8)
        self.state.regs.e = claripy.BVV(0xD3, 8)
        self.jump(self.continuation)


class AndA(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x50, 8),
            claripy.BVV(0x10, 8),
        )
        self.jump(self.state.addr + 1)


class SelectTurn(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        condition = self.state.regs.a == 0
        for player_turn in (True, False):
            successor = self.state.copy()
            successor.add_constraints(condition if player_turn else ~condition)
            successor.regs.d = claripy.BVV(0xCF, 8)
            successor.regs.e = claripy.BVV(0xD3 if player_turn else 0xCD, 8)
            self.successors.add_successor(
                successor, self.continuation, claripy.BoolV(True), "Ijk_Boring"
            )
        self.inhibit_autoret = True


class LoadHL(angr.SimProcedure):
    def __init__(self, value: int, continuation: int) -> None:
        super().__init__()
        self.value = value
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = claripy.BVV(self.value >> 8, 8)
        self.state.regs.l = claripy.BVV(self.value & 0xFF, 8)
        self.jump(self.continuation)


class SelectText(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        effectiveness = self.state.memory.load(W_DAMAGE_MULTIPLIERS, 1) & 0x7F
        critical = self.state.memory.load(W_CRITICAL, 1)
        cases = (
            (effectiveness == 0, 0x5C57),
            ((effectiveness != 0) & (critical != 0xFF), 0x5C42),
            ((effectiveness != 0) & (critical == 0xFF), 0x5C4C),
        )
        for condition, pointer in cases:
            successor = self.state.copy()
            successor.add_constraints(condition)
            successor.regs.h = claripy.BVV(pointer >> 8, 8)
            successor.regs.l = claripy.BVV(pointer & 0xFF, 8)
            self.successors.add_successor(
                successor, self.continuation, claripy.BoolV(True), "Ijk_Boring"
            )
        self.inhibit_autoret = True


class PrintTextBoundary(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(W_TEXT_BOX_ID, claripy.BVV(1, 8))
        self.state.regs.b = claripy.BVV(0xC4, 8)
        self.state.regs.c = claripy.BVV(0xB9, 8)
        self.jump(self.continuation)


class XorA(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x40, 8)
        self.jump(self.state.addr + 1)


class LoadEffect(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self.state.regs.de, 1)
        self.jump(self.continuation)


class CompareBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        effect = self.state.regs.a
        equal = effect == 0x2D
        for jump_kick in (True, False):
            successor = self.state.copy()
            successor.add_constraints(equal if jump_kick else ~equal)
            half_borrow = (effect & 0x0F) < 0x0D
            borrow = effect < 0x2D
            successor.regs.f = (
                claripy.If(equal, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
                | claripy.If(half_borrow, claripy.BVV(0x10, 8), claripy.BVV(0, 8))
                | claripy.If(borrow, claripy.BVV(0x01, 8), claripy.BVV(0, 8))
                | claripy.BVV(0x02, 8)
            )
            successor.globals["jump_kick"] = claripy.BVV(1 if jump_kick else 0, 8)
            self.successors.add_successor(
                successor, DONE, claripy.BoolV(True), "Ijk_Boring"
            )
        self.inhibit_autoret = True


def _endpoint(state: angr.SimState, *, native: bool, base: int) -> Endpoint:
    registers = native_registers(state, NATIVE_STATE) if native else assembly_registers(state)
    return Endpoint(
        **registers,
        critical=state.memory.load(base + W_CRITICAL, 1),
        text_box_id=state.memory.load(base + W_TEXT_BOX_ID, 1),
        jump_kick=(
            state.memory.load(NATIVE_STATE + 9, 1)
            if native else state.globals["jump_kick"]
        ),
        constraints=tuple(state.solver.constraints),
    )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "PrintMoveFailureText")
    base = location.address
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
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
    project.hook(base, SetupPointers(base + 3), length=3)
    project.hook(base + 3, Sm83LoadAHighImmediate(H_WHOSE_TURN, base + 5), length=2)
    project.hook(base + 5, AndA(), length=1)
    project.hook(base + 6, SelectTurn(base + 11), length=2)
    project.hook(base + 11, LoadHL(0x5C57, base + 14), length=3)
    project.hook(base + 14, Sm83LoadAHighImmediate(W_DAMAGE_MULTIPLIERS, base + 17), length=3)
    project.hook(base + 17, AndA(), length=1)
    project.hook(base + 18, SelectText(base + 34), length=2)
    project.hook(base + 34, PrintTextBoundary(base + 38), length=4)
    project.hook(base + 38, XorA(), length=1)
    project.hook(base + 39, Sm83StoreAImmediate(W_CRITICAL, base + 42), length=3)
    project.hook(base + 42, LoadEffect(base + 44), length=2)
    project.hook(base + 44, CompareBoundary(), length=2)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.memory.store(H_WHOSE_TURN, values["whose_turn"])
    state.memory.store(W_DAMAGE_MULTIPLIERS, values["damage"])
    state.memory.store(W_CRITICAL, values["critical"])
    state.memory.store(W_PLAYER_MOVE_EFFECT, values["player_effect"])
    state.memory.store(W_ENEMY_MOVE_EFFECT, values["enemy_effect"])
    state.memory.store(W_TEXT_BOX_ID, claripy.BVV(0, 8))
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=4)
    assert not manager.errored
    return [_endpoint(end, native=False, base=0) for end in manager.found]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_print_move_failure_text")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, values["whose_turn"])
    state.memory.store(NATIVE_STATE + 9, claripy.BVV(0, 8))
    state.memory.store(NATIVE_MEMORY + W_DAMAGE_MULTIPLIERS, values["damage"])
    state.memory.store(NATIVE_MEMORY + W_CRITICAL, values["critical"])
    state.memory.store(NATIVE_MEMORY + W_PLAYER_MOVE_EFFECT, values["player_effect"])
    state.memory.store(NATIVE_MEMORY + W_ENEMY_MOVE_EFFECT, values["enemy_effect"])
    state.memory.store(NATIVE_MEMORY + W_TEXT_BOX_ID, claripy.BVV(0, 8))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [_endpoint(end, native=True, base=NATIVE_MEMORY) for end in manager.deadended]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_print_move_failure_text_entry_pathwise_equivalence() -> None:
    values = symbolic_registers("print_move_failure_text")
    values["whose_turn"] = claripy.BVS("print_move_failure_text_whose_turn", 8)
    values["damage"] = claripy.BVS("print_move_failure_text_damage", 8)
    values["critical"] = claripy.BVS("print_move_failure_text_critical", 8)
    values["player_effect"] = claripy.BVS("print_move_failure_text_player_effect", 8)
    values["enemy_effect"] = claripy.BVS("print_move_failure_text_enemy_effect", 8)
    assert_pathwise_equivalent(
        _assembly(values), _native(values),
        (*REGISTERS, "critical", "text_box_id", "jump_kick"),
    )
