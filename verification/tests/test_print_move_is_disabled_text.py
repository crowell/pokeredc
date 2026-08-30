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
from verification.harness.sm83_shims import Sm83LoadAHighImmediate

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF
H_WHOSE_TURN = 0xFFF3
W_PLAYER_SELECTED_MOVE = 0xCCDC
W_PLAYER_BATTLE_STATUS1 = 0xD062
W_ENEMY_BATTLE_STATUS1 = 0xD067
W_NAMED_OBJECT_INDEX = 0xD11E
W_NAME_BUFFER = 0xCD6D
MOVE_IS_DISABLED_TEXT = 0x5AA8
TEXT_BOX_ID = 0xD125
EXPECTED = bytes.fromhex(
    "21dccc1162d0f0f3a72804231167d01acba7127eea1ed1cd583021a85ac3"
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
    player_status: claripy.ast.BV
    enemy_status: claripy.ast.BV
    named_object: claripy.ast.BV
    text_box_id: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class InitialRegisterPointers(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = claripy.BVV(0xCC, 8)
        self.state.regs.l = claripy.BVV(0xDC, 8)
        self.state.regs.d = claripy.BVV(0xD0, 8)
        self.state.regs.e = claripy.BVV(0x62, 8)
        self.jump(self.state.addr + 6)


class AndA(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x50, 8),
            claripy.BVV(0x10, 8),
        )
        self.jump(self.state.addr + 1)


class SetupPointers(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        condition = self.state.regs.a == 0
        for zero_turn in (True, False):
            successor = self.state.copy()
            successor.add_constraints(condition if zero_turn else ~condition)
            move_address = (W_PLAYER_SELECTED_MOVE if zero_turn
                            else W_PLAYER_SELECTED_MOVE + 1)
            status_address = (W_PLAYER_BATTLE_STATUS1 if zero_turn
                              else W_ENEMY_BATTLE_STATUS1)
            successor.regs.h = claripy.BVV(move_address >> 8, 8)
            successor.regs.l = claripy.BVV(move_address & 0xFF, 8)
            successor.regs.d = claripy.BVV(status_address >> 8, 8)
            successor.regs.e = claripy.BVV(status_address & 0xFF, 8)
            self.successors.add_successor(
                successor, self.continuation, claripy.BoolV(True), "Ijk_Boring"
            )
        self.inhibit_autoret = True


class ClearChargingUp(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        status = self.state.memory.load(self.state.regs.de, 1) & 0xEF
        self.state.regs.a = status
        self.state.memory.store(self.state.regs.de, status)
        self.jump(self.state.addr + 4)


class CaptureMove(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        move = self.state.memory.load(self.state.regs.hl, 1)
        self.state.regs.a = move
        self.state.memory.store(W_NAMED_OBJECT_INDEX, move)
        self.jump(self.state.addr + 4)


class GetMoveNameBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.d = claripy.BVV(W_NAME_BUFFER >> 8, 8)
        self.state.regs.e = claripy.BVV(W_NAME_BUFFER & 0xFF, 8)
        self.jump(self.state.addr + 3)


class MoveDisabledTextPointer(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = claripy.BVV(MOVE_IS_DISABLED_TEXT >> 8, 8)
        self.state.regs.l = claripy.BVV(MOVE_IS_DISABLED_TEXT & 0xFF, 8)
        self.jump(self.state.addr + 3)


class PrintTextBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(TEXT_BOX_ID, claripy.BVV(1, 8))
        self.state.regs.b = claripy.BVV(0xC4, 8)
        self.state.regs.c = claripy.BVV(0xB9, 8)
        self.inhibit_autoret = True
        self.jump(DONE)


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "PrintMoveIsDisabledText")
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
    project.hook(base, InitialRegisterPointers(), length=6)
    project.hook(base + 6, Sm83LoadAHighImmediate(0xF3, base + 8), length=2)
    project.hook(base + 8, AndA(), length=1)
    project.hook(base + 9, SetupPointers(base + 15), length=2)
    project.hook(base + 15, ClearChargingUp(), length=4)
    project.hook(base + 19, CaptureMove(), length=4)
    project.hook(base + 23, GetMoveNameBoundary(), length=3)
    project.hook(base + 26, MoveDisabledTextPointer(), length=3)
    project.hook(base + 29, PrintTextBoundary(), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.memory.store(H_WHOSE_TURN, values["whose_turn"])
    state.memory.store(W_PLAYER_SELECTED_MOVE, claripy.BVV(0x21, 8))
    state.memory.store(W_PLAYER_SELECTED_MOVE + 1, claripy.BVV(0x43, 8))
    state.memory.store(W_PLAYER_BATTLE_STATUS1, claripy.BVV(0xF1, 8))
    state.memory.store(W_ENEMY_BATTLE_STATUS1, claripy.BVV(0xE3, 8))
    state.memory.store(W_NAMED_OBJECT_INDEX, claripy.BVV(0, 8))
    state.memory.store(TEXT_BOX_ID, claripy.BVV(0, 8))
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored
    return [
        Endpoint(
            **assembly_registers(end),
            player_status=end.memory.load(W_PLAYER_BATTLE_STATUS1, 1),
            enemy_status=end.memory.load(W_ENEMY_BATTLE_STATUS1, 1),
            named_object=end.memory.load(W_NAMED_OBJECT_INDEX, 1),
            text_box_id=end.memory.load(TEXT_BOX_ID, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_print_move_is_disabled_text")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr,
                                       NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, values["whose_turn"])
    state.memory.store(NATIVE_MEMORY + W_PLAYER_SELECTED_MOVE,
                      claripy.BVV(0x21, 8))
    state.memory.store(NATIVE_MEMORY + W_PLAYER_SELECTED_MOVE + 1,
                      claripy.BVV(0x43, 8))
    state.memory.store(NATIVE_MEMORY + W_PLAYER_BATTLE_STATUS1,
                      claripy.BVV(0xF1, 8))
    state.memory.store(NATIVE_MEMORY + W_ENEMY_BATTLE_STATUS1,
                      claripy.BVV(0xE3, 8))
    state.memory.store(NATIVE_MEMORY + W_NAMED_OBJECT_INDEX,
                      claripy.BVV(0, 8))
    state.memory.store(NATIVE_MEMORY + TEXT_BOX_ID, claripy.BVV(0, 8))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            player_status=end.memory.load(NATIVE_MEMORY + W_PLAYER_BATTLE_STATUS1, 1),
            enemy_status=end.memory.load(NATIVE_MEMORY + W_ENEMY_BATTLE_STATUS1, 1),
            named_object=end.memory.load(NATIVE_MEMORY + W_NAMED_OBJECT_INDEX, 1),
            text_box_id=end.memory.load(NATIVE_MEMORY + TEXT_BOX_ID, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_print_move_is_disabled_text_entry_pathwise_equivalence() -> None:
    values = symbolic_registers("print_move_is_disabled_text")
    values["whose_turn"] = claripy.BVS("print_move_is_disabled_text_whose_turn", 8)
    assert_pathwise_equivalent(
        _assembly(values), _native(values),
        (*REGISTERS, "player_status", "enemy_status", "named_object", "text_box_id"),
    )
