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
    Sm83LoadAAtHlIncrement,
    Sm83LoadAImmediate,
    Sm83SlaRegister,
    Sm83StoreAImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
DONE = 0xFFFF

W_OPTIONS = 0xD355
W_OPTIONS_TEXT_SPEED_CURSOR_X = 0xCD3D
W_OPTIONS_BATTLE_ANIM_CURSOR_X = 0xCD3E
W_OPTIONS_BATTLE_STYLE_CURSOR_X = 0xCD3F
W_OPTIONS_CANCEL_CURSOR_X = 0xCD40
TILEMAP_TEXT_SPEED = 0xC3DC
TILEMAP_BATTLE_ANIM = 0xC440
TILEMAP_BATTLE_STYLE = 0xC4A4
TILEMAP_CANCEL = 0xC4E0
ROW_SIZE = 18
RIGHT_ARROW = 0xEC

HANDLER_EXPECTED = bytes.fromhex(
    "219760fa55d34fe63fc5110200cdab3dc12b7eea3dcd21dcc3cd8f60"
    "cb213e0130023e0aea3ecd2140c4cd8f60cb213e0130023e0aea3fcd"
    "21a4c4cd8f6021e0c43e015f16001936ecc9"
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
    options: claripy.ast.BV
    speed_x: claripy.ast.BV
    battle_anim_x: claripy.ast.BV
    battle_style_x: claripy.ast.BV
    cancel_x: claripy.ast.BV
    row0: claripy.ast.BV
    row1: claripy.ast.BV
    row2: claripy.ast.BV
    row3: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["options"] = claripy.BVS(f"{prefix}_options", 8)
    values["speed_x"] = claripy.BVS(f"{prefix}_speed_x", 8)
    values["battle_anim_x"] = claripy.BVS(f"{prefix}_battle_anim_x", 8)
    values["battle_style_x"] = claripy.BVS(f"{prefix}_battle_style_x", 8)
    values["cancel_x"] = claripy.BVS(f"{prefix}_cancel_x", 8)
    for row in range(4):
        for offset in range(ROW_SIZE):
            values[f"row{row}_{offset}"] = claripy.BVS(
                f"{prefix}_row{row}_{offset}", 8
            )
    return values


def _setup(
    state: angr.SimState,
    values: dict[str, claripy.ast.BV],
    native: bool,
) -> None:
    base = NATIVE_MEMORY if native else 0
    state.memory.store(base + W_OPTIONS, values["options"])
    state.memory.store(
        base + W_OPTIONS_TEXT_SPEED_CURSOR_X,
        values["speed_x"],
    )
    state.memory.store(
        base + W_OPTIONS_BATTLE_ANIM_CURSOR_X,
        values["battle_anim_x"],
    )
    state.memory.store(
        base + W_OPTIONS_BATTLE_STYLE_CURSOR_X,
        values["battle_style_x"],
    )
    state.memory.store(base + W_OPTIONS_CANCEL_CURSOR_X, values["cancel_x"])
    row_bases = (
        TILEMAP_TEXT_SPEED,
        TILEMAP_BATTLE_ANIM,
        TILEMAP_BATTLE_STYLE,
        TILEMAP_CANCEL,
    )
    for row, address in enumerate(row_bases):
        for offset in range(ROW_SIZE):
            state.memory.store(
                base + address + offset,
                values[f"row{row}_{offset}"],
            )


def _endpoint(state: angr.SimState, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    registers = native_registers(state, NATIVE_STATE) if native else assembly_registers(state)
    row_bases = (
        TILEMAP_TEXT_SPEED,
        TILEMAP_BATTLE_ANIM,
        TILEMAP_BATTLE_STYLE,
        TILEMAP_CANCEL,
    )
    rows = tuple(
        claripy.Concat(
            *(state.memory.load(base + address + i, 1) for i in range(ROW_SIZE))
        )
        for address in row_bases
    )
    return Endpoint(
        **registers,
        options=state.memory.load(base + W_OPTIONS, 1),
        speed_x=state.memory.load(base + W_OPTIONS_TEXT_SPEED_CURSOR_X, 1),
        battle_anim_x=state.memory.load(base + W_OPTIONS_BATTLE_ANIM_CURSOR_X, 1),
        battle_style_x=state.memory.load(base + W_OPTIONS_BATTLE_STYLE_CURSOR_X, 1),
        cancel_x=state.memory.load(base + W_OPTIONS_CANCEL_CURSOR_X, 1),
        row0=rows[0],
        row1=rows[1],
        row2=rows[2],
        row3=rows[3],
        constraints=tuple(state.solver.constraints),
    )


class CopyRegister(angr.SimProcedure):
    def __init__(self, destination: str, source: str, next_address: int) -> None:
        super().__init__()
        self.destination = destination
        self.source = source
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.destination, getattr(self.state.regs, self.source))
        self.jump(self.next_address)


class PushPair(angr.SimProcedure):
    def __init__(self, high: str, low: str, next_address: int) -> None:
        super().__init__()
        self.high = high
        self.low = low
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        sp = self.state.solver.eval(self.state.regs.sp)
        self.state.memory.store(sp - 1, getattr(self.state.regs, self.high))
        self.state.memory.store(sp - 2, getattr(self.state.regs, self.low))
        self.state.regs.sp = claripy.BVV(sp - 2, 16)
        self.jump(self.next_address)


class PopPair(angr.SimProcedure):
    def __init__(self, high: str, low: str, next_address: int) -> None:
        super().__init__()
        self.high = high
        self.low = low
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        sp = self.state.solver.eval(self.state.regs.sp)
        setattr(self.state.regs, self.low, self.state.memory.load(sp, 1))
        setattr(self.state.regs, self.high, self.state.memory.load(sp + 1, 1))
        self.state.regs.sp = claripy.BVV(sp + 2, 16)
        self.jump(self.next_address)


class LoadHLImmediate(angr.SimProcedure):
    def __init__(self, value: int, next_address: int) -> None:
        super().__init__()
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.hl = claripy.BVV(self.value, 16)
        self.jump(self.next_address)


class LoadDEImmediate(angr.SimProcedure):
    def __init__(self, value: int, next_address: int) -> None:
        super().__init__()
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.d = claripy.BVV(self.value >> 8, 8)
        self.state.regs.e = claripy.BVV(self.value & 0xFF, 8)
        self.jump(self.next_address)


class LoadRegisterImmediate(angr.SimProcedure):
    def __init__(self, register: str, value: int, next_address: int) -> None:
        super().__init__()
        self.register = register
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.register, claripy.BVV(self.value, 8))
        self.jump(self.next_address)


class DecHL(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.hl = self.state.regs.hl - 1
        self.jump(self.next_address)


class LoadAAtHL(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self.state.regs.hl, 1)
        self.jump(self.next_address)


class ArrowCall(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.d = claripy.BVV(0, 8)
        self.state.regs.e = self.state.regs.a
        self.state.regs.hl = self.state.regs.hl + claripy.ZeroExt(8, self.state.regs.a)
        self.state.memory.store(self.state.regs.hl, claripy.BVV(RIGHT_ARROW, 8))
        self.jump(self.next_address)


class StoreAtHL(angr.SimProcedure):
    def __init__(self, value: int, next_address: int) -> None:
        super().__init__()
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(self.state.regs.hl, claripy.BVV(self.value, 8))
        self.jump(self.next_address)


class IsInArrayBoundary(angr.SimProcedure):
    """Complete IsInArray transition for the four table outcomes."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        value = self.state.regs.a
        self.inhibit_autoret = True
        branches = (
            (value == 5, 0x6097),
            (value == 3, 0x6099),
            (value == 1, 0x609B),
        )
        covered = claripy.BoolV(False)
        for condition, address in branches:
            successor = self.state.copy()
            successor.solver.add(condition)
            successor.regs.hl = claripy.BVV(address, 16)
            successor.regs.ip = claripy.BVV(self.next_address, 16)
            self.successors.add_successor(
                successor,
                self.next_address,
                condition,
                "Ijk_Boring",
            )
            covered = claripy.Or(covered, condition)
        successor = self.state.copy()
        condition = claripy.Not(covered)
        successor.solver.add(condition)
        successor.regs.hl = claripy.BVV(0x609D, 16)
        successor.regs.ip = claripy.BVV(self.next_address, 16)
        self.successors.add_successor(
            successor,
            self.next_address,
            condition,
            "Ijk_Boring",
        )


class ForkOnNC(angr.SimProcedure):
    def __init__(self, taken: int, fallthrough: int) -> None:
        super().__init__()
        self.taken = taken
        self.fallthrough = fallthrough

    def run(self) -> None:  # type: ignore[override]
        nc = ((self.state.regs.f >> 0) & 1) == 0
        taken = self.state.copy()
        fallthrough = self.state.copy()
        taken.solver.add(nc)
        fallthrough.solver.add(claripy.Not(nc))
        taken.regs.ip = claripy.BVV(self.taken, 16)
        fallthrough.regs.ip = claripy.BVV(self.fallthrough, 16)
        self.inhibit_autoret = True
        self.successors.add_successor(taken, self.taken, nc, "Ijk_Boring")
        self.successors.add_successor(
            fallthrough,
            self.fallthrough,
            claripy.Not(nc),
            "Ijk_Boring",
        )


class Return(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(DONE)


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    handler = symbol_location(SYMBOLS, "SetCursorPositionsFromOptions")
    assert handler.bank == 1
    assert handler.address == 0x604C
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
    project.hook(base + 0x00, LoadHLImmediate(0x6097, base + 0x03), length=3)
    project.hook(base + 0x03, Sm83LoadAImmediate(W_OPTIONS, base + 0x06), length=3)
    project.hook(base + 0x06, CopyRegister("c", "a", base + 0x07), length=1)
    project.hook(base + 0x07, Sm83AndImmediate(0x3F, base + 0x09), length=2)
    project.hook(base + 0x09, PushPair("b", "c", base + 0x0A), length=1)
    project.hook(base + 0x0A, LoadDEImmediate(2, base + 0x0D), length=3)
    project.hook(base + 0x0D, IsInArrayBoundary(base + 0x10), length=3)
    project.hook(base + 0x10, PopPair("b", "c", base + 0x11), length=1)
    project.hook(base + 0x11, DecHL(base + 0x12), length=1)
    project.hook(base + 0x12, LoadAAtHL(base + 0x13), length=1)
    project.hook(base + 0x13, Sm83StoreAImmediate(W_OPTIONS_TEXT_SPEED_CURSOR_X, base + 0x16), length=3)
    project.hook(base + 0x16, LoadHLImmediate(TILEMAP_TEXT_SPEED, base + 0x19), length=3)
    project.hook(base + 0x19, ArrowCall(base + 0x1C), length=3)
    project.hook(base + 0x1C, Sm83SlaRegister("c", base + 0x1E), length=2)
    project.hook(base + 0x1E, LoadRegisterImmediate("a", 1, base + 0x20), length=2)
    project.hook(base + 0x20, ForkOnNC(base + 0x24, base + 0x22), length=2)
    project.hook(base + 0x22, LoadRegisterImmediate("a", 10, base + 0x24), length=2)
    project.hook(base + 0x24, Sm83StoreAImmediate(W_OPTIONS_BATTLE_ANIM_CURSOR_X, base + 0x27), length=3)
    project.hook(base + 0x27, LoadHLImmediate(TILEMAP_BATTLE_ANIM, base + 0x2A), length=3)
    project.hook(base + 0x2A, ArrowCall(base + 0x2D), length=3)
    project.hook(base + 0x2D, Sm83SlaRegister("c", base + 0x2F), length=2)
    project.hook(base + 0x2F, LoadRegisterImmediate("a", 1, base + 0x31), length=2)
    project.hook(base + 0x33, LoadRegisterImmediate("a", 10, base + 0x35), length=2)
    project.hook(base + 0x35, Sm83StoreAImmediate(W_OPTIONS_BATTLE_STYLE_CURSOR_X, base + 0x38), length=3)
    project.hook(base + 0x38, LoadHLImmediate(TILEMAP_BATTLE_STYLE, base + 0x3B), length=3)
    project.hook(base + 0x3B, ArrowCall(base + 0x3E), length=3)
    project.hook(base + 0x3E, LoadHLImmediate(TILEMAP_CANCEL, base + 0x41), length=3)
    project.hook(base + 0x41, LoadRegisterImmediate("a", 1, base + 0x43), length=2)
    project.hook(base + 0x43, CopyRegister("e", "a", base + 0x44), length=1)
    project.hook(base + 0x44, LoadRegisterImmediate("d", 0, base + 0x46), length=2)
    project.hook(base + 0x46, Sm83AddHlRegisterPair("de", base + 0x47), length=1)
    project.hook(base + 0x47, StoreAtHL(RIGHT_ARROW, base + 0x49), length=2)
    project.hook(base + 0x49, Return(), length=1)

    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _setup(state, values, native=False)
    state.regs.sp = STACK
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=64)
    assert not manager.errored, manager.errored
    assert len(manager.found) == 16, len(manager.found)
    return [_endpoint(final, native=False) for final in manager.found]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_set_cursor_positions_from_options")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, values, native=True)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored, manager.errored
    assert len(manager.deadended) == 4, len(manager.deadended)
    return [_endpoint(final, native=True) for final in manager.deadended]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(
    not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`"
)
def test_set_cursor_positions_from_options_pathwise_equivalence() -> None:
    values = _inputs("set_cursor_positions_from_options")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (
            *REGISTERS,
            "options",
            "speed_x",
            "battle_anim_x",
            "battle_style_x",
            "cancel_x",
            "row0",
            "row1",
            "row2",
            "row3",
        ),
    )
