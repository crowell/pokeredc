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
    Sm83AndImmediate,
    Sm83CpImmediate,
    Sm83LoadAImmediate,
    Sm83StoreAImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xFFFF

W_STATUS_FLAGS1 = 0xD728
W_STATUS_FLAGS6 = 0xD732
W_CUR_MAP = 0xD35E
W_EVENT_FLAGS = 0xD747
W_COORD_INDEX = 0xCD3D
W_Y_COORD = 0xD361
W_X_COORD = 0xD362
W_TEXT_BOX_ID = 0xD125
H_CURRENT_TOO_FAST_TEXT = 0x4DFA
H_CYCLING_IS_FUN_TEXT = 0x4DFF
STAIRS_COORDS = 0x4DF7
STAIRS_EVENT_BYTE = 0x13A
SEAFOAM_ISLANDS_B4F = 0xA2
PRINT_TEXT_BOX = 0xC4B9

HANDLER_EXPECTED = bytes.fromhex(
    "2128d7cbcefa32d7cb6f2020fa5ed3fea2c0fa81d8e603fe03c8"
    "21f74dcd b f34d02128d7cb8e21fa4dc3493c2128d7cb8e21ff4dc3493c".replace(" ", "")
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
    status1: claripy.ast.BV
    status6: claripy.ast.BV
    current_map: claripy.ast.BV
    event_byte: claripy.ast.BV
    coord_index: claripy.ast.BV
    textbox_id: claripy.ast.BV
    y_coord: claripy.ast.BV
    x_coord: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for name in (
        "status1",
        "status6",
        "current_map",
        "event_byte",
        "coord_index",
        "textbox_id",
        "y_coord",
        "x_coord",
    ):
        values[name] = claripy.BVS(f"{prefix}_{name}", 8)
    return values


def _setup(
    state: angr.SimState,
    values: dict[str, claripy.ast.BV],
    native: bool,
) -> None:
    base = NATIVE_MEMORY if native else 0
    state.memory.store(base + W_STATUS_FLAGS1, values["status1"])
    state.memory.store(base + W_STATUS_FLAGS6, values["status6"])
    state.memory.store(base + W_CUR_MAP, values["current_map"])
    state.memory.store(base + W_EVENT_FLAGS + STAIRS_EVENT_BYTE, values["event_byte"])
    state.memory.store(base + W_COORD_INDEX, values["coord_index"])
    state.memory.store(base + W_TEXT_BOX_ID, values["textbox_id"])
    state.memory.store(base + W_Y_COORD, values["y_coord"])
    state.memory.store(base + W_X_COORD, values["x_coord"])


def _endpoint(state: angr.SimState, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    registers = native_registers(state, NATIVE_STATE) if native else assembly_registers(state)
    return Endpoint(
        **registers,
        status1=state.memory.load(base + W_STATUS_FLAGS1, 1),
        status6=state.memory.load(base + W_STATUS_FLAGS6, 1),
        current_map=state.memory.load(base + W_CUR_MAP, 1),
        event_byte=state.memory.load(base + W_EVENT_FLAGS + STAIRS_EVENT_BYTE, 1),
        coord_index=state.memory.load(base + W_COORD_INDEX, 1),
        textbox_id=state.memory.load(base + W_TEXT_BOX_ID, 1),
        y_coord=state.memory.load(base + W_Y_COORD, 1),
        x_coord=state.memory.load(base + W_X_COORD, 1),
        constraints=tuple(state.solver.constraints),
    )


class SetBitAtHL(angr.SimProcedure):
    def __init__(self, bit: int, next_address: int) -> None:
        super().__init__()
        self.bit = bit
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        value = self.state.memory.load(self.state.regs.hl, 1)
        self.state.memory.store(self.state.regs.hl, value | (1 << self.bit))
        self.jump(self.next_address)


class ResBitAtHL(angr.SimProcedure):
    def __init__(self, bit: int, next_address: int) -> None:
        super().__init__()
        self.bit = bit
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        value = self.state.memory.load(self.state.regs.hl, 1)
        self.state.memory.store(self.state.regs.hl, value & ~(1 << self.bit))
        self.jump(self.next_address)


class BitA(angr.SimProcedure):
    def __init__(self, bit: int, next_address: int) -> None:
        super().__init__()
        self.bit = bit
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        value = self.state.regs.a
        self.state.regs.f = (
            (self.state.regs.f & 1)
            | 0x10
            | claripy.If(
                value & (1 << self.bit) == 0,
                claripy.BVV(0x40, 8),
                claripy.BVV(0, 8),
            )
        )
        self.jump(self.next_address)


class LoadHLImmediate(angr.SimProcedure):
    def __init__(self, value: int, next_address: int) -> None:
        super().__init__()
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.hl = claripy.BVV(self.value, 16)
        self.jump(self.next_address)


class ForkOnZ(angr.SimProcedure):
    def __init__(self, taken: int, fallthrough: int, taken_when_set: bool) -> None:
        super().__init__()
        self.taken = taken
        self.fallthrough = fallthrough
        self.taken_when_set = taken_when_set

    def run(self) -> None:  # type: ignore[override]
        z_set = ((self.state.regs.f >> 6) & 1) == 1
        condition = z_set if self.taken_when_set else claripy.Not(z_set)
        taken = self.state.copy()
        fallthrough = self.state.copy()
        taken.solver.add(condition)
        fallthrough.solver.add(claripy.Not(condition))
        taken.regs.ip = claripy.BVV(self.taken, 16)
        fallthrough.regs.ip = claripy.BVV(self.fallthrough, 16)
        self.inhibit_autoret = True
        self.successors.add_successor(taken, self.taken, condition, "Ijk_Boring")
        self.successors.add_successor(
            fallthrough,
            self.fallthrough,
            claripy.Not(condition),
            "Ijk_Boring",
        )


class ReturnNZ(angr.SimProcedure):
    def __init__(self, taken: int, fallthrough: int) -> None:
        super().__init__()
        self.taken = taken
        self.fallthrough = fallthrough

    def run(self) -> None:  # type: ignore[override]
        z_set = ((self.state.regs.f >> 6) & 1) == 1
        taken = self.state.copy()
        fallthrough = self.state.copy()
        taken.solver.add(claripy.Not(z_set))
        fallthrough.solver.add(z_set)
        taken.regs.ip = claripy.BVV(self.taken, 16)
        fallthrough.regs.ip = claripy.BVV(self.fallthrough, 16)
        self.inhibit_autoret = True
        self.successors.add_successor(taken, self.taken, claripy.Not(z_set), "Ijk_Boring")
        self.successors.add_successor(fallthrough, self.fallthrough, z_set, "Ijk_Boring")


class ReturnZ(angr.SimProcedure):
    def __init__(self, taken: int, fallthrough: int) -> None:
        super().__init__()
        self.taken = taken
        self.fallthrough = fallthrough

    def run(self) -> None:  # type: ignore[override]
        z_set = ((self.state.regs.f >> 6) & 1) == 1
        taken = self.state.copy()
        fallthrough = self.state.copy()
        taken.solver.add(z_set)
        fallthrough.solver.add(claripy.Not(z_set))
        taken.regs.ip = claripy.BVV(self.taken, 16)
        fallthrough.regs.ip = claripy.BVV(self.fallthrough, 16)
        self.inhibit_autoret = True
        self.successors.add_successor(taken, self.taken, z_set, "Ijk_Boring")
        self.successors.add_successor(
            fallthrough,
            self.fallthrough,
            claripy.Not(z_set),
            "Ijk_Boring",
        )


class ReturnNC(angr.SimProcedure):
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


class ArePlayerCoordsBoundary(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        y = self.state.memory.load(W_Y_COORD, 1)
        x = self.state.memory.load(W_X_COORD, 1)
        found = claripy.And(y == 11, x == 7)
        self.inhibit_autoret = True
        for condition, a, flags, hl, index in (
            (found, 7, 0x41, STAIRS_COORDS + 2, 1),
            (claripy.Not(found), 0xFF, 0x10, STAIRS_COORDS + 3, 1),
        ):
            successor = self.state.copy()
            successor.solver.add(condition)
            successor.regs.a = claripy.BVV(a, 8)
            successor.regs.b = y
            successor.regs.c = x
            successor.regs.f = claripy.BVV(flags, 8)
            successor.regs.hl = claripy.BVV(hl, 16)
            successor.memory.store(W_COORD_INDEX, claripy.BVV(index, 8))
            successor.regs.ip = claripy.BVV(self.next_address, 16)
            self.successors.add_successor(
                successor,
                self.next_address,
                condition,
                "Ijk_Boring",
            )


class PrintTextBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(W_TEXT_BOX_ID, claripy.BVV(1, 8))
        self.state.regs.b = claripy.BVV(PRINT_TEXT_BOX >> 8, 8)
        self.state.regs.c = claripy.BVV(PRINT_TEXT_BOX & 0xFF, 8)
        self.jump(DONE)


class Return(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(DONE)


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    handler = symbol_location(SYMBOLS, "IsSurfingAllowed")
    assert handler.bank == 3
    assert handler.address == 0x4DC0
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
    project.hook(base + 0x00, LoadHLImmediate(W_STATUS_FLAGS1, base + 0x03), length=3)
    project.hook(base + 0x03, SetBitAtHL(1, base + 0x05), length=2)
    project.hook(base + 0x05, Sm83LoadAImmediate(W_STATUS_FLAGS6, base + 0x08), length=3)
    project.hook(base + 0x08, BitA(5, base + 0x0A), length=2)
    project.hook(base + 0x0A, ForkOnZ(base + 0x2C, base + 0x0C, taken_when_set=False), length=2)
    project.hook(base + 0x0C, Sm83LoadAImmediate(W_CUR_MAP, base + 0x0F), length=3)
    project.hook(base + 0x0F, Sm83CpImmediate(SEAFOAM_ISLANDS_B4F, base + 0x11), length=2)
    project.hook(base + 0x11, ReturnNZ(DONE, base + 0x12), length=1)
    project.hook(base + 0x12, Sm83LoadAImmediate(W_EVENT_FLAGS + STAIRS_EVENT_BYTE, base + 0x15), length=3)
    project.hook(base + 0x15, Sm83AndImmediate(3, base + 0x17), length=2)
    project.hook(base + 0x17, Sm83CpImmediate(3, base + 0x19), length=2)
    project.hook(base + 0x19, ReturnZ(DONE, base + 0x1A), length=1)
    project.hook(base + 0x1A, LoadHLImmediate(STAIRS_COORDS, base + 0x1D), length=3)
    project.hook(base + 0x1D, ArePlayerCoordsBoundary(base + 0x20), length=3)
    project.hook(base + 0x20, ReturnNC(DONE, base + 0x21), length=1)
    project.hook(base + 0x21, LoadHLImmediate(W_STATUS_FLAGS1, base + 0x24), length=3)
    project.hook(base + 0x24, ResBitAtHL(1, base + 0x26), length=2)
    project.hook(base + 0x26, LoadHLImmediate(H_CURRENT_TOO_FAST_TEXT, base + 0x29), length=3)
    project.hook(base + 0x29, PrintTextBoundary(), length=3)
    project.hook(base + 0x2C, LoadHLImmediate(W_STATUS_FLAGS1, base + 0x2F), length=3)
    project.hook(base + 0x2F, ResBitAtHL(1, base + 0x31), length=2)
    project.hook(base + 0x31, LoadHLImmediate(H_CYCLING_IS_FUN_TEXT, base + 0x34), length=3)
    project.hook(base + 0x34, PrintTextBoundary(), length=3)

    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _setup(state, values, native=False)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=8)
    assert not manager.errored, manager.errored
    assert len(manager.found) == 5, len(manager.found)
    return [_endpoint(final, native=False) for final in manager.found]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_is_surfing_allowed")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, values, native=True)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored, manager.errored
    assert len(manager.deadended) == 6, len(manager.deadended)
    return [_endpoint(final, native=True) for final in manager.deadended]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(
    not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`"
)
def test_is_surfing_allowed_pathwise_equivalence() -> None:
    values = _inputs("is_surfing_allowed")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (
            *REGISTERS,
            "status1",
            "status6",
            "current_map",
            "event_byte",
            "coord_index",
            "textbox_id",
            "y_coord",
            "x_coord",
        ),
    )
