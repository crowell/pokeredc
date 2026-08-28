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
from verification.harness.sm83_shims import Sm83LoadAAtHlIncrement

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
DONE = 0xFFFF
TABLE_PTR = 0x7000
SCREEN_MAP = 0xC3A0
SCREEN_WIDTH = 20

HANDLER_EXPECTED = bytes.fromhex("2a5f2a57d52a5f7e57cd7573d1c9")


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
    text_pointer: claripy.ast.BV
    table: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["h"] = claripy.BVV(TABLE_PTR >> 8, 8)
    values["l"] = claripy.BVV(TABLE_PTR & 0xFF, 8)
    values["text_low"] = claripy.BVS(f"{prefix}_text_low", 8)
    values["text_high"] = claripy.BVS(f"{prefix}_text_high", 8)
    values["column"] = claripy.BVS(f"{prefix}_column", 8)
    values["row"] = claripy.BVS(f"{prefix}_row", 8)
    return values


def _setup(
    state: angr.SimState,
    values: dict[str, claripy.ast.BV],
    native: bool,
) -> None:
    base = NATIVE_MEMORY if native else 0
    state.memory.store(base + TABLE_PTR, values["text_low"])
    state.memory.store(base + TABLE_PTR + 1, values["text_high"])
    state.memory.store(base + TABLE_PTR + 2, values["column"])
    state.memory.store(base + TABLE_PTR + 3, values["row"])
    state.solver.add(claripy.ULE(values["column"], 19))
    state.solver.add(claripy.ULE(values["row"], 17))


def _endpoint(state: angr.SimState, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    registers = native_registers(state, NATIVE_STATE) if native else assembly_registers(state)
    return Endpoint(
        **registers,
        text_pointer=claripy.Concat(registers["d"], registers["e"]),
        table=claripy.Concat(
            state.memory.load(base + TABLE_PTR, 1),
            state.memory.load(base + TABLE_PTR + 1, 1),
            state.memory.load(base + TABLE_PTR + 2, 1),
            state.memory.load(base + TABLE_PTR + 3, 1),
        ),
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


class PushDE(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        sp = self.state.solver.eval(self.state.regs.sp)
        self.state.memory.store(sp - 1, self.state.regs.d)
        self.state.memory.store(sp - 2, self.state.regs.e)
        self.state.regs.sp = claripy.BVV(sp - 2, 16)
        self.jump(self.next_address)
class LoadAAtHL(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self.state.regs.hl, 1)
        self.jump(self.next_address)



class PopDE(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        sp = self.state.solver.eval(self.state.regs.sp)
        self.state.regs.e = self.state.memory.load(sp, 1)
        self.state.regs.d = self.state.memory.load(sp + 1, 1)
        self.state.regs.sp = claripy.BVV(sp + 2, 16)
        self.jump(self.next_address)


class GetAddressBoundary(angr.SimProcedure):
    """Complete legal-coordinate transition of GetAddressOfScreenCoords."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        row = self.state.regs.d
        column = self.state.regs.e
        screen = claripy.BVV(SCREEN_MAP, 16) + claripy.ZeroExt(8, row) * SCREEN_WIDTH
        screen = screen + claripy.ZeroExt(8, column)
        self.state.regs.hl = screen
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.d = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x40, 8)
        self.jump(self.next_address)


class Return(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(DONE)


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    handler = symbol_location(SYMBOLS, "GetTextBoxIDText")
    address = symbol_location(SYMBOLS, "GetAddressOfScreenCoords")
    assert handler.bank == 1
    assert handler.address == 0x7367
    assert address.address == 0x7375
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
    project.hook(base + 0x00, Sm83LoadAAtHlIncrement(base + 0x01), length=1)
    project.hook(base + 0x01, CopyRegister("e", "a", base + 0x02), length=1)
    project.hook(base + 0x02, Sm83LoadAAtHlIncrement(base + 0x03), length=1)
    project.hook(base + 0x03, CopyRegister("d", "a", base + 0x04), length=1)
    project.hook(base + 0x04, PushDE(base + 0x05), length=1)
    project.hook(base + 0x05, Sm83LoadAAtHlIncrement(base + 0x06), length=1)
    project.hook(base + 0x06, CopyRegister("e", "a", base + 0x07), length=1)
    project.hook(base + 0x07, LoadAAtHL(base + 0x08), length=1)
    project.hook(base + 0x08, CopyRegister("d", "a", base + 0x09), length=1)
    project.hook(base + 0x09, GetAddressBoundary(base + 0x0C), length=3)
    project.hook(base + 0x0C, PopDE(base + 0x0D), length=1)
    project.hook(base + 0x0D, Return(), length=1)

    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _setup(state, values, native=False)
    state.regs.sp = STACK
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=64)
    assert not manager.errored, manager.errored
    assert len(manager.found) == 1, len(manager.found)
    return [_endpoint(final, native=False) for final in manager.found]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_get_text_box_id_text")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 6, claripy.BVV(TABLE_PTR >> 8, 8))
    state.memory.store(NATIVE_STATE + 7, claripy.BVV(TABLE_PTR & 0xFF, 8))
    _setup(state, values, native=True)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored, manager.errored
    assert len(manager.deadended) == 18, len(manager.deadended)
    return [_endpoint(final, native=True) for final in manager.deadended]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(
    not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`"
)
def test_get_text_box_id_text_pathwise_equivalence() -> None:
    values = _inputs("get_text_box_id_text")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "text_pointer", "table"),
    )
