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
    Sm83LoadAAtHlIncrement,
    Sm83LoadAHighImmediate,
    Sm83StoreAHighImmediate,
    Sm83StoreAImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
SENTINEL = 0xFFFF

H_LOADED_ROM_BANK = 0xFFB8
R_ROMB = 0x2000
TEXT_PTR = 0xD360

HANDLER_EXPECTED = bytes.fromhex(
    "e1f0b8f52a5f2a572ae0b8ea0020e56b62cd401be1f1e0b8ea0020c3551b"
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
    loaded_bank: claripy.ast.BV
    romb: claripy.ast.BV
    far_low: claripy.ast.BV
    far_high: claripy.ast.BV
    far_bank: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["h"] = claripy.BVV(TEXT_PTR >> 8, 8)
    values["l"] = claripy.BVV(TEXT_PTR & 0xFF, 8)
    values["loaded_bank"] = claripy.BVS(f"{prefix}_loaded_bank", 8)
    values["romb"] = claripy.BVS(f"{prefix}_romb", 8)
    values["far_low"] = claripy.BVS(f"{prefix}_far_low", 8)
    values["far_high"] = claripy.BVS(f"{prefix}_far_high", 8)
    values["far_bank"] = claripy.BVS(f"{prefix}_far_bank", 8)
    return values


def _setup(
    state: angr.SimState,
    values: dict[str, claripy.ast.BV],
    native: bool,
) -> None:
    base = NATIVE_MEMORY if native else 0
    state.memory.store(base + H_LOADED_ROM_BANK, values["loaded_bank"])
    state.memory.store(base + R_ROMB, values["romb"])
    state.memory.store(base + TEXT_PTR, values["far_low"])
    state.memory.store(base + TEXT_PTR + 1, values["far_high"])
    state.memory.store(base + TEXT_PTR + 2, values["far_bank"])


def _endpoint(state: angr.SimState, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    registers = native_registers(state, NATIVE_STATE) if native else assembly_registers(state)
    return Endpoint(
        **registers,
        loaded_bank=state.memory.load(base + H_LOADED_ROM_BANK, 1),
        romb=state.memory.load(base + R_ROMB, 1),
        far_low=state.memory.load(base + TEXT_PTR, 1),
        far_high=state.memory.load(base + TEXT_PTR + 1, 1),
        far_bank=state.memory.load(base + TEXT_PTR + 2, 1),
        constraints=tuple(state.solver.constraints),
    )


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


class CopyRegister(angr.SimProcedure):
    def __init__(self, destination: str, source: str, next_address: int) -> None:
        super().__init__()
        self.destination = destination
        self.source = source
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        setattr(
            self.state.regs,
            self.destination,
            getattr(self.state.regs, self.source),
        )
        self.jump(self.next_address)


class ProcessorBoundary(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.jump(self.next_address)


class Jump(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__()
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.jump(self.target)


class NativeProcessorBoundary(angr.SimProcedure):
    """No-op return for the independently proved processor transition."""

    def run(self) -> None:  # type: ignore[override]
        return None


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    handler = symbol_location(SYMBOLS, "TextCommand_FAR")
    assert handler.bank == 0
    assert handler.address == 0x1CA3
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
    project.hook(base + 0x00, PopPair("h", "l", base + 0x01), length=1)
    project.hook(base + 0x01, Sm83LoadAHighImmediate(0xB8, base + 0x03), length=2)
    project.hook(base + 0x03, PushPair("a", "f", base + 0x04), length=1)
    project.hook(base + 0x04, Sm83LoadAAtHlIncrement(base + 0x05), length=1)
    project.hook(base + 0x05, CopyRegister("e", "a", base + 0x06), length=1)
    project.hook(base + 0x06, Sm83LoadAAtHlIncrement(base + 0x07), length=1)
    project.hook(base + 0x07, CopyRegister("d", "a", base + 0x08), length=1)
    project.hook(base + 0x08, Sm83LoadAAtHlIncrement(base + 0x09), length=1)
    project.hook(base + 0x09, Sm83StoreAHighImmediate(0xB8, base + 0x0B), length=2)
    project.hook(base + 0x0B, Sm83StoreAImmediate(R_ROMB, base + 0x0E), length=3)
    project.hook(base + 0x0E, PushPair("h", "l", base + 0x0F), length=1)
    project.hook(base + 0x0F, CopyRegister("l", "e", base + 0x10), length=1)
    project.hook(base + 0x10, CopyRegister("h", "d", base + 0x11), length=1)
    project.hook(base + 0x11, ProcessorBoundary(base + 0x14), length=3)
    project.hook(base + 0x14, PopPair("h", "l", base + 0x15), length=1)
    project.hook(base + 0x15, PopPair("a", "f", base + 0x16), length=1)
    project.hook(base + 0x16, Sm83StoreAHighImmediate(0xB8, base + 0x18), length=2)
    project.hook(base + 0x18, Sm83StoreAImmediate(R_ROMB, base + 0x1B), length=3)
    project.hook(base + 0x1B, Jump(SENTINEL), length=3)

    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _setup(state, values, native=False)
    state.regs.sp = STACK - 2
    state.memory.store(STACK - 2, claripy.BVV(TEXT_PTR & 0xFF, 8))
    state.memory.store(STACK - 1, claripy.BVV(TEXT_PTR >> 8, 8))
    manager = project.factory.simulation_manager(state)
    manager.explore(find=SENTINEL, num_find=1)
    assert not manager.errored, manager.errored
    assert len(manager.found) == 1, len(manager.found)
    return [_endpoint(final, native=False) for final in manager.found]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_text_command_far")
    processor = project.loader.find_symbol("port_text_command_processor")
    assert function is not None and processor is not None
    project.hook(processor.rebased_addr, NativeProcessorBoundary())

    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, values, native=True)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored, manager.errored
    assert len(manager.deadended) == 1, len(manager.deadended)
    return [_endpoint(final, native=True) for final in manager.deadended]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(
    not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`"
)
def test_text_command_far_pathwise_equivalence() -> None:
    values = _inputs("text_command_far")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (
            *REGISTERS,
            "loaded_bank",
            "romb",
            "far_low",
            "far_high",
            "far_bank",
        ),
    )
