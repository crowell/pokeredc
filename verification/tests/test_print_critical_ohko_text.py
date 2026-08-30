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
    Sm83DecRegister,
    Sm83LoadAAtHlIncrement,
    Sm83LoadAImmediate,
    Sm83StoreAImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = NATIVE_STATE + 0x10000
DONE = 0xEFFF
STACK = 0xD000
CRITICAL = 0xD05E
TEXT_BOX_ID = 0xD125
OBSERVATIONS = NATIVE_MEMORY + 0x1000
EXPECTED = bytes.fromhex(
    "fa5ed0a728133d87217a5c06004f092a666fcd493caf"
    "ea5ed00e14c33937"
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
    delay_iterations: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class AndA(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x50, 8),
            claripy.BVV(0x10, 8),
        )
        self.jump(self.state.addr + 1)


class LoadHAtHL(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = self.state.memory.load(self.state.regs.hl, 1)
        self.jump(self.continuation)


class PrintCallBoundary(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(TEXT_BOX_ID, claripy.BVV(1, 8))
        self.state.regs.b = claripy.BVV(0xC4, 8)
        self.state.regs.c = claripy.BVV(0xB9, 8)
        self.jump(self.continuation)


class DelayFrameBoundary(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x50, 8)
        count = self.state.globals.get("delay_iterations", claripy.BVV(0, 8))
        self.state.globals["delay_iterations"] = count + 1
        self.jump(self.continuation)


class DelayReturnBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.successors.add_successor(
            self.state.copy(), DONE, claripy.BoolV(True), "Ijk_Boring"
        )


def _endpoint(state: angr.SimState, *, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    registers = native_registers(state, NATIVE_STATE) if native else assembly_registers(state)
    return Endpoint(
        **registers,
        critical=state.memory.load(base + CRITICAL, 1),
        text_box_id=state.memory.load(base + TEXT_BOX_ID, 1),
        delay_iterations=(
            state.memory.load(NATIVE_STATE + 9, 1)
            if native else state.globals.get("delay_iterations", claripy.BVV(0, 8))
        ),
        constraints=tuple(state.solver.constraints),
    )


def _assembly(values: dict[str, claripy.ast.BV], critical: int) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "PrintCriticalOHKOText")
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
    project.hook(base, Sm83LoadAImmediate(CRITICAL, base + 3), length=3)
    project.hook(base + 3, AndA(), length=1)
    project.hook(base + 14, Sm83AddHlRegisterPair("bc", base + 15), length=1)
    project.hook(base + 15, Sm83LoadAAtHlIncrement(base + 16), length=1)
    project.hook(base + 16, LoadHAtHL(base + 17), length=1)
    project.hook(base + 18, PrintCallBoundary(base + 21), length=3)
    project.hook(base + 22, Sm83StoreAImmediate(CRITICAL, base + 25), length=3)
    delay = symbol_location(SYMBOLS, "DelayFrames")
    delay_frame = symbol_location(SYMBOLS, "DelayFrame")
    project.hook(delay_frame.address, DelayFrameBoundary(delay.address + 3), length=1)
    project.hook(delay.address + 3, Sm83DecRegister("c", delay.address + 4), length=1)
    project.hook(delay.address + 6, DelayReturnBoundary(), length=1)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.regs.sp = STACK
    state.memory.store(CRITICAL, claripy.BVV(critical, 8))
    state.memory.store(TEXT_BOX_ID, claripy.BVV(0, 8))
    state.memory.store(STACK, claripy.BVV(DONE, 16), endness="Iend_LE")
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored
    return [_endpoint(end, native=False) for end in manager.found]


def _native(values: dict[str, claripy.ast.BV], critical: int) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_print_critical_ohko_text")
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY, OBSERVATIONS
    )
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, claripy.BVV(critical, 8))
    state.memory.store(NATIVE_STATE + 9, claripy.BVV(0, 8))
    state.memory.store(NATIVE_MEMORY + CRITICAL, claripy.BVV(critical, 8))
    state.memory.store(NATIVE_MEMORY + TEXT_BOX_ID, claripy.BVV(0, 8))
    state.memory.store(OBSERVATIONS, claripy.BVV(0, 8))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [_endpoint(end, native=True) for end in manager.deadended]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
@pytest.mark.parametrize("critical", [0, 1, 2])
def test_print_critical_ohko_text_entry_pathwise_equivalence(critical: int) -> None:
    values = symbolic_registers("print_critical_ohko_text")
    values["critical_hit_or_ohko"] = claripy.BVV(critical, 8)
    assert_pathwise_equivalent(
        _assembly(values, critical),
        _native(values, critical),
        (*REGISTERS, "critical", "text_box_id", "delay_iterations"),
    )
