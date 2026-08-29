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
)
from verification.harness.rom import linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import (
    Sm83LoadAFromImmediate,
    Sm83LoadAHighImmediate,
    Sm83StoreAHighImmediate,
    Sm83StoreAImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0x7FFF
H_LOADED_ROM_BANK = 0xFFB8
R_ROMB = 0x2000
H_TEXT_BOX_ID = 0xD125
EXPECTED = bytes.fromhex("f0b8f53e01e0b8ea0020cdea72c178e0b8ea0020c9")


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
    constraints: tuple[claripy.ast.Bool, ...]


class SaveAF(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.sp = self.state.regs.sp - 2
        self.state.memory.store(
            self.state.regs.sp,
            claripy.Concat(self.state.regs.a, self.state.regs.f),
            endness="Iend_LE",
        )
        self.jump(self.continuation)


class PopBC(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        value = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.b = value[15:8]
        self.state.regs.c = value[7:0]
        self.state.regs.sp = self.state.regs.sp + 2
        self.jump(self.continuation)


class DisplayBoundary(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        if self.state.arch.name.startswith("AMD64"):
            return
        self.jump(self.continuation)


def _endpoint(state: angr.SimState, *, native: bool, base: int) -> Endpoint:
    return Endpoint(
        **(native_registers(state, NATIVE_STATE) if native else assembly_registers(state)),
        loaded_bank=state.memory.load(base + H_LOADED_ROM_BANK, 1),
        romb=state.memory.load(base + R_ROMB, 1),
        constraints=tuple(state.solver.constraints),
    )


def _values() -> dict[str, claripy.ast.BV]:
    return {
        "a": claripy.BVV(0x23, 8), "f": claripy.BVV(0, 8),
        "b": claripy.BVV(0x45, 8), "c": claripy.BVV(0x67, 8),
        "d": claripy.BVV(0x89, 8), "e": claripy.BVV(0xAB, 8),
        "h": claripy.BVV(0xCD, 8), "l": claripy.BVV(0xEF, 8),
    }


def _setup(state: angr.SimState, base: int) -> None:
    state.memory.store(base + H_LOADED_ROM_BANK, claripy.BVV(7, 8))
    state.memory.store(base + R_ROMB, claripy.BVV(5, 8))
    state.memory.store(base + H_TEXT_BOX_ID, claripy.BVV(0xFF, 8))


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "DisplayTextBoxID")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    base = location.address
    project.hook(base, Sm83LoadAHighImmediate(H_LOADED_ROM_BANK, base + 2), length=2)
    project.hook(base + 2, SaveAF(base + 3), length=1)
    project.hook(base + 3, Sm83LoadAFromImmediate(base + 4, base + 5), length=2)
    project.hook(base + 5, Sm83StoreAHighImmediate(H_LOADED_ROM_BANK, base + 7), length=2)
    project.hook(base + 7, Sm83StoreAImmediate(R_ROMB, base + 0x0A), length=3)
    project.hook(base + 0x0A, DisplayBoundary(base + 0x0D), length=3)
    project.hook(base + 0x0D, PopBC(base + 0x0E), length=1)
    project.hook(base + 0x0F, Sm83StoreAHighImmediate(H_LOADED_ROM_BANK, base + 0x11), length=2)
    project.hook(base + 0x11, Sm83StoreAImmediate(R_ROMB, base + 0x14), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _setup(state, 0)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=lambda candidate: candidate.addr == RETURN)
    assert not manager.errored and manager.found
    return [_endpoint(end, native=False, base=0) for end in manager.found]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_display_text_box_id_wrapper")
    display = project.loader.find_symbol("port_display_text_box_id")
    assert function is not None and display is not None
    project.hook(display.rebased_addr, DisplayBoundary(0))
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, claripy.BVV(7, 8))
    state.memory.store(NATIVE_STATE + 9, claripy.BVV(5, 8))
    _setup(state, NATIVE_MEMORY)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and manager.deadended
    return [_endpoint(end, native=True, base=NATIVE_MEMORY) for end in manager.deadended]


@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_display_text_box_id_wrapper_pathwise_equivalence() -> None:
    assert_pathwise_equivalent(
        _assembly(_values()), _native(_values()),
        (*REGISTERS, "loaded_bank", "romb"),
    )
