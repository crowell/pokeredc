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
from verification.harness.rom import collect_returns, linked_bytes, rom_window, symbol_location

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
RETURN = 0xEFFF
STACK = 0xD000


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
    constraints: tuple[claripy.ast.Bool, ...]


class TailBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.sp = STACK + 2
        self.jump(RETURN)


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "PrintText_NoCreatingTextBox")
    assert linked_bytes(ROM, location, 6) == bytes.fromhex("01b9c4c3401b")
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
    project.hook(location.address + 3, TailBoundary(), length=3)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    endpoints = collect_returns(project, state, RETURN)
    assert len(endpoints) == 1
    return [Endpoint(**assembly_registers(endpoints[0]),
                     constraints=tuple(endpoints[0].solver.constraints))]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_print_text_no_creating_text_box")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE,
                                       NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [Endpoint(**native_registers(manager.deadended[0], NATIVE_STATE),
                     constraints=tuple(manager.deadended[0].solver.constraints))]


@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_print_text_no_creating_text_box_pathwise_equivalence() -> None:
    values = symbolic_registers("print_text_no_creating_text_box")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        REGISTERS,
    )
