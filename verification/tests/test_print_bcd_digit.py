from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
    assembly_registers,
    native_registers,
    set_assembly_registers,
    store_native_registers,
    symbolic_registers,
)
from verification.harness.rom import linked_bytes, rom_window, symbol_location

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
DONE = 0xEFFF

# PrintBCDDigit: e6 0f a7 28 15
#   AND 0xf / AND A / JR Z, 0x161e


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


class Boundary(angr.SimProcedure):
    """The `JR Z, 0x161e` tail: an explicit boundary sentinel."""

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.jump(DONE)


def _inputs(tag: str) -> dict:
    return symbolic_registers(tag)


def _assembly(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "PrintBCDDigit")
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
    # `JR Z, 0x161e` is an explicit boundary.
    project.hook(base + 0x03, Boundary(), length=2)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, inputs)
    state.regs.sp = 0xD000
    state.memory.store(0xD000, claripy.BVV(0xFFFF, 16), endness="Iend_LE")
    m = project.factory.simulation_manager(state)
    m.explore(find=DONE, num_find=1)
    assert len(m.found) == 1
    end = m.found[0]
    return [
        Endpoint(
            **assembly_registers(end),
            constraints=tuple(end.solver.constraints),
        )
    ]


def _native(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_print_bcd_digit")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    end = manager.deadended[0]
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            constraints=tuple(end.solver.constraints),
        )
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_print_bcd_digit_symbolic_equivalence() -> None:
    i = _inputs("pbd")
    assert_pathwise_equivalent(
        _assembly(i),
        _native(i),
        ("a", "f", "b", "c", "d", "e", "h", "l"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_print_bcd_digit_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "PrintBCDDigit")
    # AND 0xf / AND A / JR Z, 0x161e
    assert linked_bytes(ROM, location, 5) == bytes.fromhex("e60fa72815")
