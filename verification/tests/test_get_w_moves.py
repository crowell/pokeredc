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

# GetwMoves: 21 dcd0 4f 06 00 09 7e c9
#   LD HL, 0xd0dc / LD C, A / LD B, 0 / ADD HL, BC / LD A, (HL) / RET
TABLE_BASE = 0xD0DC
TABLE_SIZE = 256


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
    """The `ret` tail: an explicit boundary sentinel."""

    def run(self) -> None:  # type: ignore[override]
        self.jump(DONE)


# Shared so the asm and native sides reference identical symbolic table
# bytes; the proof then checks only that the indexing matches.
_TABLE = [claripy.BVS(f"getw_tbl_{i}", 8) for i in range(TABLE_SIZE)]


def _table() -> list[claripy.ast.BV]:
    return _TABLE
def _store_table(state: angr.SimState, table: list[claripy.ast.BV]) -> None:
    for i, byte in enumerate(table):
        state.memory.store(TABLE_BASE + i, byte)


def _inputs(tag: str) -> dict:
    return symbolic_registers(tag)


def _assembly(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "GetwMoves")
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
    # `ret` (0xc9) is an explicit boundary.
    project.hook(base + 0x08, Boundary(), length=1)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, inputs)
    _store_table(state, _table())
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
    function = project.loader.find_symbol("port_get_w_moves")
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, claripy.BVV(0, 64)
    )
    store_native_registers(state, NATIVE_STATE, inputs)
    _store_table(state, _table())
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
def test_get_w_moves_symbolic_equivalence() -> None:
    i = _inputs("gwm")
    assert_pathwise_equivalent(
        _assembly(i),
        _native(i),
        ("a", "f", "b", "c", "d", "e", "h", "l"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_get_w_moves_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "GetwMoves")
    # LD HL,0xd0dc / LD C,A / LD B,0 / ADD HL,BC / LD A,(HL) / RET
    assert linked_bytes(ROM, location, 9) == bytes.fromhex("21dcd04f0600097ec9")
