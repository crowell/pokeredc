from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
    set_assembly_registers,
    store_native_registers,
    symbolic_registers,
)
from verification.harness.rom import (
    collect_returns,
    linked_bytes,
    rom_window,
    symbol_location,
)


class AddNTimesInline(angr.SimProcedure):
    """Model ``call AddNTimes``: hl = hl + bc * a (a = 0 leaves hl unchanged),
    a = 0, b/c preserved."""

    def __init__(self, next_address: int, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        state = self.state
        a = state.regs.a
        bc = claripy.ZeroExt(8, state.regs.c) | (claripy.ZeroExt(8, state.regs.b) << 8)
        hl = claripy.ZeroExt(8, state.regs.l) | (claripy.ZeroExt(8, state.regs.h) << 8)
        new_hl = (hl + bc * claripy.ZeroExt(8, a)) & 0xFFFF
        state.regs.a = claripy.BVV(0, 8)
        state.regs.h = claripy.Extract(15, 8, new_hl)
        state.regs.l = claripy.Extract(7, 0, new_hl)
        self.jump(self._next_address)


class CopyDataSim(angr.SimProcedure):
    """Inline ``call CopyData``: copy BC bytes from [HL] to [DE], then return."""

    def __init__(self, next_address: int, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        state = self.state
        h = int(state.solver.eval(state.regs.h))
        l = int(state.solver.eval(state.regs.l))
        d = int(state.solver.eval(state.regs.d))
        e = int(state.solver.eval(state.regs.e))
        b = int(state.solver.eval(state.regs.b))
        c = int(state.solver.eval(state.regs.c))
        hl = (h << 8) | l
        de = (d << 8) | e
        bc = (b << 8) | c
        for _ in range(bc):
            byte = state.memory.load(hl, 1)
            state.memory.store(de, byte)
            hl = (hl + 1) & 0xFFFF
            de = (de + 1) & 0xFFFF
        state.regs.h = claripy.BVV((hl >> 8) & 0xFF, 8)
        state.regs.l = claripy.BVV(hl & 0xFF, 8)
        state.regs.d = claripy.BVV((de >> 8) & 0xFF, 8)
        state.regs.e = claripy.BVV(de & 0xFF, 8)
        state.regs.b = claripy.BVV(0, 8)
        state.regs.c = claripy.BVV(0, 8)
        state.regs.a = claripy.BVV(0, 8)
        self.jump(self._next_address)


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification" / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
GB_RETURN = 0xFFFF
NATIVE_STATE = 0x100000

MOVES_ADDR = 0x4000
MOVE_LENGTH = 6
W_ENEMY_MOVE_NUM = 0xCFCC
READ_A = 1  # concrete 1-based move id -> index 0


@lru_cache(maxsize=None)
def _pp_inputs() -> tuple[claripy.ast.BV, ...]:
    # Symbolic move-data bytes shared between the asm and native endpoints so the
    # path comparator pairs the same initial values.
    return tuple(claripy.BVS(f"rm_move{i}", 8) for i in range(MOVE_LENGTH))


def _store_inputs(state: angr.SimState) -> None:
    for i, bv in enumerate(_pp_inputs()):
        state.memory.store(MOVES_ADDR + i, bv)


@dataclass(frozen=True)
class Endpoint:
    m_move0: claripy.ast.BV
    m_move1: claripy.ast.BV
    m_move2: claripy.ast.BV
    m_move3: claripy.ast.BV
    m_move4: claripy.ast.BV
    m_move5: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _load(end: angr.SimState) -> Endpoint:
    return Endpoint(
        m_move0=end.memory.load(W_ENEMY_MOVE_NUM + 0, 1),
        m_move1=end.memory.load(W_ENEMY_MOVE_NUM + 1, 1),
        m_move2=end.memory.load(W_ENEMY_MOVE_NUM + 2, 1),
        m_move3=end.memory.load(W_ENEMY_MOVE_NUM + 3, 1),
        m_move4=end.memory.load(W_ENEMY_MOVE_NUM + 4, 1),
        m_move5=end.memory.load(W_ENEMY_MOVE_NUM + 5, 1),
        constraints=tuple(end.solver.constraints),
    )


def _assembly_endpoint(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "ReadMove")
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
    base = location.address
    # call AddNTimes is modeled as hl = hl + bc*a.
    project.hook(base + 0x0A, AddNTimesInline(base + 0x0D), length=3)
    # call CopyData is modeled as a BC-byte copy from [HL] to [DE].
    project.hook(base + 0x10, CopyDataSim(base + 0x13), length=3)
    state = project.factory.blank_state(addr=base)
    _store_inputs(state)
    set_assembly_registers(state, inputs)
    state.regs.sp = claripy.BVV(0xE000, 16)
    state.memory.store(0xE000, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    return [_load(end) for end in returned]


def _native_endpoint(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_read_move")
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, claripy.BVV(0, 64)
    )
    store_native_registers(state, NATIVE_STATE, inputs)
    _store_inputs(state)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [_load(end) for end in manager.deadended]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_read_move_symbolic_equivalence() -> None:
    inputs = symbolic_registers("rm")
    inputs["a"] = claripy.BVV(READ_A, 8)  # concrete 1-based move id
    assembly = _assembly_endpoint(inputs)
    native = _native_endpoint(inputs)
    assert_pathwise_equivalent(
        assembly,
        native,
        (
            "m_move0",
            "m_move1",
            "m_move2",
            "m_move3",
            "m_move4",
            "m_move5",
        ),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_read_move_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "ReadMove")
    expected = bytes.fromhex(
        "e5d5c53d210040010600cd873a11cccfcdb500c1d1e1c9"
    )
    assert linked_bytes(ROM, location, len(expected)) == expected
