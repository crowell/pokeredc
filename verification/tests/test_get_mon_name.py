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
from verification.harness.sm83_shims import (
    Sm83LoadAHighImmediate,
    Sm83StoreAHighImmediate,
    Sm83StoreAImmediate,
    Sm83LoadAImmediate,
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

W_NAMED_OBJECT_INDEX = 0xD11E
MONSTER_NAMES = 0x421E
NAME_LENGTH = 11
W_NAME_BUFFER = 0xCD6D
HRAM_BANK = 0xB8  # hLoadedROMBank (a8)
ROMB = 0x2000
NAMED_OBJECT_INDEX = 1  # concrete 1-based id -> index 0


@lru_cache(maxsize=None)
def _pp_inputs() -> tuple[claripy.ast.BV, ...]:
    # Symbolic species-name bytes shared between the asm and native endpoints.
    return tuple(claripy.BVS(f"gmn_name{i}", 8) for i in range(NAME_LENGTH - 1))


def _store_inputs(state: angr.SimState) -> None:
    for i, bv in enumerate(_pp_inputs()):
        state.memory.store(MONSTER_NAMES + i, bv)
    state.memory.store(W_NAMED_OBJECT_INDEX, claripy.BVV(NAMED_OBJECT_INDEX, 8))
    state.memory.store(0xFF00 | HRAM_BANK, claripy.BVV(0, 8))  # scratch bank byte


@dataclass(frozen=True)
class Endpoint:
    m_name0: claripy.ast.BV
    m_name1: claripy.ast.BV
    m_name2: claripy.ast.BV
    m_name3: claripy.ast.BV
    m_name4: claripy.ast.BV
    m_name5: claripy.ast.BV
    m_name6: claripy.ast.BV
    m_name7: claripy.ast.BV
    m_name8: claripy.ast.BV
    m_name9: claripy.ast.BV
    m_terminator: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _load(end: angr.SimState) -> Endpoint:
    return Endpoint(
        m_name0=end.memory.load(W_NAME_BUFFER + 0, 1),
        m_name1=end.memory.load(W_NAME_BUFFER + 1, 1),
        m_name2=end.memory.load(W_NAME_BUFFER + 2, 1),
        m_name3=end.memory.load(W_NAME_BUFFER + 3, 1),
        m_name4=end.memory.load(W_NAME_BUFFER + 4, 1),
        m_name5=end.memory.load(W_NAME_BUFFER + 5, 1),
        m_name6=end.memory.load(W_NAME_BUFFER + 6, 1),
        m_name7=end.memory.load(W_NAME_BUFFER + 7, 1),
        m_name8=end.memory.load(W_NAME_BUFFER + 8, 1),
        m_name9=end.memory.load(W_NAME_BUFFER + 9, 1),
        m_terminator=end.memory.load(W_NAME_BUFFER + 10, 1),
        constraints=tuple(end.solver.constraints),
    )


def _assembly_endpoint(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "GetMonName")
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
    # ldh a, [a8] (0xF0) and ldh [a8], a (0xE0) are shimmed (absent from z80).
    project.hook(base + 0x01, Sm83LoadAHighImmediate(HRAM_BANK, base + 0x03), length=2)
    project.hook(base + 0x06, Sm83StoreAHighImmediate(HRAM_BANK, base + 0x08), length=2)
    # ld [a16], a (0xEA) store is shimmed (absent from the z80 decoder).
    project.hook(base + 0x08, Sm83StoreAImmediate(ROMB, base + 0x0B), length=3)
    # ld a, [a16] (0xFA) load is shimmed (absent from the z80 decoder).
    project.hook(base + 0x0B, Sm83LoadAImmediate(W_NAMED_OBJECT_INDEX, base + 0x0E), length=3)
    # call AddNTimes is modeled as hl = hl + bc*a.
    project.hook(base + 0x16, AddNTimesInline(base + 0x19), length=3)
    # call CopyData is modeled as a BC-byte copy from [HL] to [DE].
    project.hook(base + 0x20, CopyDataSim(base + 0x23), length=3)
    project.hook(base + 0x2A, Sm83StoreAHighImmediate(HRAM_BANK, base + 0x2C), length=2)
    project.hook(base + 0x2C, Sm83StoreAImmediate(ROMB, base + 0x2F), length=3)
    state = project.factory.blank_state(addr=base)
    _store_inputs(state)
    set_assembly_registers(state, inputs)
    state.regs.sp = claripy.BVV(0xE000, 16)
    state.memory.store(0xE000, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    return [_load(end) for end in returned]


def _native_endpoint(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_get_mon_name")
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
def test_get_mon_name_symbolic_equivalence() -> None:
    inputs = symbolic_registers("gmn")
    assembly = _assembly_endpoint(inputs)
    native = _native_endpoint(inputs)
    assert_pathwise_equivalent(
        assembly,
        native,
        (
            "m_name0",
            "m_name1",
            "m_name2",
            "m_name3",
            "m_name4",
            "m_name5",
            "m_name6",
            "m_name7",
            "m_name8",
            "m_name9",
            "m_terminator",
        ),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_get_mon_name_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "GetMonName")
    expected = bytes.fromhex(
        "e5f0b8f53e07e0b8ea0020fa1ed13d211e420e0a0600cd873a116dcdd5010a00cdb5002177cd3650d1f1e0b8ea0020e1"
    )
    assert linked_bytes(ROM, location, len(expected)) == expected
