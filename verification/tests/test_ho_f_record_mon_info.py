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
    assembly_registers,
    native_registers,
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
    Sm83LoadAImmediate,
    Sm83StoreAAtHlIncrement,
)


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification" / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
GB_STACK = 0xD000
GB_RETURN = 0xFFFF
NATIVE_STATE = 0x100000
W_HALL_OF_FAME = 0xCC5B
W_HOF_PARTY_MON_INDEX = 0xCD3E
W_HOF_MON_SPECIES = 0xCD3D
W_HOF_MON_LEVEL = 0xCD3F
W_NAME_BUFFER = 0xCD6D
HOF_MON = 0x10
NAME_LENGTH = 11
RECORD_LEN = 2 + NAME_LENGTH  # species, level, name


class AddNTimesInline(angr.SimProcedure):
    """Model ``call AddNTimes``: hl = hl + bc * a (a = 0 leaves hl unchanged),
    a = 0, b/c preserved. Flags are transient and excluded from the observables."""

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
    """Inline ``jp CopyData``: copy BC bytes from [HL] to [DE], then return."""

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
        state.regs.f = claripy.BVV(0x40, 8)
        self.jump(self._next_address)


@lru_cache(maxsize=None)
def _record_inputs() -> tuple[
    claripy.ast.BV,
    claripy.ast.BV,
    claripy.ast.BV,
    tuple[claripy.ast.BV, ...],
]:
    """Symbolic record inputs shared between the assembly and native endpoints
    so path constraints refer to the same claripy variables."""
    index = claripy.BVS("hof_index", 8)
    species = claripy.BVS("hof_species", 8)
    level = claripy.BVS("hof_level", 8)
    name = tuple(claripy.BVS(f"hof_name{i}", 8) for i in range(NAME_LENGTH))
    return index, species, level, name


def _store_record_inputs(state: angr.SimState) -> None:
    index, species, level, name = _record_inputs()
    state.memory.store(W_HOF_PARTY_MON_INDEX, index)
    state.memory.store(W_HOF_MON_SPECIES, species)
    state.memory.store(W_HOF_MON_LEVEL, level)
    for i in range(NAME_LENGTH):
        state.memory.store(W_NAME_BUFFER + i, name[i])


@dataclass(frozen=True)
class Endpoint:
    m_record: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _record_base() -> claripy.ast.BV:
    index, _, _, _ = _record_inputs()
    idx = claripy.ZeroExt(8, index)
    return (claripy.BVV(W_HALL_OF_FAME, 16) + claripy.BVV(HOF_MON, 16) * idx) & 0xFFFF


def _assembly_endpoint(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "HoFRecordMonInfo")
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
    state = project.factory.blank_state(addr=location.address)
    base = location.address
    project.hook(
        base + 0x06,
        Sm83LoadAImmediate(W_HOF_PARTY_MON_INDEX, base + 0x09),
        length=3,
    )
    project.hook(base + 0x09, AddNTimesInline(base + 0x0C), length=3)
    project.hook(
        base + 0x0C,
        Sm83LoadAImmediate(W_HOF_MON_SPECIES, base + 0x0F),
        length=3,
    )
    project.hook(base + 0x0F, Sm83StoreAAtHlIncrement(base + 0x10), length=1)
    project.hook(
        base + 0x10,
        Sm83LoadAImmediate(W_HOF_MON_LEVEL, base + 0x13),
        length=3,
    )
    project.hook(base + 0x13, Sm83StoreAAtHlIncrement(base + 0x14), length=1)
    project.hook(base + 0x1C, CopyDataSim(GB_RETURN), length=3)
    _store_record_inputs(state)
    set_assembly_registers(state, inputs)
    state.regs.sp = claripy.BVV(GB_STACK, 16)
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    base_expr = _record_base()
    return [
        Endpoint(
            m_record=end.memory.load(base_expr, RECORD_LEN),
            constraints=tuple(end.solver.constraints),
        )
        for end in returned
    ]


def _native_endpoint(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(
        "port_ho_f_record_mon_info"
    )
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, claripy.BVV(0, 64)
    )
    store_native_registers(state, NATIVE_STATE, inputs)
    _store_record_inputs(state)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    base_expr = _record_base()
    return [
        Endpoint(
            m_record=end.memory.load(base_expr, RECORD_LEN),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_ho_f_record_mon_info_symbolic_equivalence() -> None:
    inputs = symbolic_registers("hofr")
    assembly = _assembly_endpoint(inputs)
    native = _native_endpoint(inputs)
    assert_pathwise_equivalent(assembly, native, ("m_record",))


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_ho_f_record_mon_info_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "HoFRecordMonInfo")
    expected = bytes.fromhex("215bcc011000fa3ecdcd873afa3dcd22fa3fcd225d54216dcd010b00c3b500")
    assert linked_bytes(ROM, location, len(expected)) == expected
