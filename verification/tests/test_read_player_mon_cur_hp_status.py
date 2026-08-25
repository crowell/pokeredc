from __future__ import annotations

from dataclasses import dataclass
from functools import cache
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
from verification.harness.rom import (
    collect_returns,
    linked_bytes,
    rom_window,
    symbol_location,
)
from verification.harness.sm83_shims import Sm83LoadAAtHlIncrement, Sm83OrRegister


ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xE000
RETURN = 0xFFFF
W_PLAYER_MON_NUMBER = 0xCC2F
W_BATTLE_MON_HP = 0xD015
W_PARTY_MON_1_HP = 0xD16C
PARTY_STRUCT_LENGTH = 0x2C
PARTY_COUNT = 6
COPY_LENGTH = 4
DESTINATION_SIZE = PARTY_STRUCT_LENGTH * (PARTY_COUNT - 1) + COPY_LENGTH
EXPECTED = bytes.fromhex("fa2fcc216cd1012c00cd873a545d2115d0010400c3b500")


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
    memory: claripy.ast.BV
    add_call: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _register_bytes(state: angr.SimState) -> claripy.ast.BV:
    registers = assembly_registers(state)
    return claripy.Concat(*(registers[name] for name in REGISTERS))


def _add_transition(
    count: claripy.ast.BV,
    hl: claripy.ast.BV,
) -> tuple[claripy.ast.BV, claripy.ast.BV]:
    result = hl + claripy.ZeroExt(8, count) * PARTY_STRUCT_LENGTH
    flags = claripy.If(
        count == 0,
        claripy.BVV(0xA0, 8),
        claripy.BVV(0xC0, 8),
    )
    return result, flags


class LoadPlayerIndex(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(W_PLAYER_MON_NUMBER, 1)
        self.jump(self._continuation)


class AssemblyAddNTimes(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["add_call"] = _register_bytes(self.state)
        result, flags = _add_transition(self.state.regs.a, self.state.regs.hl)
        self.state.regs.a = 0
        self.state.regs.f = claripy.If(
            flags == 0xA0,
            claripy.BVV(0x50, 8),
            claripy.BVV(0x42, 8),
        )
        self.state.regs.hl = result
        self.jump(self._continuation)


class NativeAddNTimes(angr.SimProcedure):
    def run(self, address: claripy.ast.BV) -> None:  # type: ignore[override]
        self.state.globals["add_call"] = self.state.memory.load(address, 8)
        count = self.state.memory.load(address, 1)
        hl = self.state.memory.load(address + 6, 2)
        result, flags = _add_transition(count, hl)
        self.state.memory.store(address, claripy.BVV(0, 8))
        self.state.memory.store(address + 1, flags)
        self.state.memory.store(address + 6, result)


class StoreAAtDE(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(self.state.regs.de, self.state.regs.a)
        self.jump(self._continuation)


class IncDE(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.de += 1
        self.jump(self._continuation)


class DecBC(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.bc -= 1
        self.jump(self._continuation)


def _inputs() -> dict[str, claripy.ast.BV]:
    values = symbolic_registers("read_player_mon")
    values["player_index"] = claripy.BVS("read_player_mon_index", 8)
    for offset in range(COPY_LENGTH):
        values[f"source_{offset}"] = claripy.BVS(
            f"read_player_mon_source_{offset}", 8
        )
    for offset in range(DESTINATION_SIZE):
        values[f"destination_{offset}"] = claripy.BVS(
            f"read_player_mon_destination_{offset}", 8
        )
    return values


def _setup(
    state: angr.SimState, values: dict[str, claripy.ast.BV], native: bool
) -> None:
    base = NATIVE_MEMORY if native else 0
    state.memory.store(base + W_PLAYER_MON_NUMBER, values["player_index"])
    for offset in range(COPY_LENGTH):
        state.memory.store(
            base + W_BATTLE_MON_HP + offset, values[f"source_{offset}"]
        )
    for offset in range(DESTINATION_SIZE):
        state.memory.store(
            base + W_PARTY_MON_1_HP + offset,
            values[f"destination_{offset}"],
        )
    state.globals["add_call"] = claripy.BVV(0, 64)
    state.add_constraints(values["player_index"] < PARTY_COUNT)


def _endpoint(state: angr.SimState, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    registers = (
        native_registers(state, NATIVE_STATE)
        if native
        else assembly_registers(state)
    )
    return Endpoint(
        **registers,
        memory=claripy.Concat(
            state.memory.load(base + W_PLAYER_MON_NUMBER, 1),
            state.memory.load(base + W_BATTLE_MON_HP, COPY_LENGTH),
            state.memory.load(
                base + W_PARTY_MON_1_HP, DESTINATION_SIZE
            ),
        ),
        add_call=state.globals["add_call"],
        constraints=tuple(state.solver.constraints),
    )


@cache
def _assembly_project() -> tuple[angr.Project, int]:
    location = symbol_location(SYMS, "ReadPlayerMonCurHPAndStatus")
    copy = symbol_location(SYMS, "CopyData")
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
    project.hook(base, LoadPlayerIndex(base + 3), length=3)
    project.hook(base + 9, AssemblyAddNTimes(base + 12), length=3)
    project.hook(
        copy.address,
        Sm83LoadAAtHlIncrement(copy.address + 1),
        length=1,
    )
    project.hook(copy.address + 1, StoreAAtDE(copy.address + 2), length=1)
    project.hook(copy.address + 2, IncDE(copy.address + 3), length=1)
    project.hook(copy.address + 3, DecBC(copy.address + 4), length=1)
    project.hook(
        copy.address + 5,
        Sm83OrRegister("b", copy.address + 6),
        length=1,
    )
    return project, base


@cache
def _native_project() -> tuple[angr.Project, int]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_read_player_mon_cur_hp_status")
    add = project.loader.find_symbol("port_add_n_times")
    assert function is not None and add is not None
    project.hook(add.rebased_addr, NativeAddNTimes())
    return project, function.rebased_addr


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, base = _assembly_project()
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _setup(state, values, False)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    return [_endpoint(end, False) for end in collect_returns(project, state, RETURN)]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, function = _native_project()
    state = project.factory.call_state(function, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, values, True)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [_endpoint(manager.deadended[0], True)]


@pytest.mark.skipif(
    not ELF.exists() or not ROM.exists() or not SYMS.exists(), reason="build"
)
def test_read_player_mon_cur_hp_status_pathwise_equivalence() -> None:
    location = symbol_location(SYMS, "ReadPlayerMonCurHPAndStatus")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    values = _inputs()
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "memory", "add_call"),
    )
