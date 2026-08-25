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
    sm83_flags_to_z80,
    symbol_location,
)
from verification.harness.sm83_shims import (
    Sm83LoadAHighImmediate,
    Sm83LoadAImmediate,
    Sm83StoreAImmediate,
    Sm83SubImmediate,
)


ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xE000
RETURN = 0xFFFF
W_WHOSE_TURN = 0xFFF3
W_PLAYER_MOVE_TYPE = 0xCFD5
W_ENEMY_MOVE_TYPE = 0xCFCF
W_ENEMY_MON_STATUS = 0xCFE9
W_BATTLE_MON_STATUS = 0xD018
W_ENEMY_MON_PARTY_POS = 0xCFE8
W_PLAYER_MON_NUMBER = 0xCC2F
W_ENEMY_MON_1_STATUS = 0xD8A8
W_PARTY_MON_1_STATUS = 0xD16F
W_TEXT_BOX_ID = 0xD125
PARTY_STRUCT_LENGTH = 0x2C
PARTY_COUNT = 6
ROSTER_REGION_SIZE = PARTY_STRUCT_LENGTH * (PARTY_COUNT - 1) + 1
EXPECTED = bytes.fromhex(
    "e620c8f0f3a7201cfad5cfd614c0eae9cf21a8d8fae8cf012c00cd873a"
    "af77212374181afacfcfd614c0ea18d0216fd1fa2fcc012c00cd873aaf77"
    "212374c3493c"
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
    memory: claripy.ast.BV
    add_call: claripy.ast.BV
    print_call: claripy.ast.BV
    trace: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _register_bytes(state: angr.SimState) -> claripy.ast.BV:
    registers = assembly_registers(state)
    return claripy.Concat(*(registers[name] for name in REGISTERS))


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        *(
            state.memory.load(base + address, 1)
            for address in (
                W_WHOSE_TURN,
                W_PLAYER_MOVE_TYPE,
                W_ENEMY_MOVE_TYPE,
                W_ENEMY_MON_STATUS,
                W_BATTLE_MON_STATUS,
                W_ENEMY_MON_PARTY_POS,
                W_PLAYER_MON_NUMBER,
                W_TEXT_BOX_ID,
            )
        ),
        state.memory.load(base + W_PARTY_MON_1_STATUS, ROSTER_REGION_SIZE),
        state.memory.load(base + W_ENEMY_MON_1_STATUS, ROSTER_REGION_SIZE),
    )


class AndA(angr.SimProcedure):
    def __init__(self, mask: int, continuation: int) -> None:
        super().__init__()
        self._mask = mask
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a &= self._mask
        self.state.regs.f = claripy.BVV(0x10, 8) | claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x40, 8),
            claripy.BVV(0, 8),
        )
        self.jump(self._continuation)


class XorA(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = 0
        self.state.regs.f = 0x40
        self.jump(self._continuation)


class StoreAAtHL(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(self.state.regs.hl, self.state.regs.a)
        self.jump(self._continuation)


def _add_transition(
    count: claripy.ast.BV, hl: claripy.ast.BV
) -> tuple[claripy.ast.BV, claripy.ast.BV]:
    result = hl + claripy.ZeroExt(8, count) * PARTY_STRUCT_LENGTH
    flags = claripy.If(
        count == 0,
        claripy.BVV(0xA0, 8),
        claripy.BVV(0xC0, 8),
    )
    return result, flags


class AssemblyAddNTimes(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.globals["add_call"] = _register_bytes(self.state)
        self.state.globals["trace"] = self.state.globals["trace"] * 16 + 1
        registers = assembly_registers(self.state)
        result, flags = _add_transition(
            registers["a"], claripy.Concat(registers["h"], registers["l"])
        )
        self.state.regs.a = 0
        self.state.regs.f = sm83_flags_to_z80(flags)
        self.state.regs.hl = result
        target = self.state.memory.load(
            self.state.regs.sp, 2, endness="Iend_LE"
        )
        self.state.regs.sp += 2
        self.jump(target)


class NativeAddNTimes(angr.SimProcedure):
    def run(self, address: claripy.ast.BV) -> None:  # type: ignore[override]
        self.state.globals["add_call"] = self.state.memory.load(address, 8)
        self.state.globals["trace"] = self.state.globals["trace"] * 16 + 1
        count = self.state.memory.load(address, 1)
        hl = self.state.memory.load(address + 6, 2)
        result, flags = _add_transition(count, hl)
        self.state.memory.store(address, claripy.BVV(0, 8))
        self.state.memory.store(address + 1, flags)
        self.state.memory.store(address + 6, result)


class AssemblyPrintText(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.globals["print_call"] = _register_bytes(self.state)
        self.state.globals["trace"] = self.state.globals["trace"] * 16 + 2
        self.state.memory.store(W_TEXT_BOX_ID, claripy.BVV(1, 8))
        self.state.regs.b = 0xC4
        self.state.regs.c = 0xB9
        target = self.state.memory.load(
            self.state.regs.sp, 2, endness="Iend_LE"
        )
        self.state.regs.sp += 2
        self.jump(target)


class NativePrintText(angr.SimProcedure):
    def run(
        self, address: claripy.ast.BV, memory: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        assert not memory.symbolic
        assert self.state.solver.eval(memory) == NATIVE_MEMORY
        self.state.globals["print_call"] = self.state.memory.load(address, 8)
        self.state.globals["trace"] = self.state.globals["trace"] * 16 + 2
        self.state.memory.store(address + 2, claripy.BVV(0xC4B9, 16))
        self.state.memory.store(memory + W_TEXT_BOX_ID, claripy.BVV(1, 8))


def _inputs() -> dict[str, claripy.ast.BV]:
    values = symbolic_registers("check_defrost")
    for name in (
        "whose_turn",
        "player_move_type",
        "enemy_move_type",
        "enemy_status",
        "player_status",
        "enemy_index",
        "player_index",
        "text_box_id",
    ):
        values[name] = claripy.BVS(f"check_defrost_{name}", 8)
    for side in ("player", "enemy"):
        for offset in range(ROSTER_REGION_SIZE):
            values[f"{side}_roster_{offset}"] = claripy.BVS(
                f"check_defrost_{side}_roster_{offset}", 8
            )
    return values


def _setup(
    state: angr.SimState, values: dict[str, claripy.ast.BV], native: bool
) -> None:
    base = NATIVE_MEMORY if native else 0
    for address, name in (
        (W_WHOSE_TURN, "whose_turn"),
        (W_PLAYER_MOVE_TYPE, "player_move_type"),
        (W_ENEMY_MOVE_TYPE, "enemy_move_type"),
        (W_ENEMY_MON_STATUS, "enemy_status"),
        (W_BATTLE_MON_STATUS, "player_status"),
        (W_ENEMY_MON_PARTY_POS, "enemy_index"),
        (W_PLAYER_MON_NUMBER, "player_index"),
        (W_TEXT_BOX_ID, "text_box_id"),
    ):
        state.memory.store(base + address, values[name])
    for side, address in (
        ("player", W_PARTY_MON_1_STATUS),
        ("enemy", W_ENEMY_MON_1_STATUS),
    ):
        for offset in range(ROSTER_REGION_SIZE):
            state.memory.store(
                base + address + offset, values[f"{side}_roster_{offset}"]
            )
    state.globals["add_call"] = claripy.BVV(0, 64)
    state.globals["print_call"] = claripy.BVV(0, 64)
    state.globals["trace"] = claripy.BVV(0, 16)
    state.add_constraints(values["enemy_index"] < PARTY_COUNT)
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
        memory=_memory(state, base),
        add_call=state.globals["add_call"],
        print_call=state.globals["print_call"],
        trace=state.globals["trace"],
        constraints=tuple(state.solver.constraints),
    )


@cache
def _assembly_project() -> tuple[angr.Project, int]:
    location = symbol_location(SYMS, "CheckDefrost")
    add_n_times = symbol_location(SYMS, "AddNTimes")
    print_text = symbol_location(SYMS, "PrintText")
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
    project.hook(base, AndA(0x20, base + 2), length=2)
    project.hook(base + 3, Sm83LoadAHighImmediate(0xF3, base + 5), length=2)
    project.hook(base + 5, AndA(0xFF, base + 6), length=1)
    project.hook(
        base + 8, Sm83LoadAImmediate(W_PLAYER_MOVE_TYPE, base + 11), length=3
    )
    project.hook(base + 11, Sm83SubImmediate(0x14, base + 13), length=2)
    project.hook(
        base + 14, Sm83StoreAImmediate(W_ENEMY_MON_STATUS, base + 17), length=3
    )
    project.hook(
        base + 20,
        Sm83LoadAImmediate(W_ENEMY_MON_PARTY_POS, base + 23),
        length=3,
    )
    project.hook(base + 29, XorA(base + 30), length=1)
    project.hook(base + 30, StoreAAtHL(base + 31), length=1)
    project.hook(
        base + 36, Sm83LoadAImmediate(W_ENEMY_MOVE_TYPE, base + 39), length=3
    )
    project.hook(base + 39, Sm83SubImmediate(0x14, base + 41), length=2)
    project.hook(
        base + 42, Sm83StoreAImmediate(W_BATTLE_MON_STATUS, base + 45), length=3
    )
    project.hook(
        base + 48, Sm83LoadAImmediate(W_PLAYER_MON_NUMBER, base + 51), length=3
    )
    project.hook(base + 57, XorA(base + 58), length=1)
    project.hook(base + 58, StoreAAtHL(base + 59), length=1)
    project.hook(add_n_times.address, AssemblyAddNTimes())
    project.hook(print_text.address, AssemblyPrintText())
    return project, base


@cache
def _native_project() -> tuple[angr.Project, int]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_check_defrost")
    add_n_times = project.loader.find_symbol("port_add_n_times")
    print_text = project.loader.find_symbol("port_print_text")
    assert function is not None
    assert add_n_times is not None
    assert print_text is not None
    project.hook(add_n_times.rebased_addr, NativeAddNTimes())
    project.hook(print_text.rebased_addr, NativePrintText())
    return project, function.rebased_addr


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, function = _assembly_project()
    state = project.factory.blank_state(addr=function)
    set_assembly_registers(state, values)
    _setup(state, values, False)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    endpoints = [
        _endpoint(end, False)
        for end in collect_returns(project, state, RETURN)
    ]
    assert len(endpoints) == 5
    return endpoints


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, function = _native_project()
    state = project.factory.call_state(function, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, values, True)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 5
    return [_endpoint(end, True) for end in manager.deadended]


@pytest.mark.skipif(
    not ELF.exists() or not ROM.exists() or not SYMS.exists(), reason="build"
)
def test_check_defrost_pathwise_equivalence() -> None:
    location = symbol_location(SYMS, "CheckDefrost")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    values = _inputs()
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "memory", "add_call", "print_call", "trace"),
    )
