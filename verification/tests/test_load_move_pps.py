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
    linked_bytes,
    rom_window,
    sm83_flags_to_z80,
    symbol_location,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xFF80
DONE = 0xEFFF
W_MOVE_DATA = 0xCD6D
MARKER = 0xC200
EXECUTING_BANK = 0x03
PARTY_MON_MOVES = 0xD173
PARTY_MON_LENGTH = 0x2C
NORMAL_MAX_PP_MINUS_1 = 0xCD77
ENEMY_MON_MOVES = 0xCFED
ENEMY_MON_PP_MINUS_1 = 0xCFFD
EXPECTED = bytes.fromhex("cd943e")
PREDEF_FIELDS = tuple(f"predef_{index}" for index in range(6))
BANK_FIELDS = ("requested_bank", "loaded_bank", "rom_bank")
MEMORY_FIELDS = (
    *(f"move_{index}" for index in range(4)),
    *(f"pp_{index}" for index in range(4)),
    *(f"move_data_{index}" for index in range(6)),
    "marker",
)

CALLER_LAYOUTS = (
    pytest.param(ENEMY_MON_MOVES, ENEMY_MON_PP_MINUS_1, id="battle"),
    *(
        pytest.param(
            PARTY_MON_MOVES + slot * PARTY_MON_LENGTH,
            NORMAL_MAX_PP_MINUS_1,
            id=f"restore-slot-{slot}",
        )
        for slot in range(6)
    ),
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
    banks: claripy.ast.BV
    predef: claripy.ast.BV
    moves: claripy.ast.BV
    pp: claripy.ast.BV
    move_data: claripy.ast.BV
    marker: claripy.ast.BV
    calls: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _register_snapshot(state: angr.SimState) -> claripy.ast.BV:
    registers = assembly_registers(state)
    return claripy.Concat(*(registers[name] for name in REGISTERS))


class AssemblyGetPredefRegisters(angr.SimProcedure):
    """Complete transition of the independently proven register restore."""

    def run(self) -> None:  # type: ignore[override]
        predef = [self.state.globals[field] for field in PREDEF_FIELDS]
        self.state.globals["predef_call"] = claripy.Concat(
            _register_snapshot(self.state), *predef
        )
        self.state.regs.a = predef[5]
        self.state.regs.b = predef[4]
        self.state.regs.c = predef[5]
        self.state.regs.d = predef[2]
        self.state.regs.e = predef[3]
        self.state.regs.h = predef[0]
        self.state.regs.l = predef[1]
        return_address = self.state.memory.load(
            self.state.regs.sp, 2, endness="Iend_LE"
        )
        self.state.regs.sp += 2
        self.jump(return_address)


class NativeGetPredefRegisters(angr.SimProcedure):
    def run(self, state_address: claripy.ast.BV) -> None:  # type: ignore[override]
        self.state.globals["predef_call"] = self.state.memory.load(
            state_address, 14
        )
        predef = [
            self.state.memory.load(state_address + 8 + index, 1)
            for index in range(6)
        ]
        output = claripy.Concat(
            predef[5],
            self.state.memory.load(state_address + 1, 1),
            predef[4],
            predef[5],
            predef[2],
            predef[3],
            predef[0],
            predef[1],
        )
        self.state.memory.store(state_address, output)


def _assembly_add_call(state: angr.SimState) -> claripy.ast.BV:
    moves = state.globals["moves_address"]
    destination = state.globals["destination_address"]
    return claripy.Concat(
        _register_snapshot(state),
        *(state.globals[field] for field in BANK_FIELDS),
        state.memory.load(moves, 4),
        state.memory.load(destination + 1, 4),
        state.memory.load(W_MOVE_DATA, 6),
        state.memory.load(MARKER, 1),
    )


class AssemblyAddPartyMonWriteMovePP(angr.SimProcedure):
    """Arbitrary complete transition of the proven fallthrough function."""

    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["add_call"] = _assembly_add_call(self.state)
        for register in REGISTERS:
            value = self.state.globals[f"add_out_{register}"]
            if register == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, register, value)
        for field in BANK_FIELDS:
            self.state.globals[field] = self.state.globals[f"add_out_{field}"]
        destination = self.state.globals["destination_address"]
        for index in range(4):
            self.state.memory.store(
                destination + 1 + index,
                self.state.globals[f"add_out_pp_{index}"],
            )
        for index in range(6):
            self.state.memory.store(
                W_MOVE_DATA + index,
                self.state.globals[f"add_out_move_data_{index}"],
            )
        self.jump(self._continuation)


class NativeAddPartyMonWriteMovePP(angr.SimProcedure):
    def run(
        self, state_address: claripy.ast.BV, memory: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        moves = self.state.globals["moves_address"]
        destination = self.state.globals["destination_address"]
        self.state.globals["add_call"] = claripy.Concat(
            self.state.memory.load(state_address, 11),
            self.state.memory.load(memory + moves, 4),
            self.state.memory.load(memory + destination + 1, 4),
            self.state.memory.load(memory + W_MOVE_DATA, 6),
            self.state.memory.load(memory + MARKER, 1),
        )
        output = claripy.Concat(
            *(self.state.globals[f"add_out_{register}"] for register in REGISTERS),
            *(self.state.globals[f"add_out_{field}"] for field in BANK_FIELDS),
        )
        self.state.memory.store(state_address, output)
        for index in range(4):
            self.state.memory.store(
                memory + destination + 1 + index,
                self.state.globals[f"add_out_pp_{index}"],
            )
        for index in range(6):
            self.state.memory.store(
                memory + W_MOVE_DATA + index,
                self.state.globals[f"add_out_move_data_{index}"],
            )


def _inputs(
    prefix: str, moves: int, destination: int
) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    pointers = (
        moves >> 8,
        moves & 0xFF,
        destination >> 8,
        destination & 0xFF,
    )
    for index, field in enumerate(PREDEF_FIELDS):
        values[field] = (
            claripy.BVV(pointers[index], 8)
            if index < 4
            else claripy.BVS(f"{prefix}_{field}", 8)
        )
    values["requested_bank"] = claripy.BVS(f"{prefix}_requested_bank", 8)
    values["loaded_bank"] = claripy.BVV(EXECUTING_BANK, 8)
    values["rom_bank"] = claripy.BVV(EXECUTING_BANK, 8)
    for field in MEMORY_FIELDS:
        values[field] = claripy.BVS(f"{prefix}_{field}", 8)
    for register in REGISTERS:
        values[f"add_out_{register}"] = (
            claripy.Concat(
                claripy.BVS(f"{prefix}_add_out_flags", 4),
                claripy.BVV(0, 4),
            )
            if register == "f"
            else claripy.BVS(f"{prefix}_add_out_{register}", 8)
        )
    for field in BANK_FIELDS:
        values[f"add_out_{field}"] = claripy.BVS(
            f"{prefix}_add_out_{field}", 8
        )
    for index in range(4):
        values[f"add_out_pp_{index}"] = claripy.BVS(
            f"{prefix}_add_out_pp_{index}", 8
        )
    for index in range(6):
        values[f"add_out_move_data_{index}"] = claripy.BVS(
            f"{prefix}_add_out_move_data_{index}", 8
        )
    return values


def _setup(
    state: angr.SimState,
    values: dict[str, claripy.ast.BV],
    moves: int,
    destination: int,
    native: bool,
) -> None:
    memory_base = NATIVE_MEMORY if native else 0
    state.globals["moves_address"] = moves
    state.globals["destination_address"] = destination
    for field in (*PREDEF_FIELDS, *BANK_FIELDS):
        state.globals[field] = values[field]
    for register in REGISTERS:
        state.globals[f"add_out_{register}"] = values[f"add_out_{register}"]
    for field in BANK_FIELDS:
        state.globals[f"add_out_{field}"] = values[f"add_out_{field}"]
    for index in range(4):
        state.memory.store(memory_base + moves + index, values[f"move_{index}"])
        state.memory.store(
            memory_base + destination + 1 + index,
            values[f"pp_{index}"],
        )
        state.globals[f"add_out_pp_{index}"] = values[f"add_out_pp_{index}"]
    for index in range(6):
        state.memory.store(
            memory_base + W_MOVE_DATA + index,
            values[f"move_data_{index}"],
        )
        state.globals[f"add_out_move_data_{index}"] = values[
            f"add_out_move_data_{index}"
        ]
    state.memory.store(memory_base + MARKER, values["marker"])
    state.globals["predef_call"] = claripy.BVV(0, 112)
    state.globals["add_call"] = claripy.BVV(0, 208)


def _endpoint(
    state: angr.SimState, moves: int, destination: int, native: bool
) -> Endpoint:
    memory_base = NATIVE_MEMORY if native else 0
    registers = (
        native_registers(state, NATIVE_STATE)
        if native
        else assembly_registers(state)
    )
    banks = (
        state.memory.load(NATIVE_STATE + 8, 3)
        if native
        else claripy.Concat(*(state.globals[field] for field in BANK_FIELDS))
    )
    predef = (
        state.memory.load(NATIVE_STATE + 11, 6)
        if native
        else claripy.Concat(*(state.globals[field] for field in PREDEF_FIELDS))
    )
    return Endpoint(
        **registers,
        banks=banks,
        predef=predef,
        moves=state.memory.load(memory_base + moves, 4),
        pp=state.memory.load(memory_base + destination + 1, 4),
        move_data=state.memory.load(memory_base + W_MOVE_DATA, 6),
        marker=state.memory.load(memory_base + MARKER, 1),
        calls=claripy.Concat(
            state.globals["predef_call"], state.globals["add_call"]
        ),
        constraints=tuple(state.solver.constraints),
    )


@cache
def _assembly_project() -> tuple[angr.Project, int]:
    location = symbol_location(SYMS, "LoadMovePPs")
    add_party = symbol_location(SYMS, "AddPartyMon_WriteMovePP")
    get_predef = symbol_location(SYMS, "GetPredefRegisters")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    assert add_party.bank == location.bank and add_party.address == location.address + 3
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
    project.hook(get_predef.address, AssemblyGetPredefRegisters())
    project.hook(
        add_party.address,
        AssemblyAddPartyMonWriteMovePP(DONE),
        length=39,
    )
    return project, location.address


@cache
def _native_project() -> tuple[angr.Project, int]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_load_move_pps")
    get_predef = project.loader.find_symbol("port_get_predef_registers")
    add_party = project.loader.find_symbol("port_add_party_mon_write_move_pp")
    assert function is not None and get_predef is not None and add_party is not None
    project.hook(get_predef.rebased_addr, NativeGetPredefRegisters())
    project.hook(add_party.rebased_addr, NativeAddPartyMonWriteMovePP())
    return project, function.rebased_addr


def _assembly(
    values: dict[str, claripy.ast.BV], moves: int, destination: int
) -> list[Endpoint]:
    project, function = _assembly_project()
    state = project.factory.blank_state(addr=function)
    set_assembly_registers(state, values)
    _setup(state, values, moves, destination, False)
    state.regs.sp = STACK
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE)
    assert not manager.errored and len(manager.found) == 1
    return [_endpoint(end, moves, destination, False) for end in manager.found]


def _native(
    values: dict[str, claripy.ast.BV], moves: int, destination: int
) -> list[Endpoint]:
    project, function = _native_project()
    state = project.factory.call_state(function, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    for offset, field in enumerate(BANK_FIELDS, 8):
        state.memory.store(NATIVE_STATE + offset, values[field])
    for offset, field in enumerate(PREDEF_FIELDS, 11):
        state.memory.store(NATIVE_STATE + offset, values[field])
    _setup(state, values, moves, destination, True)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [_endpoint(end, moves, destination, True) for end in manager.deadended]


@pytest.mark.skipif(
    not ELF.exists() or not ROM.exists() or not SYMS.exists(), reason="build"
)
@pytest.mark.parametrize("moves,destination", CALLER_LAYOUTS)
def test_load_move_pps_pathwise_equivalence(moves: int, destination: int) -> None:
    values = _inputs(f"load_move_pps_{moves:04x}", moves, destination)
    assert_pathwise_equivalent(
        _assembly(values, moves, destination),
        _native(values, moves, destination),
        (
            *REGISTERS,
            "banks",
            "predef",
            "moves",
            "pp",
            "move_data",
            "marker",
            "calls",
        ),
    )
