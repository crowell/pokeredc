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
from verification.harness.rom import (
    collect_returns,
    linked_bytes,
    rom_window,
    sm83_flags_to_z80,
    symbol_location,
)
from verification.harness.sm83_shims import Sm83AndImmediate


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_CALLBACK = 0x100100
NATIVE_GLOBALS = 0x100200
STACK = 0xD000
RETURN = 0xFFFF
CURRENT_OPPONENT = 0xD059
CURRENT_PARTY_SPECIES = 0xCF91
ENEMY_SPECIES2 = 0xCFD8
STATE_KEYS = (
    "current_opponent",
    "current_party_species",
    "enemy_species2",
    "destination",
)
CALLBACK_KEYS = ("current_opponent", "current_party_species", "enemy_species2")


class ReadGlobal(angr.SimProcedure):
    def __init__(self, key: str, next_address: int) -> None:
        super().__init__()
        self.key = key
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals[self.key]
        self.jump(self.next_address)


class StoreGlobal(angr.SimProcedure):
    def __init__(self, key: str, next_address: int) -> None:
        super().__init__()
        self.key = key
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.globals[self.key] = self.state.regs.a
        self.jump(self.next_address)


class TailBoundary(angr.SimProcedure):
    def __init__(self, destination: int, full: bool) -> None:
        super().__init__()
        self.destination = destination
        self.full = full

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["destination"] = claripy.BVV(self.destination, 8)
        if self.full:
            callback = self.state.globals["callback"]
            for register in REGISTERS:
                value = callback[register]
                if register == "f":
                    value = sm83_flags_to_z80(value)
                setattr(self.state.regs, register, value)
            for key in CALLBACK_KEYS:
                self.state.globals[key] = callback[key]
        self.jump(RETURN)


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
    constraints: tuple[claripy.ast.Bool, ...]


def inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for key in STATE_KEYS:
        values[key] = claripy.BVS(f"{prefix}_{key}", 8)
    callback = symbolic_registers(f"{prefix}_callback")
    for register, value in callback.items():
        values[f"callback_{register}"] = value
    for key in CALLBACK_KEYS:
        values[f"callback_{key}"] = claripy.BVS(f"{prefix}_callback_{key}", 8)
    return values


def assembly(
    symbol: str, values: dict[str, claripy.ast.BV], full: bool
) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, symbol)
    opponent = symbol_location(SYMBOLS, "InitOpponent").address
    wild = symbol_location(SYMBOLS, "DetermineWildOpponent").address
    common = symbol_location(SYMBOLS, "InitBattleCommon").address
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
    if symbol == "InitBattle":
        q = location.address
        project.hook(q, ReadGlobal("current_opponent", q + 3), length=3)
        project.hook(q + 3, Sm83AndImmediate(0xFF, q + 4), length=1)
    project.hook(opponent, ReadGlobal("current_opponent", opponent + 3), length=3)
    project.hook(
        opponent + 3,
        StoreGlobal("current_party_species", opponent + 6),
        length=3,
    )
    project.hook(
        opponent + 6, StoreGlobal("enemy_species2", opponent + 9), length=3
    )
    project.hook(wild, TailBoundary(0, full))
    project.hook(common, TailBoundary(1, full))

    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    for key in STATE_KEYS[:-1]:
        state.globals[key] = values[key]
    state.globals["destination"] = values["destination"]
    state.globals["callback"] = {
        register: values[f"callback_{register}"] for register in REGISTERS
    } | {key: values[f"callback_{key}"] for key in CALLBACK_KEYS}
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    endpoints = []
    for end in collect_returns(project, state, RETURN):
        memory = [end.globals[key] for key in STATE_KEYS]
        if full:
            memory.extend(end.globals["callback"][register] for register in REGISTERS)
            memory.extend(end.globals["callback"][key] for key in CALLBACK_KEYS)
        endpoints.append(
            Endpoint(
                **assembly_registers(end),
                memory=claripy.Concat(*memory),
                constraints=tuple(end.solver.constraints),
            )
        )
    return endpoints


def native(
    symbol: str, values: dict[str, claripy.ast.BV], full: bool
) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    c_symbol = {
        "InitBattle": "port_init_battle",
        "InitOpponent": "port_init_opponent",
    }[symbol] + ("" if full else "_begin")
    function = project.loader.find_symbol(c_symbol)
    assert function
    if full:
        state = project.factory.call_state(
            function.rebased_addr, NATIVE_STATE, NATIVE_CALLBACK, NATIVE_GLOBALS
        )
    else:
        state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(
        NATIVE_STATE + 8, claripy.Concat(*(values[key] for key in STATE_KEYS))
    )
    if full:
        callback_registers = {
            register: values[f"callback_{register}"] for register in REGISTERS
        }
        store_native_registers(state, NATIVE_CALLBACK, callback_registers)
        state.memory.store(
            NATIVE_GLOBALS,
            claripy.Concat(*(values[f"callback_{key}"] for key in CALLBACK_KEYS)),
        )
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    endpoints = []
    for end in manager.deadended:
        memory = [end.memory.load(NATIVE_STATE + 8, len(STATE_KEYS))]
        if full:
            memory.append(end.memory.load(NATIVE_CALLBACK, len(REGISTERS)))
            memory.append(end.memory.load(NATIVE_GLOBALS, len(CALLBACK_KEYS)))
        endpoints.append(
            Endpoint(
                **native_registers(end, NATIVE_STATE),
                memory=claripy.Concat(*memory),
                constraints=tuple(end.solver.constraints),
            )
        )
    return endpoints


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native")
@pytest.mark.parametrize("symbol", ("InitBattle", "InitOpponent"))
@pytest.mark.parametrize("full", (False, True))
def test_equivalence(symbol: str, full: bool) -> None:
    values = inputs(f"{symbol}_{full}")
    assert_pathwise_equivalent(
        assembly(symbol, values, full),
        native(symbol, values, full),
        (*REGISTERS, "memory"),
    )


def test_exact_bodies() -> None:
    battle = symbol_location(SYMBOLS, "InitBattle")
    opponent = symbol_location(SYMBOLS, "InitOpponent")
    assert linked_bytes(ROM, battle, 6) == bytes.fromhex("fa59d0a7280b")
    assert linked_bytes(ROM, opponent, 11) == bytes.fromhex(
        "fa59d0ea91cfead8cf181a"
    )
    assert symbol_location(SYMBOLS, "wCurOpponent").address == CURRENT_OPPONENT
    assert (
        symbol_location(SYMBOLS, "wCurPartySpecies").address
        == CURRENT_PARTY_SPECIES
    )
    assert symbol_location(SYMBOLS, "wEnemyMonSpecies2").address == ENEMY_SPECIES2
