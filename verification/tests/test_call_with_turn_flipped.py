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
    z80_flags_to_sm83,
)
from verification.harness.sm83_shims import Sm83XorImmediate


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_CALLBACK = 0x100100
STACK = 0xD000
RETURN = 0xFFFF
DONE = 0xEFFF
WHOSE_TURN = 0xFFF3


class ReadTurn(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals["whose_turn"]
        self.jump(self.next_address)


class WriteTurn(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["whose_turn"] = self.state.regs.a
        self.jump(self.next_address)


class SaveAf(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["saved_a"] = self.state.regs.a
        self.state.globals["saved_f"] = z80_flags_to_sm83(self.state.regs.f)
        self.jump(self.next_address)


class RestoreAf(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals["saved_a"]
        self.state.regs.f = sm83_flags_to_z80(self.state.globals["saved_f"])
        self.jump(self.next_address)


class IgnorePush(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.jump(self.next_address)


class CallbackBoundary(angr.SimProcedure):
    def __init__(self, next_address: int | None = None) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        if self.next_address is None:
            self.jump(DONE)
            return
        callback = self.state.globals["callback"]
        for register in REGISTERS:
            value = callback[register]
            if register == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, register, value)
        self.state.globals["whose_turn"] = callback["whose_turn"]
        self.jump(self.next_address)


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
    values["whose_turn"] = claripy.BVS(f"{prefix}_whose_turn", 8)
    values["saved_a"] = claripy.BVS(f"{prefix}_saved_a", 8)
    values["saved_f"] = claripy.Concat(
        claripy.BVS(f"{prefix}_saved_flags", 4), claripy.BVV(0, 4)
    )
    callback = symbolic_registers(f"{prefix}_callback")
    for register, value in callback.items():
        values[f"callback_{register}"] = value
    values["callback_whose_turn"] = claripy.BVS(
        f"{prefix}_callback_whose_turn", 8
    )
    return values


def gb_project() -> tuple[int, angr.Project]:
    location = symbol_location(SYMBOLS, "CallWithTurnFlipped")
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
    return location.address, project


def install_prefix_hooks(
    project: angr.Project, q: int, callback: angr.SimProcedure
) -> None:
    project.hook(q, ReadTurn(q + 2), length=2)
    project.hook(q + 2, SaveAf(q + 3), length=1)
    project.hook(q + 3, Sm83XorImmediate(1, q + 5), length=2)
    project.hook(q + 5, WriteTurn(q + 7), length=2)
    project.hook(q + 10, IgnorePush(q + 11), length=1)
    project.hook(q + 11, callback, length=1)


def setup_assembly(
    state: angr.SimState, values: dict[str, claripy.ast.BV]
) -> None:
    set_assembly_registers(state, values)
    state.globals["whose_turn"] = values["whose_turn"]
    state.globals["saved_a"] = values["saved_a"]
    state.globals["saved_f"] = values["saved_f"]
    state.globals["callback"] = {
        register: values[f"callback_{register}"] for register in REGISTERS
    } | {"whose_turn": values["callback_whose_turn"]}
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")


def assembly_endpoint(state: angr.SimState, callback_memory: bool) -> Endpoint:
    memory = [
        state.globals["whose_turn"],
        state.globals["saved_a"],
        state.globals["saved_f"],
    ]
    if callback_memory:
        memory.extend(state.globals["callback"][register] for register in REGISTERS)
    return Endpoint(
        **assembly_registers(state),
        memory=claripy.Concat(*memory),
        constraints=tuple(state.solver.constraints),
    )


def assembly_begin(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    q, project = gb_project()
    install_prefix_hooks(project, q, CallbackBoundary())
    state = project.factory.blank_state(addr=q)
    setup_assembly(state, values)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE)
    assert len(manager.found) == 1
    return [assembly_endpoint(manager.found[0], False)]


def assembly_return(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    q, project = gb_project()
    project.hook(q + 12, RestoreAf(q + 13), length=1)
    project.hook(q + 13, WriteTurn(q + 15), length=2)
    state = project.factory.blank_state(addr=q + 12)
    setup_assembly(state, values)
    return [
        assembly_endpoint(end, False)
        for end in collect_returns(project, state, RETURN)
    ]


def assembly_full(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    q, project = gb_project()
    install_prefix_hooks(project, q, CallbackBoundary(q + 12))
    project.hook(q + 12, RestoreAf(q + 13), length=1)
    project.hook(q + 13, WriteTurn(q + 15), length=2)
    state = project.factory.blank_state(addr=q)
    setup_assembly(state, values)
    return [
        assembly_endpoint(end, True)
        for end in collect_returns(project, state, RETURN)
    ]


def native(
    symbol: str,
    values: dict[str, claripy.ast.BV],
    callback_memory: bool = False,
) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(symbol)
    assert function
    if callback_memory:
        state = project.factory.call_state(
            function.rebased_addr,
            NATIVE_STATE,
            NATIVE_CALLBACK,
            values["callback_whose_turn"],
        )
    else:
        state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(
        NATIVE_STATE + 8,
        claripy.Concat(
            values["whose_turn"], values["saved_a"], values["saved_f"]
        ),
    )
    if callback_memory:
        callback = {
            register: values[f"callback_{register}"] for register in REGISTERS
        }
        store_native_registers(state, NATIVE_CALLBACK, callback)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    endpoints = []
    for end in manager.deadended:
        memory = [end.memory.load(NATIVE_STATE + 8, 3)]
        if callback_memory:
            memory.append(end.memory.load(NATIVE_CALLBACK, 8))
        endpoints.append(
            Endpoint(
                **native_registers(end, NATIVE_STATE),
                memory=claripy.Concat(*memory),
                constraints=tuple(end.solver.constraints),
            )
        )
    return endpoints


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native")
@pytest.mark.parametrize(
    ("assembly", "symbol"),
    (
        (assembly_begin, "port_call_with_turn_flipped_begin"),
        (assembly_return, "port_call_with_turn_flipped_return"),
    ),
)
def test_phase_equivalence(assembly, symbol: str) -> None:
    values = inputs(symbol)
    assert_pathwise_equivalent(
        assembly(values), native(symbol, values), (*REGISTERS, "memory")
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native")
def test_full_compositional_equivalence() -> None:
    values = inputs("call_with_turn_flipped")
    assert_pathwise_equivalent(
        assembly_full(values),
        native("port_call_with_turn_flipped", values, callback_memory=True),
        (*REGISTERS, "memory"),
    )


def test_exact_body() -> None:
    location = symbol_location(SYMBOLS, "CallWithTurnFlipped")
    assert linked_bytes(ROM, location, 16) == bytes.fromhex(
        "f0f3f5ee01e0f3116151d5e9f1e0f3c9"
    )
    assert symbol_location(SYMBOLS, "hWhoseTurn").address == WHOSE_TURN
