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
from verification.harness.sm83_shims import Sm83AddHlRegisterPair, Sm83AddRegister


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_CALLBACK = 0x100100
STACK = 0xD000
RETURN = 0xFFFF
KEYS = ("fetched_low", "fetched_high", "saved_h", "saved_l", "dispatched")


class SaveHl(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["saved_h"] = self.state.regs.h
        self.state.globals["saved_l"] = self.state.regs.l
        self.jump(self.next_address)


class RestoreHl(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = self.state.globals["saved_h"]
        self.state.regs.l = self.state.globals["saved_l"]
        self.jump(self.next_address)


class FetchLow(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals["fetched_low"]
        self.state.regs.hl = self.state.regs.hl + 1
        self.jump(self.next_address)


class FetchHigh(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.d = self.state.globals["fetched_high"]
        self.jump(self.next_address)


class TailBoundary(angr.SimProcedure):
    def __init__(self, full: bool) -> None:
        super().__init__()
        self.full = full

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["dispatched"] = claripy.BVV(1, 8)
        if self.full:
            callback = self.state.globals["callback"]
            for register in REGISTERS:
                value = callback[register]
                if register == "f":
                    value = sm83_flags_to_z80(value)
                setattr(self.state.regs, register, value)
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
    for key in KEYS:
        values[key] = claripy.BVS(f"{prefix}_{key}", 8)
    callback = symbolic_registers(f"{prefix}_callback")
    for register, value in callback.items():
        values[f"callback_{register}"] = value
    return values


def assembly(values: dict[str, claripy.ast.BV], full: bool) -> list[Endpoint]:
    entry = symbol_location(SYMBOLS, "PrintType")
    shared = symbol_location(SYMBOLS, "PrintType_").address
    project = angr.Project(
        rom_window(ROM, entry.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": entry.address,
        },
    )
    project.hook(entry.address, SaveHl(entry.address + 1), length=1)
    project.hook(shared, Sm83AddRegister("a", shared + 1), length=1)
    project.hook(shared + 7, Sm83AddHlRegisterPair("de", shared + 8), length=1)
    project.hook(shared + 8, FetchLow(shared + 9), length=1)
    project.hook(shared + 10, FetchHigh(shared + 11), length=1)
    project.hook(shared + 11, RestoreHl(shared + 12), length=1)
    project.hook(shared + 12, TailBoundary(full), length=3)

    state = project.factory.blank_state(addr=entry.address)
    set_assembly_registers(state, values)
    for key in KEYS[:-1]:
        state.globals[key] = values[key]
    state.globals["dispatched"] = claripy.BVV(0, 8)
    state.globals["callback"] = {
        register: values[f"callback_{register}"] for register in REGISTERS
    }
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    return [
        Endpoint(
            **assembly_registers(end),
            memory=claripy.Concat(*(end.globals[key] for key in KEYS)),
            constraints=tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, RETURN)
    ]


def native(values: dict[str, claripy.ast.BV], full: bool) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    symbol = "port_print_type" if full else "port_print_type_begin"
    function = project.loader.find_symbol(symbol)
    assert function
    if full:
        state = project.factory.call_state(
            function.rebased_addr, NATIVE_STATE, NATIVE_CALLBACK
        )
    else:
        state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(
        NATIVE_STATE + 8, claripy.Concat(*(values[key] for key in KEYS))
    )
    if full:
        callback = {
            register: values[f"callback_{register}"] for register in REGISTERS
        }
        store_native_registers(state, NATIVE_CALLBACK, callback)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=end.memory.load(NATIVE_STATE + 8, len(KEYS)),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native")
@pytest.mark.parametrize("full", (False, True))
def test_equivalence(full: bool) -> None:
    values = inputs(f"print_type_{full}")
    assert_pathwise_equivalent(
        assembly(values, full), native(values, full), (*REGISTERS, "memory")
    )


def test_exact_entry_and_shared_body() -> None:
    entry = symbol_location(SYMBOLS, "PrintType")
    shared = symbol_location(SYMBOLS, "PrintType_")
    assert linked_bytes(ROM, entry, 3) == bytes.fromhex("e51813")
    assert linked_bytes(ROM, shared, 15) == bytes.fromhex(
        "8721ae7d5f1600192a5f56e1c35519"
    )
    assert symbol_location(SYMBOLS, "TypeNames").address == 0x7DAE
    assert symbol_location(SYMBOLS, "PlaceString").address == 0x1955
