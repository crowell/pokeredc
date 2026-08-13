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
from verification.harness.sm83_shims import (
    Sm83AddHlRegisterPair,
    Sm83AddRegister,
    Sm83AndImmediate,
    Sm83DecRegister,
)


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_CALLBACK = 0x100100
STACK = 0xD000
RETURN = 0xFFFF
ANIMATION_TYPE = 0xCC5B


class ReadAnimationType(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals["animation_type"]
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
        self.state.regs.h = self.state.globals["fetched_high"]
        self.jump(self.next_address)


class TailBoundary(angr.SimProcedure):
    def __init__(self, apply_callback: bool) -> None:
        super().__init__()
        self.apply_callback = apply_callback

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["dispatched"] = claripy.BVV(1, 8)
        if self.apply_callback:
            callback = self.state.globals["callback"]
            for register in REGISTERS:
                value = callback[register]
                if register == "f":
                    value = sm83_flags_to_z80(value)
                setattr(self.state.regs, register, value)
            self.state.globals["animation_type"] = callback["animation_type"]
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
    for name in ("animation_type", "fetched_low", "fetched_high", "dispatched"):
        values[name] = claripy.BVS(f"{prefix}_{name}", 8)
    callback = symbolic_registers(f"{prefix}_callback")
    for register, value in callback.items():
        values[f"callback_{register}"] = value
    values["callback_animation_type"] = claripy.BVS(
        f"{prefix}_callback_animation_type", 8
    )
    return values


def assembly(values: dict[str, claripy.ast.BV], full: bool) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "PlayApplyingAttackAnimation")
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
    q = location.address
    project.hook(q, ReadAnimationType(q + 3), length=3)
    project.hook(q + 3, Sm83AndImmediate(0xFF, q + 4), length=1)
    project.hook(q + 5, Sm83DecRegister("a", q + 6), length=1)
    project.hook(q + 6, Sm83AddRegister("a", q + 7), length=1)
    project.hook(q + 13, Sm83AddHlRegisterPair("bc", q + 14), length=1)
    project.hook(q + 14, FetchLow(q + 15), length=1)
    project.hook(q + 15, FetchHigh(q + 16), length=1)
    project.hook(q + 17, TailBoundary(full), length=1)

    state = project.factory.blank_state(addr=q)
    set_assembly_registers(state, values)
    for name in ("animation_type", "fetched_low", "fetched_high"):
        state.globals[name] = values[name]
    state.globals["dispatched"] = claripy.BVV(0, 8)
    state.globals["callback"] = {
        register: values[f"callback_{register}"] for register in REGISTERS
    } | {"animation_type": values["callback_animation_type"]}
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    endpoints = []
    for end in collect_returns(project, state, RETURN):
        memory = [
            end.globals["animation_type"],
            end.globals["fetched_low"],
            end.globals["fetched_high"],
            end.globals["dispatched"],
        ]
        if full:
            memory.extend(end.globals["callback"][register] for register in REGISTERS)
        endpoints.append(
            Endpoint(
                **assembly_registers(end),
                memory=claripy.Concat(*memory),
                constraints=tuple(end.solver.constraints),
            )
        )
    return endpoints


def native(values: dict[str, claripy.ast.BV], full: bool) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    symbol = (
        "port_play_applying_attack_animation"
        if full
        else "port_play_applying_attack_animation_begin"
    )
    function = project.loader.find_symbol(symbol)
    assert function
    if full:
        state = project.factory.call_state(
            function.rebased_addr,
            NATIVE_STATE,
            NATIVE_CALLBACK,
            values["callback_animation_type"],
        )
    else:
        state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(
        NATIVE_STATE + 8,
        claripy.Concat(
            values["animation_type"],
            values["fetched_low"],
            values["fetched_high"],
            values["dispatched"],
        ),
    )
    if full:
        callback = {
            register: values[f"callback_{register}"] for register in REGISTERS
        }
        store_native_registers(state, NATIVE_CALLBACK, callback)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    endpoints = []
    for end in manager.deadended:
        memory = [end.memory.load(NATIVE_STATE + 8, 4)]
        if full:
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
@pytest.mark.parametrize("full", (False, True))
def test_equivalence(full: bool) -> None:
    values = inputs(f"applying_attack_{full}")
    assert_pathwise_equivalent(
        assembly(values, full), native(values, full), (*REGISTERS, "memory")
    )


def test_exact_body_and_table() -> None:
    location = symbol_location(SYMBOLS, "PlayApplyingAttackAnimation")
    table = symbol_location(SYMBOLS, "AnimationTypePointerTable")
    assert linked_bytes(ROM, location, 18) == bytes.fromhex(
        "fa5bcca7c83d874f060021cf4d092a666fe9"
    )
    assert linked_bytes(ROM, table, 12) == bytes.fromhex(
        "db4de34deb4df04df64dfe4d"
    )
    assert symbol_location(SYMBOLS, "wAnimationType").address == ANIMATION_TYPE
