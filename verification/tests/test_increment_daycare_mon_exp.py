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
    symbol_location,
)
from verification.harness.sm83_shims import (
    Sm83CpImmediate,
    Sm83LoadAImmediate,
)


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
GB_STACK = 0xD000
GB_RETURN = 0xFFFF


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


class AndA(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.f = 0x10 | claripy.If(
            self.state.regs.a == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)
        )
        self.jump(self._next_address)


class IncAtHl(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        old = self.state.memory.load(self.state.regs.hl, 1)
        result = old + 1
        self.state.memory.store(self.state.regs.hl, result)
        self.state.regs.f = (self.state.regs.f & 1) | claripy.If(
            result == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)
        ) | claripy.If(
            (old & 0x0F) == 0x0F, claripy.BVV(0x10, 8), claripy.BVV(0, 8)
        )
        self.jump(self._next_address)


def addresses() -> tuple[int, int]:
    return (
        symbol_location(SYMBOLS, "wDayCareInUse").address,
        symbol_location(SYMBOLS, "wDayCareMonExp").address,
    )


def inputs() -> dict[str, claripy.ast.BV]:
    values = symbolic_registers("increment_daycare_mon_exp")
    for name in ("in_use", "exp_high", "exp_mid", "exp_low"):
        values[name] = claripy.BVS(f"daycare_{name}", 8)
    return values


def assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "IncrementDayCareMonExp")
    in_use, exp = addresses()
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
    project.hook(base, Sm83LoadAImmediate(in_use, base + 3), length=3)
    project.hook(base + 3, AndA(base + 4), length=1)
    project.hook(base + 8, IncAtHl(base + 9), length=1)
    project.hook(base + 11, IncAtHl(base + 12), length=1)
    project.hook(base + 14, IncAtHl(base + 15), length=1)
    project.hook(base + 17, Sm83CpImmediate(0x50, base + 19), length=2)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.memory.store(in_use, values["in_use"])
    state.memory.store(
        exp,
        claripy.Concat(values["exp_high"], values["exp_mid"], values["exp_low"]),
    )
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    return [
        Endpoint(
            **assembly_registers(end),
            memory=claripy.Concat(
                end.memory.load(in_use, 1), end.memory.load(exp, 3)
            ),
            constraints=tuple(end.solver.constraints),
        )
        for end in returned
    ]


def native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_increment_daycare_mon_exp")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(
        NATIVE_STATE + 8,
        claripy.Concat(
            values["in_use"],
            values["exp_high"],
            values["exp_mid"],
            values["exp_low"],
        ),
    )
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=end.memory.load(NATIVE_STATE + 8, 4),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native port not built")
def test_symbolic_equivalence() -> None:
    values = inputs()
    assert_pathwise_equivalent(
        assembly(values), native(values), (*REGISTERS, "memory")
    )


def test_exact_body_and_addresses() -> None:
    location = symbol_location(SYMBOLS, "IncrementDayCareMonExp")
    assert addresses() == (0xDA48, 0xDA6D)
    assert linked_bytes(ROM, location, 23) == bytes.fromhex(
        "fa48daa7c8216fda34c02b34c02b347efe50d83e5077c9"
    )
