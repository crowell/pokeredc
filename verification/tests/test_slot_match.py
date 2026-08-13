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
from verification.harness.rom import collect_returns, linked_bytes, rom_window, symbol_location


ROOT = Path(__file__).resolve().parents[2]
VERIFY = ROOT / "verification"
NATIVE_ELF = VERIFY / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
GB_STACK = 0xD000
GB_RETURN = 0xFFFF
NATIVE_STATE = 0x100000


class LoadValue(angr.SimProcedure):
    def __init__(self, name: str, next_address: int) -> None:
        super().__init__()
        self._name = name
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals[self._name]
        self.jump(self._next_address)


class CompareHlValue(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        left = self.state.regs.a
        right = self.state.globals["hl_value"]
        result = left - right
        flags = claripy.BVV(0x02, 8)
        flags |= claripy.If(result == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        flags |= claripy.If(
            (left & 0x0F).ULT(right & 0x0F),
            claripy.BVV(0x10, 8),
            claripy.BVV(0, 8),
        )
        flags |= claripy.If(left.ULT(right), claripy.BVV(1, 8), claripy.BVV(0, 8))
        self.state.regs.f = flags
        self.jump(self._next_address)


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
    de_value: claripy.ast.BV
    bc_value: claripy.ast.BV
    hl_value: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _alias_constraints(inputs: dict[str, claripy.ast.BV]) -> tuple[claripy.ast.Bool, ...]:
    de = claripy.Concat(inputs["d"], inputs["e"])
    bc = claripy.Concat(inputs["b"], inputs["c"])
    hl = claripy.Concat(inputs["h"], inputs["l"])
    return (
        claripy.Or(de != hl, inputs["de_value"] == inputs["hl_value"]),
        claripy.Or(bc != hl, inputs["bc_value"] == inputs["hl_value"]),
        claripy.Or(de != bc, inputs["de_value"] == inputs["bc_value"]),
    )


def _assembly(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "SlotMachine_CheckForMatch")
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
    project.hook(location.address, LoadValue("de_value", location.address + 1), length=1)
    project.hook(location.address + 1, CompareHlValue(location.address + 2), length=1)
    project.hook(location.address + 3, LoadValue("bc_value", location.address + 4), length=1)
    project.hook(location.address + 4, CompareHlValue(location.address + 5), length=1)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    for name in ("de_value", "bc_value", "hl_value"):
        state.globals[name] = inputs[name]
    state.solver.add(*_alias_constraints(inputs))
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    return [
        Endpoint(
            **assembly_registers(end),
            de_value=inputs["de_value"],
            bc_value=inputs["bc_value"],
            hl_value=inputs["hl_value"],
            constraints=tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, GB_RETURN)
    ]


def _native(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_slot_machine_check_for_match")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    for index, name in enumerate(("de_value", "bc_value", "hl_value")):
        state.memory.store(NATIVE_STATE + 8 + index, inputs[name])
    state.solver.add(*_alias_constraints(inputs))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            de_value=end.memory.load(NATIVE_STATE + 8, 1),
            bc_value=end.memory.load(NATIVE_STATE + 9, 1),
            hl_value=end.memory.load(NATIVE_STATE + 10, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_slot_machine_check_for_match_symbolic_equivalence() -> None:
    inputs = symbolic_registers("slot_machine_check_for_match")
    for name in ("de_value", "bc_value", "hl_value"):
        inputs[name] = claripy.BVS(f"slot_machine_check_for_match_{name}", 8)
    assert_pathwise_equivalent(
        _assembly(inputs),
        _native(inputs),
        (*REGISTERS, "de_value", "bc_value", "hl_value"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_slot_machine_check_for_match_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "SlotMachine_CheckForMatch")
    assert linked_bytes(ROM, location, 6) == bytes.fromhex("1abec00abec9")
