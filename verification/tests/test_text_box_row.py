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
from verification.harness.rom import linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import Sm83DecRegister


ROOT = Path(__file__).resolve().parents[2]
VERIFY = ROOT / "verification"
NATIVE_ELF = VERIFY / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
LOOP_BOUNDARY = 0xEFFE
RETURN_BOUNDARY = 0xEFFF
NATIVE_STATE = 0x100000


class IncrementHlOnce(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        if self.state.globals.get("row_step_entered", False):
            self.jump(LOOP_BOUNDARY)
            return
        self.state.globals["row_step_entered"] = True
        self.state.regs.hl = self.state.regs.hl + 1
        self.jump(self._next_address)


class ReturnBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(RETURN_BOUNDARY)


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
    value: claripy.ast.BV
    continuation: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _assembly(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "TrainerInfo_NextTextBoxRow")
    project = angr.Project(
        rom_window(ROM, location.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": location.address + 3,
        },
    )
    project.hook(
        location.address + 3,
        IncrementHlOnce(location.address + 4),
        length=1,
    )
    project.hook(
        location.address + 4,
        Sm83DecRegister("a", location.address + 5),
        length=1,
    )
    project.hook(location.address + 7, ReturnBoundary(), length=1)
    state = project.factory.blank_state(addr=location.address + 3)
    set_assembly_registers(state, inputs)
    manager = project.factory.simulation_manager(state)
    manager.stashes["found"] = []
    while manager.active:
        manager.move(
            from_stash="active",
            to_stash="found",
            filter_func=lambda candidate: candidate.addr
            in {LOOP_BOUNDARY, RETURN_BOUNDARY},
        )
        if manager.active:
            manager.step()
    assert not manager.errored
    assert {end.addr for end in manager.found} == {LOOP_BOUNDARY, RETURN_BOUNDARY}
    return [
        Endpoint(
            **assembly_registers(end),
            value=inputs["value"],
            continuation=claripy.BVV(1 if end.addr == LOOP_BOUNDARY else 0, 8),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_trainer_info_next_text_box_row_step")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["value"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            value=end.memory.load(NATIVE_STATE + 8, 1),
            continuation=claripy.If(
                end.regs.rax[7:0] == 0,
                claripy.BVV(1, 8),
                claripy.BVV(0, 8),
            ),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_trainer_info_next_text_box_row_one_step_inductive_equivalence() -> None:
    inputs = symbolic_registers("trainer_info_next_text_box_row_step")
    inputs["value"] = claripy.BVS("trainer_info_next_text_box_row_memory", 8)
    assert_pathwise_equivalent(
        _assembly(inputs),
        _native(inputs),
        (*REGISTERS, "value", "continuation"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_trainer_info_next_text_box_row_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "TrainerInfo_NextTextBoxRow")
    value_address = symbol_location(SYMBOLS, "wTrainerInfoTextBoxNextRowOffset").address
    assert linked_bytes(ROM, location, 8) == bytes(
        (
            0xFA, value_address & 0xFF, value_address >> 8,
            0x23, 0x3D, 0x20, 0xFC, 0xC9,
        )
    )
