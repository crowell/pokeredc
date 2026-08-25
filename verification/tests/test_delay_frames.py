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
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_OBSERVATION = 0x100100
LOOP = 0xEFFE
RETURN = 0xEFFF


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
    vblank_occurred: claripy.ast.BV
    continuation: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class DelayFrameThenLoopBoundary(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        if self.state.globals.get("entered", False):
            self.jump(LOOP)
            return
        self.state.globals["entered"] = True
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x50, 8)
        self.state.globals["vblank_occurred"] = claripy.BVV(0, 8)
        self.jump(self.next_address)


class ReturnBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(RETURN)


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "DelayFrames")
    start = location.address
    project = angr.Project(
        rom_window(ROM, location.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": start,
        },
    )
    # Compose with the separately proved DelayFrame terminal transition, then
    # execute the real DEC/JR recurrence.  Re-entry marks the loop endpoint.
    project.hook(start, DelayFrameThenLoopBoundary(start + 3), length=3)
    project.hook(start + 3, Sm83DecRegister("c", start + 4), length=1)
    project.hook(start + 6, ReturnBoundary(), length=1)
    state = project.factory.blank_state(addr=start)
    set_assembly_registers(state, values)
    state.globals["vblank_occurred"] = values["vblank_occurred"]
    manager = project.factory.simulation_manager(state)
    manager.stashes["found"] = []
    while manager.active:
        manager.move(
            from_stash="active",
            to_stash="found",
            filter_func=lambda end: end.addr in {LOOP, RETURN},
        )
        if manager.active:
            manager.step()
    assert not manager.errored
    return [
        Endpoint(
            **assembly_registers(end),
            vblank_occurred=end.globals["vblank_occurred"],
            continuation=claripy.BVV(1 if end.addr == LOOP else 0, 8),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_delay_frames_step")
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_OBSERVATION
    )
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, values["vblank_occurred"])
    state.memory.store(NATIVE_STATE + 9, values["observed_vblank"])
    state.memory.store(NATIVE_OBSERVATION, claripy.BVV(0, 8))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            vblank_occurred=end.memory.load(NATIVE_STATE + 8, 1),
            continuation=end.regs.rax[7:0],
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run red")
def test_delay_frames_one_step_pathwise_equivalence() -> None:
    location = symbol_location(SYMBOLS, "DelayFrames")
    assert linked_bytes(ROM, location, 7) == bytes.fromhex("cdaf200d20fac9")
    values = symbolic_registers("delay_frames_step")
    values["vblank_occurred"] = claripy.BVS("delay_frames_vblank", 8)
    values["observed_vblank"] = claripy.BVS("delay_frames_observed", 8)
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "vblank_occurred", "continuation"),
    )
