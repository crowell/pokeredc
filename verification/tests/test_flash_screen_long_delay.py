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
from verification.harness.rom import rom_window, symbol_location
from verification.harness.sm83_shims import Sm83CpImmediate

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
DONE = 0xEFFF


class LoadCounter(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals["counter"]
        self.jump(self._next_address)


class DelayFrames(angr.SimProcedure):
    """Terminal transition plus selected count of the proven delay loop."""

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["frames_waited"] = self.state.regs.c
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.c = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x42, 8)
        self.jump(DONE)


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
    counter: claripy.ast.BV
    frames_waited: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "FlashScreenLongDelay")
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
    project.hook(base, LoadCounter(base + 3), length=3)
    project.hook(base + 3, Sm83CpImmediate(4, base + 5), length=2)
    project.hook(base + 9, Sm83CpImmediate(3, base + 11), length=2)
    project.hook(base + 15, Sm83CpImmediate(2, base + 17), length=2)
    project.hook(base + 19, DelayFrames(), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.globals["counter"] = values["counter"]
    state.globals["frames_waited"] = values["frames_waited"]
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=3)
    assert not manager.errored
    assert len(manager.found) == 3
    return [
        Endpoint(
            **assembly_registers(end),
            counter=end.globals["counter"],
            frames_waited=end.globals["frames_waited"],
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_flash_screen_long_delay")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, values["counter"])
    state.memory.store(NATIVE_STATE + 9, values["frames_waited"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            counter=end.memory.load(NATIVE_STATE + 8, 1),
            frames_waited=end.memory.load(NATIVE_STATE + 9, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_flash_screen_long_delay_pathwise_equivalence() -> None:
    values = symbolic_registers("flash_screen_long_delay")
    values["counter"] = claripy.BVS("flash_screen_long_counter", 8)
    values["frames_waited"] = claripy.BVS("flash_screen_long_frames", 8)
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "counter", "frames_waited"),
    )
