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

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
DONE = 0xEFFF


class DelayFrames80(angr.SimProcedure):
    """Terminal transition plus count of the proven DelayFrames loop."""

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
    frames_waited: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _assembly(values: dict[str, claripy.ast.BV]) -> Endpoint:
    location = symbol_location(SYMBOLS, "Trade_Delay80")
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
    project.hook(base + 2, DelayFrames80(), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.globals["frames_waited"] = values["frames_waited"]
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored
    assert len(manager.found) == 1
    end = manager.found[0]
    return Endpoint(
        **assembly_registers(end),
        frames_waited=end.globals["frames_waited"],
        constraints=tuple(end.solver.constraints),
    )


def _native(values: dict[str, claripy.ast.BV]) -> Endpoint:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_trade_delay80")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, values["frames_waited"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    end = manager.deadended[0]
    return Endpoint(
        **native_registers(end, NATIVE_STATE),
        frames_waited=end.memory.load(NATIVE_STATE + 8, 1),
        constraints=tuple(end.solver.constraints),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_trade_delay80_pathwise_equivalence() -> None:
    values = symbolic_registers("trade_delay80")
    values["frames_waited"] = claripy.BVS("trade_delay80_frames", 8)
    assert_pathwise_equivalent(
        [_assembly(values)],
        [_native(values)],
        (*REGISTERS, "frames_waited"),
    )
