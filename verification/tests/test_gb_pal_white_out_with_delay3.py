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
from verification.harness.sm83_shims import Sm83DecRegister, Sm83StoreAHighImmediate


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
GB_STACK = 0xD000
DONE = 0xEFFF


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
    background_palette: claripy.ast.BV
    object_palette0: claripy.ast.BV
    object_palette1: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class DelayFrameTerminal(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x50, 8)
        self.jump(self.next_address)


class ReturnBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(DONE)


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    entry = symbol_location(SYMBOLS, "GBPalWhiteOutWithDelay3")
    white_out = symbol_location(SYMBOLS, "GBPalWhiteOut").address
    delay_frames = symbol_location(SYMBOLS, "DelayFrames").address
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
    project.hook(
        white_out + 1,
        Sm83StoreAHighImmediate(0x47, white_out + 3),
        length=2,
    )
    project.hook(
        white_out + 3,
        Sm83StoreAHighImmediate(0x48, white_out + 5),
        length=2,
    )
    project.hook(
        white_out + 5,
        Sm83StoreAHighImmediate(0x49, white_out + 7),
        length=2,
    )
    project.hook(
        delay_frames,
        DelayFrameTerminal(delay_frames + 3),
        length=3,
    )
    project.hook(
        delay_frames + 3,
        Sm83DecRegister("c", delay_frames + 4),
        length=1,
    )
    project.hook(delay_frames + 6, ReturnBoundary(), length=1)

    state = project.factory.blank_state(addr=entry.address)
    set_assembly_registers(state, values)
    state.memory.store(0xFF47, values["background_palette"])
    state.memory.store(0xFF48, values["object_palette0"])
    state.memory.store(0xFF49, values["object_palette1"])
    state.regs.sp = GB_STACK
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE)
    assert not manager.errored
    return [
        Endpoint(
            **assembly_registers(end),
            background_palette=end.memory.load(0xFF47, 1),
            object_palette0=end.memory.load(0xFF48, 1),
            object_palette1=end.memory.load(0xFF49, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_gb_pal_white_out_with_delay3")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, values["background_palette"])
    state.memory.store(NATIVE_STATE + 9, values["object_palette0"])
    state.memory.store(NATIVE_STATE + 10, values["object_palette1"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            background_palette=end.memory.load(NATIVE_STATE + 8, 1),
            object_palette0=end.memory.load(NATIVE_STATE + 9, 1),
            object_palette1=end.memory.load(NATIVE_STATE + 10, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run red")
def test_gb_pal_white_out_with_delay3_pathwise_equivalence() -> None:
    values = symbolic_registers("gb_pal_white_out_with_delay3")
    values["background_palette"] = claripy.BVS("white_delay_bgp", 8)
    values["object_palette0"] = claripy.BVS("white_delay_obp0", 8)
    values["object_palette1"] = claripy.BVS("white_delay_obp1", 8)
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "background_palette", "object_palette0", "object_palette1"),
    )
