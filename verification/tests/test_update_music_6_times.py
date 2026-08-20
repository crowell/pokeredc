from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
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
NATIVE_MEMORY = 0x110000
DONE = 0xEFFF
AUDIO_BANK = 0xC0EF


@dataclass(frozen=True)
class Endpoint:
    b: claripy.ast.BV
    c: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class UpdateMusicSummary(angr.SimProcedure):
    def run(self) -> None:
        bank = self.state.globals["audio_bank"]
        self.state.regs.a = bank
        self.state.regs.b = bank
        self.state.regs.c = claripy.BVV(0, 8)
        self.state.regs.h = claripy.If(
            bank == 2, claripy.BVV(0x40, 8), claripy.If(bank == 8, claripy.BVV(0x58, 8), claripy.BVV(0x77, 8))
        )
        self.state.regs.l = claripy.If(
            bank == 2, claripy.BVV(0x03, 8), claripy.If(bank == 8, claripy.BVV(0x79, 8), claripy.BVV(0x51, 8))
        )
        self.jump(DONE)


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["audio_bank"] = claripy.BVS(f"{prefix}_audio_bank", 8)
    return values


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "UpdateMusic6Times")
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
    project.hook(location.address, UpdateMusicSummary(), length=1)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.globals["audio_bank"] = values["audio_bank"]
    state.memory.store(AUDIO_BANK, values["audio_bank"])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored
    return [
        Endpoint(
            b=end.regs.b,
            c=end.regs.c,
            h=end.regs.h,
            l=end.regs.l,
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_update_music_6_times")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_MEMORY + AUDIO_BANK, values["audio_bank"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            b=native_registers(end, NATIVE_STATE)["b"],
            c=native_registers(end, NATIVE_STATE)["c"],
            h=native_registers(end, NATIVE_STATE)["h"],
            l=native_registers(end, NATIVE_STATE)["l"],
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_update_music_6_times_pathwise_equivalence() -> None:
    values = _inputs("update_music6")
    assert_pathwise_equivalent(_assembly(values), _native(values), ("b", "c", "h", "l"))
