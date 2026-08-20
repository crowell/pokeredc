from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import set_assembly_registers, store_native_registers, symbolic_registers
from verification.harness.rom import rom_window, symbol_location

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x110000
DONE = 0xEFFF
AUTO = 0xFFBA
LOADED_BANK = 0xFFB8
BANK_TEMP = 0xFF8B
ROMB = 0xFF00
COPY_SOURCE = 0xFFCC
COPY_DEST = 0xFFCE
COPY_SIZE = 0xFFCB
ADDRESSES = (AUTO, LOADED_BANK, BANK_TEMP, ROMB, COPY_SOURCE, COPY_SOURCE + 1, COPY_DEST, COPY_DEST + 1, COPY_SIZE)
FIELDS = ("auto", "loaded_bank", "bank_temp", "romb", "copy_source", "copy_source_high", "copy_dest", "copy_dest_high", "copy_size")


@dataclass(frozen=True)
class Endpoint:
    memory: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class CopyVideoDoubleSummary(angr.SimProcedure):
    def run(self) -> None:
        saved_auto = self.state.globals["auto"]
        saved_bank = self.state.globals["loaded_bank"]
        self.state.globals["auto"] = saved_auto
        self.state.globals["loaded_bank"] = saved_bank
        self.state.globals["bank_temp"] = saved_bank
        self.state.globals["romb"] = saved_bank
        self.state.globals["copy_source"] = self.state.regs.e
        self.state.globals["copy_source_high"] = self.state.regs.d
        self.state.globals["copy_dest"] = self.state.regs.l
        self.state.globals["copy_dest_high"] = self.state.regs.h
        self.state.globals["copy_size"] = claripy.BVV(0, 8)
        self.jump(DONE)


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for field in FIELDS:
        values[field] = claripy.BVS(f"{prefix}_{field}", 8)
    values["c"] = claripy.BVV(0, 8)
    return values


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "CopyVideoDataDouble")
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
    project.hook(location.address, CopyVideoDoubleSummary(), length=1)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    for address, field in zip(ADDRESSES, FIELDS):
        state.memory.store(address, values[field])
        state.globals[field] = values[field]
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored
    return [
        Endpoint(
            memory=claripy.Concat(*(end.globals[field] for field in FIELDS)),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_copy_video_data_double")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    for address, field in zip(ADDRESSES, FIELDS):
        state.memory.store(NATIVE_MEMORY + address, values[field])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            memory=claripy.Concat(*(end.memory.load(NATIVE_MEMORY + address, 1) for address in ADDRESSES)),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_copy_video_data_double_zero_count_pathwise_equivalence() -> None:
    values = _inputs("copy_video_double_zero")
    assert_pathwise_equivalent(_assembly(values), _native(values), ("memory",))
