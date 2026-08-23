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
    linked_bytes,
    rom_window,
    sm83_flags_to_z80,
    symbol_location,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF
MARKER = 0x1234
EXPECTED_BODY = bytes.fromhex("11805a210088018004c38618")


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
    call_registers: claripy.ast.BV
    marker: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class CopyVideoDataDoubleSummary(angr.SimProcedure):
    """Arbitrary transition supplied by proven CopyVideoDataDouble."""

    def run(self) -> None:  # type: ignore[override]
        call = assembly_registers(self.state)
        self.state.globals["call_registers"] = claripy.Concat(
            *(call[register] for register in REGISTERS)
        )
        for register in REGISTERS:
            value = self.state.globals[f"transfer_{register}"]
            if register == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, register, value)
        self.state.memory.store(MARKER, self.state.globals["transfer_marker"])
        self.jump(DONE)


class NativeCopyVideoDataDoubleSummary(angr.SimProcedure):
    """Native-ABI form of the same independently proven transition."""

    def run(
        self, registers: claripy.ast.BV, memory: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        self.state.globals["call_registers"] = self.state.memory.load(registers, 8)
        for offset, register in enumerate(REGISTERS):
            self.state.memory.store(
                registers + offset, self.state.globals[f"transfer_{register}"]
            )
        self.state.memory.store(
            memory + MARKER, self.state.globals["transfer_marker"]
        )


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["marker"] = claripy.BVS(f"{prefix}_marker", 8)
    for register in REGISTERS:
        values[f"transfer_{register}"] = (
            claripy.Concat(
                claripy.BVS(f"{prefix}_transfer_flags", 4), claripy.BVV(0, 4)
            )
            if register == "f"
            else claripy.BVS(f"{prefix}_transfer_{register}", 8)
        )
    values["transfer_marker"] = claripy.BVS(f"{prefix}_transfer_marker", 8)
    return values


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "LoadFontTilePatterns.on")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY
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
    project.hook(
        location.address + 9, CopyVideoDataDoubleSummary(), length=3
    )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.globals["call_registers"] = claripy.BVV(0, 64)
    for register in REGISTERS:
        state.globals[f"transfer_{register}"] = values[f"transfer_{register}"]
    state.globals["transfer_marker"] = values["transfer_marker"]
    state.memory.store(MARKER, values["marker"])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE)
    return [
        Endpoint(
            **assembly_registers(end),
            call_registers=end.globals["call_registers"],
            marker=end.memory.load(MARKER, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_load_font_tile_patterns_on")
    transfer = project.loader.find_symbol("port_copy_video_data_double")
    assert function is not None and transfer is not None
    project.hook(transfer.rebased_addr, NativeCopyVideoDataDoubleSummary())
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    state.globals["call_registers"] = claripy.BVV(0, 64)
    for register in REGISTERS:
        state.globals[f"transfer_{register}"] = values[f"transfer_{register}"]
    state.globals["transfer_marker"] = values["transfer_marker"]
    state.memory.store(NATIVE_MEMORY + MARKER, values["marker"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            call_registers=end.globals["call_registers"],
            marker=end.memory.load(NATIVE_MEMORY + MARKER, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_load_font_tile_patterns_on_pathwise_equivalence() -> None:
    values = _inputs("load_font_tile_patterns_on")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "call_registers", "marker"),
    )
