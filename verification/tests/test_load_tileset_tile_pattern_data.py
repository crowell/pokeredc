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
from verification.harness.rom import linked_bytes, rom_window, sm83_flags_to_z80, symbol_location

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF
MARKER = 0x1234
FIELDS = (
    "requested_bank",
    "loaded_bank",
    "rom_bank",
    "tileset_gfx_low",
    "tileset_gfx_high",
    "tileset_bank",
)
EXPECTED_BODY = bytes.fromhex("fa2ed56ffa2fd567110090010006fa2bd5c3f717")


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
    call_registers: claripy.ast.BV
    marker: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class LoadField(angr.SimProcedure):
    def __init__(self, field: str, continuation: int) -> None:
        super().__init__()
        self.field = field
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals[self.field]
        self.jump(self.continuation)


class FarCopyData2Summary(angr.SimProcedure):
    """Arbitrary transition supplied by the independently proven callee."""

    def run(self) -> None:  # type: ignore[override]
        call_registers = assembly_registers(self.state)
        self.state.globals["call_registers"] = claripy.Concat(
            *(call_registers[register] for register in REGISTERS)
        )
        for register in REGISTERS:
            value = self.state.globals[f"far_{register}"]
            if register == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, register, value)
        for field in ("requested_bank", "loaded_bank", "rom_bank"):
            self.state.globals[field] = self.state.globals[f"far_{field}"]
        self.state.memory.store(MARKER, self.state.globals["far_marker"])
        self.jump(DONE)


class NativeFarCopyData2Summary(angr.SimProcedure):
    def run(
        self, state: claripy.ast.BV, memory: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        self.state.globals["call_registers"] = self.state.memory.load(state, 8)
        for offset, register in enumerate(REGISTERS):
            self.state.memory.store(state + offset, self.state.globals[f"far_{register}"])
        for offset, field in enumerate(
            ("requested_bank", "loaded_bank", "rom_bank"), 8
        ):
            self.state.memory.store(state + offset, self.state.globals[f"far_{field}"])
        self.state.memory.store(memory + MARKER, self.state.globals["far_marker"])


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for field in FIELDS:
        values[field] = claripy.BVS(f"{prefix}_{field}", 8)
    for register in REGISTERS:
        values[f"far_{register}"] = (
            claripy.Concat(
                claripy.BVS(f"{prefix}_far_flags", 4), claripy.BVV(0, 4)
            )
            if register == "f"
            else claripy.BVS(f"{prefix}_far_{register}", 8)
        )
    for field in ("requested_bank", "loaded_bank", "rom_bank"):
        values[f"far_{field}"] = claripy.BVS(f"{prefix}_far_{field}", 8)
    values["marker"] = claripy.BVS(f"{prefix}_marker", 8)
    values["far_marker"] = claripy.BVS(f"{prefix}_far_marker", 8)
    return values


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "LoadTilesetTilePatternData")
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
    base = location.address
    project.hook(base, LoadField("tileset_gfx_low", base + 3), length=3)
    project.hook(base + 4, LoadField("tileset_gfx_high", base + 7), length=3)
    project.hook(base + 14, LoadField("tileset_bank", base + 17), length=3)
    project.hook(base + 17, FarCopyData2Summary(), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    for field in FIELDS:
        state.globals[field] = values[field]
    for key, value in values.items():
        if key.startswith("far_"):
            state.globals[key] = value
    state.globals["call_registers"] = claripy.BVV(0, 64)
    state.memory.store(MARKER, values["marker"])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored and len(manager.found) == 1
    return [
        Endpoint(
            **assembly_registers(end),
            memory=claripy.Concat(*(end.globals[field] for field in FIELDS)),
            call_registers=end.globals["call_registers"],
            marker=end.memory.load(MARKER, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_load_tileset_tile_pattern_data")
    far_copy = project.loader.find_symbol("port_far_copy_data2")
    assert function is not None and far_copy is not None
    project.hook(far_copy.rebased_addr, NativeFarCopyData2Summary())
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    for offset, field in enumerate(FIELDS, 8):
        state.memory.store(NATIVE_STATE + offset, values[field])
    for key, value in values.items():
        if key.startswith("far_"):
            state.globals[key] = value
    state.globals["call_registers"] = claripy.BVV(0, 64)
    state.memory.store(NATIVE_MEMORY + MARKER, values["marker"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=end.memory.load(NATIVE_STATE + 8, len(FIELDS)),
            call_registers=end.globals["call_registers"],
            marker=end.memory.load(NATIVE_MEMORY + MARKER, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_load_tileset_tile_pattern_data_pathwise_equivalence() -> None:
    values = _inputs("load_tileset_tile_pattern_data")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "memory", "call_registers", "marker"),
    )
