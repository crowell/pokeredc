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
from verification.harness.sm83_shims import Sm83BitRegister
from verification.tests.test_load_text_box_tile_patterns import LoadLcdc

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF
MARKER = 0x1234
EXPECTED = bytes.fromhex(
    "f040cb7f200e21805a1100880100043e04c32b1811805a210088018004c38618"
)
FIELDS = (
    "rom_bank_temp",
    "loaded_rom_bank",
    "mapper_bank",
    "saved_a",
    "saved_f",
    "memory0",
    "memory1",
    "memory2",
    "lcd_control",
)


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
    state: claripy.ast.BV
    call_registers: claripy.ast.BV
    kind: claripy.ast.BV
    marker: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class TransferSummary(angr.SimProcedure):
    def __init__(self, kind: int, banked: bool):
        super().__init__()
        self.kind = kind
        self.banked = banked

    def run(self) -> None:  # type: ignore[override]
        call = assembly_registers(self.state)
        self.state.globals["call_registers"] = claripy.Concat(
            *(call[register] for register in REGISTERS)
        )
        self.state.globals["kind"] = claripy.BVV(self.kind, 8)
        for register in REGISTERS:
            value = self.state.globals[f"callee_{register}"]
            if register == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, register, value)
        if self.banked:
            for field in FIELDS[:-1]:
                self.state.globals[field] = self.state.globals[f"callee_{field}"]
        self.state.memory.store(MARKER, self.state.globals["callee_marker"])
        self.jump(DONE)


class NativeTransferSummary(angr.SimProcedure):
    def __init__(self, kind: int, banked: bool):
        super().__init__()
        self.kind = kind
        self.banked = banked

    def run(
        self, state: claripy.ast.BV, memory: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        self.state.globals["call_registers"] = self.state.memory.load(state, 8)
        self.state.globals["kind"] = claripy.BVV(self.kind, 8)
        for offset, register in enumerate(REGISTERS):
            self.state.memory.store(
                state + offset, self.state.globals[f"callee_{register}"]
            )
        if self.banked:
            for offset, field in enumerate(FIELDS[:-1], 8):
                self.state.memory.store(
                    state + offset, self.state.globals[f"callee_{field}"]
                )
        self.state.memory.store(
            memory + MARKER, self.state.globals["callee_marker"]
        )


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for field in FIELDS:
        values[field] = claripy.BVS(f"{prefix}_{field}", 8)
    for register in REGISTERS:
        values[f"callee_{register}"] = (
            claripy.Concat(
                claripy.BVS(f"{prefix}_callee_flags", 4), claripy.BVV(0, 4)
            )
            if register == "f"
            else claripy.BVS(f"{prefix}_callee_{register}", 8)
        )
    for field in FIELDS[:-1]:
        values[f"callee_{field}"] = claripy.BVS(
            f"{prefix}_callee_{field}", 8
        )
    values["marker"] = claripy.BVS(f"{prefix}_marker", 8)
    values["callee_marker"] = claripy.BVS(f"{prefix}_callee_marker", 8)
    return values


def _setup_globals(
    state: angr.SimState, values: dict[str, claripy.ast.BV]
) -> None:
    for field in FIELDS:
        state.globals[field] = values[field]
    for register in REGISTERS:
        state.globals[f"callee_{register}"] = values[f"callee_{register}"]
    for field in FIELDS[:-1]:
        state.globals[f"callee_{field}"] = values[f"callee_{field}"]
    state.globals["callee_marker"] = values["callee_marker"]
    state.globals["call_registers"] = claripy.BVV(0, 64)
    state.globals["kind"] = claripy.BVV(0, 8)


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "LoadFontTilePatterns")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
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
    project.hook(base, LoadLcdc(base + 2), length=2)
    project.hook(base + 2, Sm83BitRegister(7, "a", base + 4), length=2)
    project.hook(base + 17, TransferSummary(1, True), length=3)
    project.hook(base + 20, TransferSummary(2, False), length=12)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _setup_globals(state, values)
    state.memory.store(MARKER, values["marker"])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=10)
    return [
        Endpoint(
            **assembly_registers(end),
            state=claripy.Concat(*(end.globals[field] for field in FIELDS)),
            call_registers=end.globals["call_registers"],
            kind=end.globals["kind"],
            marker=end.memory.load(MARKER, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_load_font_tile_patterns")
    far_copy = project.loader.find_symbol("port_far_copy_data_double")
    on_path = project.loader.find_symbol("port_load_font_tile_patterns_on")
    assert function is not None and far_copy is not None and on_path is not None
    project.hook(far_copy.rebased_addr, NativeTransferSummary(1, True))
    project.hook(on_path.rebased_addr, NativeTransferSummary(2, False))
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    for offset, field in enumerate(FIELDS, 8):
        state.memory.store(NATIVE_STATE + offset, values[field])
    _setup_globals(state, values)
    state.memory.store(NATIVE_MEMORY + MARKER, values["marker"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            state=end.memory.load(NATIVE_STATE + 8, len(FIELDS)),
            call_registers=end.globals["call_registers"],
            kind=end.globals["kind"],
            marker=end.memory.load(NATIVE_MEMORY + MARKER, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_load_font_tile_patterns_pathwise_equivalence() -> None:
    values = _inputs("load_font_tile_patterns")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "state", "call_registers", "kind", "marker"),
    )
