from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
    REGISTERS, assembly_registers, native_registers,
    set_assembly_registers, store_native_registers, symbolic_registers,
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
EXPECTED = bytes.fromhex("f0b8f5fa5ed3cdbc12cd6100cde809cd7b00f1e0b8ea0020c9")
FIELDS = (
    "cur_map", "map_rom_bank", "loaded_rom_bank", "mapper_bank",
    "home_temp", "home_saved_rom_bank", "interrupt_flags",
    "interrupt_enable", "lcd_control", "requested_bank",
    "tileset_gfx_low", "tileset_gfx_high", "tileset_bank",
)
GROUPS = {
    "switch": ("map_rom_bank", "loaded_rom_bank", "mapper_bank", "home_temp", "home_saved_rom_bank"),
    "disable": ("interrupt_flags", "interrupt_enable", "lcd_control"),
    "load": ("requested_bank", "loaded_rom_bank", "mapper_bank"),
    "enable": ("lcd_control",),
}


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
    calls: claripy.ast.BV
    marker: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class LoadGlobalA(angr.SimProcedure):
    def __init__(self, field: str, next_address: int):
        super().__init__(); self.field = field; self.next_address = next_address
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals[self.field]; self.jump(self.next_address)


class SaveAf(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__(); self.next_address = next_address
    def run(self) -> None:  # type: ignore[override]
        self.state.globals["saved_a"] = self.state.regs.a
        self.state.globals["saved_f"] = assembly_registers(self.state)["f"]
        self.jump(self.next_address)


class RestoreAf(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__(); self.next_address = next_address
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals["saved_a"]
        self.state.regs.f = sm83_flags_to_z80(self.state.globals["saved_f"])
        self.jump(self.next_address)


def _call_fields(kind: str) -> tuple[str, ...]:
    if kind == "load":
        return ("requested_bank", "loaded_rom_bank", "mapper_bank", "tileset_gfx_low", "tileset_gfx_high", "tileset_bank")
    return GROUPS[kind]


class CallSummary(angr.SimProcedure):
    def __init__(self, kind: str, next_address: int):
        super().__init__(); self.kind = kind; self.next_address = next_address
    def run(self) -> None:  # type: ignore[override]
        regs = assembly_registers(self.state)
        self.state.globals[f"call_{self.kind}"] = claripy.Concat(
            *(regs[r] for r in REGISTERS),
            *(self.state.globals[f] for f in _call_fields(self.kind)),
        )
        for r in REGISTERS:
            value = self.state.globals[f"{self.kind}_out_{r}"]
            setattr(self.state.regs, r, sm83_flags_to_z80(value) if r == "f" else value)
        for field in GROUPS[self.kind]:
            self.state.globals[field] = self.state.globals[f"{self.kind}_out_{field}"]
        if self.kind == "load":
            self.state.memory.store(MARKER, self.state.globals["load_out_marker"])
        self.jump(self.next_address)


class NativeCallSummary(angr.SimProcedure):
    def __init__(self, kind: str): super().__init__(); self.kind = kind
    def run(self, state: claripy.ast.BV, memory: claripy.ast.BV | None = None) -> None:  # type: ignore[override]
        fields = _call_fields(self.kind)
        self.state.globals[f"call_{self.kind}"] = claripy.Concat(
            self.state.memory.load(state, 8),
            *(self.state.memory.load(state + 8 + i, 1) for i in range(len(fields))),
        )
        for i, r in enumerate(REGISTERS):
            self.state.memory.store(state + i, self.state.globals[f"{self.kind}_out_{r}"])
        for i, field in enumerate(GROUPS[self.kind]):
            self.state.memory.store(state + 8 + i, self.state.globals[f"{self.kind}_out_{field}"])
        if self.kind == "load":
            if memory is None:
                memory = self.state.regs.rsi
            self.state.memory.store(memory + MARKER, self.state.globals["load_out_marker"])


class StoreBank(angr.SimProcedure):
    def __init__(self, field: str, next_address: int):
        super().__init__(); self.field = field; self.next_address = next_address
    def run(self) -> None:  # type: ignore[override]
        self.state.globals[self.field] = self.state.regs.a; self.jump(self.next_address)


class Finish(angr.SimProcedure):
    def run(self) -> None: self.jump(DONE)  # type: ignore[override]


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for field in FIELDS: values[field] = claripy.BVS(f"{prefix}_{field}", 8)
    for kind, fields in GROUPS.items():
        for r in REGISTERS:
            values[f"{kind}_out_{r}"] = (
                claripy.Concat(claripy.BVS(f"{prefix}_{kind}_out_flags", 4), claripy.BVV(0, 4))
                if r == "f" else claripy.BVS(f"{prefix}_{kind}_out_{r}", 8)
            )
        for field in fields:
            values[f"{kind}_out_{field}"] = claripy.BVS(f"{prefix}_{kind}_out_{field}", 8)
    values["marker"] = claripy.BVS(f"{prefix}_marker", 8)
    values["load_out_marker"] = claripy.BVS(f"{prefix}_load_out_marker", 8)
    return values


def _setup(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    for field in FIELDS: state.globals[field] = values[field]
    for kind, fields in GROUPS.items():
        for r in REGISTERS: state.globals[f"{kind}_out_{r}"] = values[f"{kind}_out_{r}"]
        for field in fields: state.globals[f"{kind}_out_{field}"] = values[f"{kind}_out_{field}"]
        state.globals[f"call_{kind}"] = claripy.BVV(0, 8 * (8 + len(_call_fields(kind))))
    state.globals["load_out_marker"] = values["load_out_marker"]


def _calls(end: angr.SimState) -> claripy.ast.BV:
    return claripy.Concat(*(end.globals[f"call_{kind}"] for kind in ("switch", "disable", "load", "enable")))


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "ReloadTilesetTilePatterns")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    project = angr.Project(rom_window(ROM, location.bank), auto_load_libs=False, rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0, "entry_point": location.address})
    base = location.address
    project.hook(base, LoadGlobalA("loaded_rom_bank", base + 2), length=2)
    project.hook(base + 2, SaveAf(base + 3), length=1)
    project.hook(base + 3, LoadGlobalA("cur_map", base + 6), length=3)
    project.hook(base + 6, CallSummary("switch", base + 9), length=3)
    project.hook(base + 9, CallSummary("disable", base + 12), length=3)
    project.hook(base + 12, CallSummary("load", base + 15), length=3)
    project.hook(base + 15, CallSummary("enable", base + 18), length=3)
    project.hook(base + 18, RestoreAf(base + 19), length=1)
    project.hook(base + 19, StoreBank("loaded_rom_bank", base + 21), length=2)
    project.hook(base + 21, StoreBank("mapper_bank", base + 24), length=3)
    project.hook(base + 24, Finish(), length=1)
    state = project.factory.blank_state(addr=base); set_assembly_registers(state, values); _setup(state, values)
    state.memory.store(MARKER, values["marker"])
    manager = project.factory.simulation_manager(state); manager.explore(find=DONE); assert not manager.errored
    return [Endpoint(**assembly_registers(end), state=claripy.Concat(*(end.globals[f] for f in FIELDS)), calls=_calls(end),
        marker=end.memory.load(MARKER, 1), constraints=tuple(end.solver.constraints)) for end in manager.found]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_reload_tileset_tile_patterns")
    symbols = {kind: project.loader.find_symbol(name) for kind, name in {
        "switch": "port_switch_to_map_rom_bank", "disable": "port_disable_lcd",
        "load": "port_load_tileset_tile_pattern_data", "enable": "port_enable_lcd"}.items()}
    assert function is not None and all(symbols.values())
    for kind, symbol in symbols.items(): project.hook(symbol.rebased_addr, NativeCallSummary(kind))  # type: ignore[union-attr]
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    for i, field in enumerate(FIELDS): state.memory.store(NATIVE_STATE + 8 + i, values[field])
    _setup(state, values); state.memory.store(NATIVE_MEMORY + MARKER, values["marker"])
    manager = project.factory.simulation_manager(state); manager.run(); assert not manager.errored
    return [Endpoint(**native_registers(end, NATIVE_STATE), state=end.memory.load(NATIVE_STATE + 8, len(FIELDS)), calls=_calls(end),
        marker=end.memory.load(NATIVE_MEMORY + MARKER, 1), constraints=tuple(end.solver.constraints)) for end in manager.deadended]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_reload_tileset_tile_patterns_pathwise_equivalence() -> None:
    values = _inputs("reload_tileset_tile_patterns")
    assert_pathwise_equivalent(_assembly(values), _native(values), (*REGISTERS, "state", "calls", "marker"))
