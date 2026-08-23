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
EXPECTED = bytes.fromhex(
    "f0b8f5fa5ed3cdbc12cd6100cda036cdaa0ccde809cd7b00f1e0b8ea0020c9"
)

FIELDS = (
    "cur_map",
    "map_rom_bank",
    "loaded_rom_bank",
    "mapper_bank",
    "home_temp",
    "home_saved_rom_bank",
    "interrupt_flags",
    "interrupt_enable",
    "lcd_control",
    "requested_bank",
    "tileset_gfx_low",
    "tileset_gfx_high",
    "tileset_bank",
    "map_view_pointer_low",
    "map_view_pointer_high",
    "map_width",
    "y_block_coord",
    "x_block_coord",
    "tileset_blocks_low",
    "tileset_blocks_high",
    "view_saved_a",
    "view_saved_f",
    "view_row_d",
    "view_row_e",
    "view_row_h",
    "view_row_l",
    "view_fetched_block",
    "view_fetched_copy",
    "view_written_copy",
    "view_write_h",
    "view_write_l",
)

VIEW_FIELDS = (
    "tileset_bank",
    "loaded_rom_bank",
    "mapper_bank",
    "map_view_pointer_low",
    "map_view_pointer_high",
    "map_width",
    "y_block_coord",
    "x_block_coord",
    "tileset_blocks_low",
    "tileset_blocks_high",
    "view_saved_a",
    "view_saved_f",
    "view_row_d",
    "view_row_e",
    "view_row_h",
    "view_row_l",
    "view_fetched_block",
    "view_fetched_copy",
    "view_written_copy",
    "view_write_h",
    "view_write_l",
)

CALL_FIELDS = {
    "switch": (
        "map_rom_bank",
        "loaded_rom_bank",
        "mapper_bank",
        "home_temp",
        "home_saved_rom_bank",
    ),
    "disable": ("interrupt_flags", "interrupt_enable", "lcd_control"),
    "text": (
        "requested_bank",
        "loaded_rom_bank",
        "mapper_bank",
        "lcd_control",
    ),
    "view": VIEW_FIELDS,
    "tiles": (
        "requested_bank",
        "loaded_rom_bank",
        "mapper_bank",
        "tileset_gfx_low",
        "tileset_gfx_high",
        "tileset_bank",
    ),
    "enable": ("lcd_control", "enable_object0", "enable_object1"),
}

OUTPUT_FIELDS = {
    "switch": CALL_FIELDS["switch"],
    "disable": CALL_FIELDS["disable"],
    "text": CALL_FIELDS["text"],
    "view": VIEW_FIELDS,
    "tiles": CALL_FIELDS["tiles"],
    "enable": ("lcd_control",),
}

MEMORY_CALLS = {"text", "view", "tiles"}
ORDER = ("switch", "disable", "text", "view", "tiles", "enable")


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


def _call_values(
    state: angr.SimState, kind: str
) -> tuple[claripy.ast.BV, ...]:
    values = []
    for field in CALL_FIELDS[kind]:
        if field in {"enable_object0", "enable_object1"}:
            values.append(claripy.BVV(0, 8))
        else:
            values.append(state.globals[field])
    if kind in MEMORY_CALLS:
        values.append(state.memory.load(MARKER, 1))
    return tuple(values)


class LoadGlobalA(angr.SimProcedure):
    def __init__(self, field: str, next_address: int):
        super().__init__()
        self.field = field
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals[self.field]
        self.jump(self.next_address)


class SaveAf(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["outer_saved_a"] = self.state.regs.a
        self.state.globals["outer_saved_f"] = assembly_registers(self.state)["f"]
        self.jump(self.next_address)


class RestoreAf(SaveAf):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals["outer_saved_a"]
        self.state.regs.f = sm83_flags_to_z80(
            self.state.globals["outer_saved_f"]
        )
        self.jump(self.next_address)


class CallSummary(angr.SimProcedure):
    def __init__(self, kind: str, next_address: int):
        super().__init__()
        self.kind = kind
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        registers = assembly_registers(self.state)
        self.state.globals["call_" + self.kind] = claripy.Concat(
            *(registers[r] for r in REGISTERS),
            *_call_values(self.state, self.kind),
        )
        for register in REGISTERS:
            value = self.state.globals[f"{self.kind}_out_{register}"]
            if register == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, register, value)
        for field in OUTPUT_FIELDS[self.kind]:
            self.state.globals[field] = self.state.globals[
                f"{self.kind}_out_{field}"
            ]
        if self.kind in MEMORY_CALLS:
            self.state.memory.store(
                MARKER, self.state.globals[f"{self.kind}_out_marker"]
            )
        self.jump(self.next_address)


class NativeCallSummary(angr.SimProcedure):
    def __init__(self, kind: str):
        super().__init__()
        self.kind = kind

    def run(
        self,
        callee_state: claripy.ast.BV,
        memory: claripy.ast.BV | None = None,
    ) -> None:  # type: ignore[override]
        field_count = len(CALL_FIELDS[self.kind])
        call_parts = [self.state.memory.load(callee_state, 8 + field_count)]
        if self.kind in MEMORY_CALLS:
            if memory is None:
                memory = self.state.regs.rsi
            call_parts.append(self.state.memory.load(memory + MARKER, 1))
        self.state.globals["call_" + self.kind] = claripy.Concat(*call_parts)
        for offset, register in enumerate(REGISTERS):
            self.state.memory.store(
                callee_state + offset,
                self.state.globals[f"{self.kind}_out_{register}"],
            )
        for offset, field in enumerate(OUTPUT_FIELDS[self.kind], 8):
            self.state.memory.store(
                callee_state + offset,
                self.state.globals[f"{self.kind}_out_{field}"],
            )
        if self.kind in MEMORY_CALLS:
            assert memory is not None
            self.state.memory.store(
                memory + MARKER,
                self.state.globals[f"{self.kind}_out_marker"],
            )


class StoreBank(angr.SimProcedure):
    def __init__(self, field: str, next_address: int):
        super().__init__()
        self.field = field
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.globals[self.field] = self.state.regs.a
        self.jump(self.next_address)


class Finish(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(DONE)


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for field in FIELDS:
        values[field] = (
            claripy.Concat(
                claripy.BVS(f"{prefix}_{field}_flags", 4), claripy.BVV(0, 4)
            )
            if field == "view_saved_f"
            else claripy.BVS(f"{prefix}_{field}", 8)
        )
    for kind in ORDER:
        for register in REGISTERS:
            values[f"{kind}_out_{register}"] = (
                claripy.Concat(
                    claripy.BVS(f"{prefix}_{kind}_out_flags", 4),
                    claripy.BVV(0, 4),
                )
                if register == "f"
                else claripy.BVS(f"{prefix}_{kind}_out_{register}", 8)
            )
        for field in OUTPUT_FIELDS[kind]:
            values[f"{kind}_out_{field}"] = (
                claripy.Concat(
                    claripy.BVS(f"{prefix}_{kind}_out_{field}_flags", 4),
                    claripy.BVV(0, 4),
                )
                if field == "view_saved_f"
                else claripy.BVS(f"{prefix}_{kind}_out_{field}", 8)
            )
        if kind in MEMORY_CALLS:
            values[f"{kind}_out_marker"] = claripy.BVS(
                f"{prefix}_{kind}_out_marker", 8
            )
    values["marker"] = claripy.BVS(f"{prefix}_marker", 8)
    return values


def _call_width(kind: str) -> int:
    return 8 * (
        8 + len(CALL_FIELDS[kind]) + (1 if kind in MEMORY_CALLS else 0)
    )


def _setup(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    for field in FIELDS:
        state.globals[field] = values[field]
    for kind in ORDER:
        for register in REGISTERS:
            state.globals[f"{kind}_out_{register}"] = values[
                f"{kind}_out_{register}"
            ]
        for field in OUTPUT_FIELDS[kind]:
            state.globals[f"{kind}_out_{field}"] = values[
                f"{kind}_out_{field}"
            ]
        if kind in MEMORY_CALLS:
            state.globals[f"{kind}_out_marker"] = values[
                f"{kind}_out_marker"
            ]
        state.globals["call_" + kind] = claripy.BVV(0, _call_width(kind))


def _calls(state: angr.SimState) -> claripy.ast.BV:
    return claripy.Concat(*(state.globals["call_" + kind] for kind in ORDER))


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "ReloadMapData")
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
    project.hook(base, LoadGlobalA("loaded_rom_bank", base + 2), length=2)
    project.hook(base + 2, SaveAf(base + 3), length=1)
    project.hook(base + 3, LoadGlobalA("cur_map", base + 6), length=3)
    for kind, offset in zip(ORDER, (6, 9, 12, 15, 18, 21), strict=True):
        project.hook(
            base + offset, CallSummary(kind, base + offset + 3), length=3
        )
    project.hook(base + 24, RestoreAf(base + 25), length=1)
    project.hook(
        base + 25, StoreBank("loaded_rom_bank", base + 27), length=2
    )
    project.hook(base + 27, StoreBank("mapper_bank", base + 30), length=3)
    project.hook(base + 30, Finish(), length=1)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _setup(state, values)
    state.memory.store(MARKER, values["marker"])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE)
    assert not manager.errored
    return [
        Endpoint(
            **assembly_registers(end),
            state=claripy.Concat(*(end.globals[field] for field in FIELDS)),
            calls=_calls(end),
            marker=end.memory.load(MARKER, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_reload_map_data")
    names = {
        "switch": "port_switch_to_map_rom_bank",
        "disable": "port_disable_lcd",
        "text": "port_load_text_box_tile_patterns",
        "view": "port_load_current_map_view",
        "tiles": "port_load_tileset_tile_pattern_data",
        "enable": "port_enable_lcd",
    }
    symbols = {kind: project.loader.find_symbol(name) for kind, name in names.items()}
    assert function is not None and all(symbols.values())
    for kind, symbol in symbols.items():
        assert symbol is not None
        project.hook(symbol.rebased_addr, NativeCallSummary(kind))
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    for offset, field in enumerate(FIELDS, 8):
        state.memory.store(NATIVE_STATE + offset, values[field])
    _setup(state, values)
    state.memory.store(NATIVE_MEMORY + MARKER, values["marker"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            state=end.memory.load(NATIVE_STATE + 8, len(FIELDS)),
            calls=_calls(end),
            marker=end.memory.load(NATIVE_MEMORY + MARKER, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_reload_map_data_pathwise_equivalence() -> None:
    values = _inputs("reload_map_data")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "state", "calls", "marker"),
    )
