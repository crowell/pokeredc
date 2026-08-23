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
from verification.harness.sm83_shims import Sm83CpImmediate

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
MARKER = 0x1234
DONE = 0xEFFF
EXPECTED = bytes.fromhex("fa57cca7c0fa5ed3fe1c2005f0b4e670c0c3270d")

ADVANCE_FIELDS = (
    "y_step", "x_step", "walk_counter", "y_coord", "x_coord",
    "map_view_vram_low", "map_view_vram_high",
    "x_block_coord", "y_block_coord",
    "x_special_warp_offset", "y_special_warp_offset",
    "map_view_pointer_low", "map_view_pointer_high", "map_width",
    "scroll_y", "scroll_x", "num_sprites",
    "redraw_dest_low", "redraw_dest_high", "redraw_mode",
    "tileset_bank", "loaded_rom_bank", "mapper_bank",
    "tileset_blocks_low", "tileset_blocks_high",
    "view_saved_a", "view_saved_f",
    "view_row_d", "view_row_e", "view_row_h", "view_row_l",
    "view_fetched_block", "view_fetched_copy", "view_written_copy",
    "view_write_h", "view_write_l",
    "sprite_fetched_y", "sprite_fetched_x",
    "sprite_written_y", "sprite_written_x",
    "sprite_write_y_high", "sprite_write_y_low",
    "sprite_write_x_high", "sprite_write_x_low",
)
WRAPPER_FIELDS = (
    "npc_movement_script_pointer_table_num",
    "cur_map",
    "joy_held",
)
FIELDS = (*ADVANCE_FIELDS, *WRAPPER_FIELDS)
CALL_BYTES = 8 + len(ADVANCE_FIELDS) + 1


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
    called: claripy.ast.BV
    call_data: claripy.ast.BV
    marker: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class LoadField(angr.SimProcedure):
    def __init__(self, field: str, target: int):
        super().__init__()
        self.field = field
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals[self.field]
        self.jump(self.target)


class AndImmediate(angr.SimProcedure):
    def __init__(self, value: int, target: int):
        super().__init__()
        self.value = value
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a &= self.value
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x50, 8),
            claripy.BVV(0x10, 8),
        )
        self.jump(self.target)


class BranchValue(angr.SimProcedure):
    def __init__(self, value: int, equal: int, other: int):
        super().__init__()
        self.value = value
        self.equal = equal
        self.other = other

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        condition = self.state.regs.a == self.value
        equal = self.state.copy()
        other = self.state.copy()
        equal.add_constraints(condition)
        other.add_constraints(claripy.Not(condition))
        self.successors.add_successor(
            equal, self.equal, claripy.BoolV(True), "Ijk_Boring"
        )
        self.successors.add_successor(
            other, self.other, claripy.BoolV(True), "Ijk_Boring"
        )


class AdvanceSummary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        registers = assembly_registers(self.state)
        self.state.globals["called"] = claripy.BVV(1, 8)
        self.state.globals["call_data"] = claripy.Concat(
            *(registers[register] for register in REGISTERS),
            *(self.state.globals[field] for field in ADVANCE_FIELDS),
            self.state.globals["marker"],
        )
        for register in REGISTERS:
            value = self.state.globals["out_" + register]
            if register == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, register, value)
        for field in ADVANCE_FIELDS:
            self.state.globals[field] = self.state.globals["out_" + field]
        self.state.globals["marker"] = self.state.globals["out_marker"]
        self.jump(DONE)


class NativeAdvanceSummary(angr.SimProcedure):
    def run(
        self, advance_state: claripy.ast.BV, memory: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        self.state.globals["called"] = claripy.BVV(1, 8)
        self.state.globals["call_data"] = claripy.Concat(
            self.state.memory.load(advance_state, 8 + len(ADVANCE_FIELDS)),
            self.state.memory.load(memory + MARKER, 1),
        )
        self.state.memory.store(
            advance_state,
            claripy.Concat(
                *(self.state.globals["out_" + register] for register in REGISTERS),
                *(self.state.globals["out_" + field] for field in ADVANCE_FIELDS),
            ),
        )
        self.state.memory.store(
            memory + MARKER, self.state.globals["out_marker"]
        )


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for field in FIELDS:
        values[field] = claripy.BVS(f"{prefix}_{field}", 8)
    for register in REGISTERS:
        values["out_" + register] = (
            claripy.Concat(
                claripy.BVS(f"{prefix}_out_flags", 4), claripy.BVV(0, 4)
            )
            if register == "f"
            else claripy.BVS(f"{prefix}_out_{register}", 8)
        )
    for field in ADVANCE_FIELDS:
        values["out_" + field] = claripy.BVS(f"{prefix}_out_{field}", 8)
    values["marker"] = claripy.BVS(f"{prefix}_marker", 8)
    values["out_marker"] = claripy.BVS(f"{prefix}_out_marker", 8)
    return values


def _setup(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    for field in FIELDS:
        state.globals[field] = values[field]
    for register in REGISTERS:
        state.globals["out_" + register] = values["out_" + register]
    for field in ADVANCE_FIELDS:
        state.globals["out_" + field] = values["out_" + field]
    state.globals["marker"] = values["marker"]
    state.globals["out_marker"] = values["out_marker"]
    state.globals["called"] = claripy.BVV(0, 8)
    state.globals["call_data"] = claripy.BVV(0, CALL_BYTES * 8)


def _collect(manager: angr.SimulationManager) -> list[angr.SimState]:
    manager.stashes["finished"] = []
    while manager.active:
        manager.move(
            from_stash="active",
            to_stash="finished",
            filter_func=lambda state: state.addr == DONE,
        )
        if manager.active:
            manager.step()
    assert not manager.errored
    assert manager.finished
    return manager.finished


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "DoBikeSpeedup")
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
    project.hook(
        base,
        LoadField("npc_movement_script_pointer_table_num", base + 3),
        length=3,
    )
    project.hook(base + 3, AndImmediate(0xFF, base + 4), length=1)
    project.hook(base + 4, BranchValue(0, base + 5, DONE), length=1)
    project.hook(base + 5, LoadField("cur_map", base + 8), length=3)
    project.hook(base + 8, Sm83CpImmediate(0x1C, base + 10), length=2)
    project.hook(base + 10, BranchValue(0x1C, base + 12, base + 17), length=2)
    project.hook(base + 12, LoadField("joy_held", base + 14), length=2)
    project.hook(base + 14, AndImmediate(0x70, base + 16), length=2)
    project.hook(base + 16, BranchValue(0, base + 17, DONE), length=1)
    project.hook(base + 17, AdvanceSummary(), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _setup(state, values)
    return [
        Endpoint(
            **assembly_registers(end),
            state=claripy.Concat(*(end.globals[field] for field in FIELDS)),
            called=end.globals["called"],
            call_data=end.globals["call_data"],
            marker=end.globals["marker"],
            constraints=tuple(end.solver.constraints),
        )
        for end in _collect(project.factory.simulation_manager(state))
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_do_bike_speedup")
    advance = project.loader.find_symbol("port_advance_player_sprite")
    assert function is not None and advance is not None
    project.hook(advance.rebased_addr, NativeAdvanceSummary())
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
            called=end.globals["called"],
            call_data=end.globals["call_data"],
            marker=end.memory.load(NATIVE_MEMORY + MARKER, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_do_bike_speedup_pathwise_equivalence() -> None:
    values = _inputs("do_bike_speedup")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "state", "called", "call_data", "marker"),
    )
