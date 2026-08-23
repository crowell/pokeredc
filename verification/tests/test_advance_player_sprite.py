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
from verification.harness.sm83_shims import (
    Sm83AddImmediate,
    Sm83AddRegister,
    Sm83CpImmediate,
    Sm83DecRegister,
    Sm83IncRegister,
    Sm83SlaRegister,
    Sm83SubImmediate,
    Sm83SubRegister,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
MARKER = 0x1234
DONE0 = 0xED00
DONE1 = 0xED01
EXPECTED = bytes.fromhex(
    "fa03c147fa05c14f21c5cf35200efa61d380ea61d3fa62d381ea62d3fac5cffe07"
    "c2360e79fe012012fa26d55fe6e0577bc602e61fb2ea26d5184bfeff2012fa26d5"
    "5fe6e0577bd602e61fb2ea26d5183578fe012017fa26d5c640ea26d53026fa27d5"
    "3ce603f698ea27d51819feff2015fa26d5d640ea26d5300bfa27d5"
    "3de603f698ea27d579a728002164d37e8177fe02200eaf7721e3d434115fd3cd650e"
    "1842feff200f3e017721e3d435115fd3cd6f0e182f2163d37e8077fe022011af77"
    "21e2d434115fd3fa69d3cd790e1814feff20103e017721e2d435115fd3fa69d3cd"
    "850ecdaa0cfa03c1fe012005cdb20e181cfeff2005cd910e1813fa05c1fe012005"
    "cdd30e1807feff2003cd080ffa03c147fa05c14fcb20cb21f0af80e0aff0ae81e0"
    "ae2114c1fae1d4a7280f5f7e90222c7e91773e0e856f1d20f2c9"
)

AUX = (
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
    aux: claripy.ast.BV
    continuation: claripy.ast.BV
    call_kind: claripy.ast.BV
    call_data: claripy.ast.BV
    marker: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class Jump(angr.SimProcedure):
    def __init__(self, target: int):
        super().__init__()
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.jump(self.target)


class LoadField(Jump):
    def __init__(self, field: str, target: int):
        super().__init__(target)
        self.field = field

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals[self.field]
        self.jump(self.target)


class StoreField(LoadField):
    def run(self) -> None:  # type: ignore[override]
        self.state.globals[self.field] = self.state.regs.a
        self.jump(self.target)


class DecField(LoadField):
    def run(self) -> None:  # type: ignore[override]
        old = self.state.globals[self.field]
        result = old - 1
        flags = self.state.regs.f & 1
        flags |= claripy.BVV(0x02, 8)
        flags |= claripy.If(result == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        flags |= claripy.If(
            (old & 0x0F) == 0, claripy.BVV(0x10, 8), claripy.BVV(0, 8)
        )
        self.state.globals[self.field] = result
        self.state.regs.f = flags
        self.jump(self.target)


class AndImmediate(Jump):
    def __init__(self, value: int, target: int):
        super().__init__(target)
        self.value = value

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a &= self.value
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x50, 8),
            claripy.BVV(0x10, 8),
        )
        self.jump(self.target)


class AndRegister(AndImmediate):
    def __init__(self, register: str, target: int):
        super().__init__(0, target)
        self.register = register

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a &= getattr(self.state.regs, self.register)
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x50, 8),
            claripy.BVV(0x10, 8),
        )
        self.jump(self.target)


class OrValue(Jump):
    def __init__(self, value: int | str, target: int):
        super().__init__(target)
        self.value = value

    def run(self) -> None:  # type: ignore[override]
        value = (
            getattr(self.state.regs, self.value)
            if isinstance(self.value, str)
            else self.value
        )
        self.state.regs.a |= value
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x40, 8),
            claripy.BVV(0, 8),
        )
        self.jump(self.target)


class BranchContinuation(angr.SimProcedure):
    def __init__(self, register: str):
        super().__init__()
        self.register = register

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        value = getattr(self.state.regs, self.register)
        self.successors.add_successor(
            self.state.copy(), DONE1, value != 0, "Ijk_Boring"
        )
        self.successors.add_successor(
            self.state.copy(), DONE0, value == 0, "Ijk_Boring"
        )


class FirstIterationBranch(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        is_first = self.state.regs.a == 7
        self.successors.add_successor(
            self.state.copy(), DONE1, is_first, "Ijk_Boring"
        )
        self.successors.add_successor(
            self.state.copy(), DONE0, claripy.Not(is_first), "Ijk_Boring"
        )


class BranchEq(angr.SimProcedure):
    def __init__(
        self, register: str, value: int, equal_target: int, other_target: int
    ) -> None:
        super().__init__()
        self.register = register
        self.value = value
        self.equal_target = equal_target
        self.other_target = other_target

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        condition = getattr(self.state.regs, self.register) == self.value
        equal = self.state.copy()
        other = self.state.copy()
        equal.add_constraints(condition)
        other.add_constraints(claripy.Not(condition))
        self.successors.add_successor(
            equal, self.equal_target, claripy.BoolV(True), "Ijk_Boring"
        )
        self.successors.add_successor(
            other, self.other_target, claripy.BoolV(True), "Ijk_Boring"
        )


class BranchCarry(angr.SimProcedure):
    def __init__(self, carry_target: int, clear_target: int) -> None:
        super().__init__()
        self.carry_target = carry_target
        self.clear_target = clear_target

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        condition = (self.state.regs.f & 1) != 0
        carry = self.state.copy()
        clear = self.state.copy()
        carry.add_constraints(condition)
        clear.add_constraints(claripy.Not(condition))
        self.successors.add_successor(
            carry, self.carry_target, claripy.BoolV(True), "Ijk_Boring"
        )
        self.successors.add_successor(
            clear, self.clear_target, claripy.BoolV(True), "Ijk_Boring"
        )


class BranchFieldEq(BranchEq):
    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        condition = self.state.globals[self.register] == self.value
        equal = self.state.copy()
        other = self.state.copy()
        equal.add_constraints(condition)
        other.add_constraints(claripy.Not(condition))
        self.successors.add_successor(
            equal, self.equal_target, claripy.BoolV(True), "Ijk_Boring"
        )
        self.successors.add_successor(
            other, self.other_target, claripy.BoolV(True), "Ijk_Boring"
        )


class ScrollBranch(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        nonzero = self.state.copy()
        nonzero.regs.e = nonzero.regs.a
        self.successors.add_successor(nonzero, DONE1, nonzero.regs.a != 0, "Ijk_Boring")
        self.successors.add_successor(
            self.state.copy(), DONE0, self.state.regs.a == 0, "Ijk_Boring"
        )


class WriteY(Jump):
    def run(self) -> None:  # type: ignore[override]
        self.state.globals["sprite_written_y"] = self.state.regs.a
        self.state.globals["sprite_write_y_high"] = self.state.regs.h
        self.state.globals["sprite_write_y_low"] = self.state.regs.l
        self.state.regs.hl = self.state.regs.hl + 1
        self.jump(self.target)


class WriteX(Jump):
    def run(self) -> None:  # type: ignore[override]
        self.state.globals["sprite_written_x"] = self.state.regs.a
        self.state.globals["sprite_write_x_high"] = self.state.regs.h
        self.state.globals["sprite_write_x_low"] = self.state.regs.l
        self.jump(self.target)


class XorA(Jump):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = 0
        self.state.regs.f = 0x40
        self.jump(self.target)


class IncField(LoadField):
    def run(self) -> None:  # type: ignore[override]
        old = self.state.globals[self.field]
        result = old + 1
        flags = self.state.regs.f & 1
        flags |= claripy.If(result == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        flags |= claripy.If(
            (old & 0x0F) == 0x0F,
            claripy.BVV(0x10, 8),
            claripy.BVV(0, 8),
        )
        self.state.globals[self.field] = result
        self.state.regs.f = flags
        self.jump(self.target)


class PointerSummary(Jump):
    def __init__(self, kind: int, target: int):
        super().__init__(target)
        self.kind = kind

    def run(self) -> None:  # type: ignore[override]
        registers = assembly_registers(self.state)
        self.state.globals["call_kind"] = claripy.BVV(self.kind, 8)
        self.state.globals["call_data"] = claripy.Concat(
            *(registers[r] for r in REGISTERS),
            self.state.globals["map_view_pointer_low"],
            self.state.globals["map_view_pointer_high"],
        )
        for register in REGISTERS:
            value = self.state.globals["pointer_out_" + register]
            if register == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, register, value)
        self.state.globals["map_view_pointer_low"] = self.state.globals[
            "pointer_out_low"
        ]
        self.state.globals["map_view_pointer_high"] = self.state.globals[
            "pointer_out_high"
        ]
        self.jump(self.target)


class NativePointerSummary(angr.SimProcedure):
    def __init__(self, kind: int):
        super().__init__()
        self.kind = kind

    def run(self, pointer: claripy.ast.BV) -> None:  # type: ignore[override]
        self.state.globals["call_kind"] = claripy.BVV(self.kind, 8)
        self.state.globals["call_data"] = self.state.memory.load(pointer, 10)
        for offset, register in enumerate(REGISTERS):
            self.state.memory.store(
                pointer + offset, self.state.globals["pointer_out_" + register]
            )
        self.state.memory.store(pointer + 8, self.state.globals["pointer_out_low"])
        self.state.memory.store(pointer + 9, self.state.globals["pointer_out_high"])


VIEW_FIELDS = (
    "tileset_bank", "loaded_rom_bank", "mapper_bank",
    "map_view_pointer_low", "map_view_pointer_high", "map_width",
    "y_block_coord", "x_block_coord",
    "tileset_blocks_low", "tileset_blocks_high",
    "view_saved_a", "view_saved_f",
    "view_row_d", "view_row_e", "view_row_h", "view_row_l",
    "view_fetched_block", "view_fetched_copy", "view_written_copy",
    "view_write_h", "view_write_l",
)
SCHEDULE_FIELDS = (
    "map_view_vram_low", "map_view_vram_high",
    "redraw_dest_low", "redraw_dest_high", "redraw_mode",
)


class ViewSummary(Jump):
    def run(self) -> None:  # type: ignore[override]
        registers = assembly_registers(self.state)
        self.state.globals["view_call"] = claripy.Concat(
            *(registers[r] for r in REGISTERS),
            *(self.state.globals[field] for field in VIEW_FIELDS),
            self.state.globals["marker"],
        )
        for register in REGISTERS:
            value = self.state.globals["view_out_" + register]
            if register == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, register, value)
        for field in VIEW_FIELDS:
            self.state.globals[field] = self.state.globals["view_out_" + field]
        self.state.globals["marker"] = self.state.globals["view_out_marker"]
        self.jump(self.target)


class ScheduleSummary(Jump):
    def __init__(self, kind: int, target: int):
        super().__init__(target)
        self.kind = kind

    def run(self) -> None:  # type: ignore[override]
        registers = assembly_registers(self.state)
        self.state.globals["call_kind"] = claripy.BVV(self.kind, 8)
        self.state.globals["schedule_call"] = claripy.Concat(
            *(registers[r] for r in REGISTERS),
            *(self.state.globals[field] for field in SCHEDULE_FIELDS),
            self.state.globals["marker"],
        )
        for register in REGISTERS:
            value = self.state.globals["schedule_out_" + register]
            if register == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, register, value)
        for field in SCHEDULE_FIELDS:
            self.state.globals[field] = self.state.globals[
                "schedule_out_" + field
            ]
        self.state.globals["marker"] = self.state.globals[
            "schedule_out_marker"
        ]
        self.jump(self.target)


class FinishUpdateView(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.globals["call_data"] = claripy.Concat(
            self.state.globals["view_call"],
            self.state.globals["schedule_call"],
        )
        self.jump(DONE0)


class NativeViewSummary(angr.SimProcedure):
    def run(
        self, view: claripy.ast.BV, memory: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        self.state.globals["view_call"] = claripy.Concat(
            self.state.memory.load(view, 29),
            self.state.memory.load(memory + MARKER, 1),
        )
        for offset, register in enumerate(REGISTERS):
            self.state.memory.store(
                view + offset, self.state.globals["view_out_" + register]
            )
        for offset, field in enumerate(VIEW_FIELDS, 8):
            self.state.memory.store(
                view + offset, self.state.globals["view_out_" + field]
            )
        self.state.memory.store(
            memory + MARKER, self.state.globals["view_out_marker"]
        )


class NativeScheduleSummary(angr.SimProcedure):
    def __init__(self, kind: int):
        super().__init__()
        self.kind = kind

    def run(
        self, schedule: claripy.ast.BV, memory: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        self.state.globals["call_kind"] = claripy.BVV(self.kind, 8)
        self.state.globals["schedule_call"] = claripy.Concat(
            self.state.memory.load(schedule, 13),
            self.state.memory.load(memory + MARKER, 1),
        )
        for offset, register in enumerate(REGISTERS):
            self.state.memory.store(
                schedule + offset,
                self.state.globals["schedule_out_" + register],
            )
        for offset, field in enumerate(SCHEDULE_FIELDS, 8):
            self.state.memory.store(
                schedule + offset,
                self.state.globals["schedule_out_" + field],
            )
        self.state.memory.store(
            memory + MARKER, self.state.globals["schedule_out_marker"]
        )


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for field in AUX:
        values[field] = (
            claripy.Concat(
                claripy.BVS(f"{prefix}_{field}_flags", 4), claripy.BVV(0, 4)
            )
            if field == "view_saved_f"
            else claripy.BVS(f"{prefix}_{field}", 8)
        )
    return values


def _setup(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    set_assembly_registers(state, values)
    for field in AUX:
        state.globals[field] = values[field]
    state.globals["call_kind"] = claripy.BVV(0, 8)
    state.globals["call_data"] = claripy.BVV(0, 8)
    state.globals["marker"] = claripy.BVV(0, 8)


def _endpoint(state: angr.SimState, continuation: int) -> Endpoint:
    return Endpoint(
        **assembly_registers(state),
        aux=claripy.Concat(*(state.globals[field] for field in AUX)),
        continuation=claripy.BVV(continuation, 8),
        call_kind=state.globals["call_kind"],
        call_data=state.globals["call_data"],
        marker=state.globals["marker"],
        constraints=tuple(state.solver.constraints),
    )


def _project() -> tuple[angr.Project, int]:
    location = symbol_location(SYMBOLS, "AdvancePlayerSprite")
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
    return project, location.address


def _collect(project: angr.Project, state: angr.SimState) -> list[Endpoint]:
    manager = project.factory.simulation_manager(state)
    manager.stashes["found"] = []
    while manager.active:
        manager.move(
            from_stash="active",
            to_stash="found",
            filter_func=lambda end: end.addr in {DONE0, DONE1},
        )
        if manager.active:
            manager.step()
    assert not manager.errored
    return [_endpoint(end, 1 if end.addr == DONE1 else 0) for end in manager.found]


def _assembly_begin(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, base = _project()
    project.hook(base, LoadField("y_step", base + 3), length=3)
    project.hook(base + 4, LoadField("x_step", base + 7), length=3)
    project.hook(base + 11, DecField("walk_counter", base + 12), length=1)
    project.hook(
        base + 12,
        BranchFieldEq("walk_counter", 0, base + 14, base + 28),
        length=2,
    )
    project.hook(base + 14, LoadField("y_coord", base + 17), length=3)
    project.hook(base + 17, Sm83AddRegister("b", base + 18), length=1)
    project.hook(base + 18, StoreField("y_coord", base + 21), length=3)
    project.hook(base + 21, LoadField("x_coord", base + 24), length=3)
    project.hook(base + 24, Sm83AddRegister("c", base + 25), length=1)
    project.hook(base + 25, StoreField("x_coord", base + 28), length=3)
    project.hook(base + 28, LoadField("walk_counter", base + 31), length=3)
    project.hook(base + 31, Sm83CpImmediate(7, base + 33), length=2)
    project.hook(base + 33, FirstIterationBranch(), length=3)
    state = project.factory.blank_state(addr=base)
    _setup(state, values)
    return _collect(project, state)


def _assembly_adjust_vram(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, base = _project()
    project.hook(base + 37, Sm83CpImmediate(1, base + 39), length=2)
    project.hook(base + 39, BranchEq("a", 1, base + 41, base + 59), length=2)
    project.hook(base + 41, LoadField("map_view_vram_low", base + 44), length=3)
    project.hook(base + 45, AndImmediate(0xE0, base + 47), length=2)
    project.hook(base + 49, Sm83AddImmediate(2, base + 51), length=2)
    project.hook(base + 51, AndImmediate(0x1F, base + 53), length=2)
    project.hook(base + 53, OrValue("d", base + 54), length=1)
    project.hook(base + 54, StoreField("map_view_vram_low", base + 57), length=3)
    project.hook(base + 57, Jump(base + 134), length=2)
    project.hook(base + 59, Sm83CpImmediate(0xFF, base + 61), length=2)
    project.hook(base + 61, BranchEq("a", 0xFF, base + 63, base + 81), length=2)
    project.hook(base + 63, LoadField("map_view_vram_low", base + 66), length=3)
    project.hook(base + 67, AndImmediate(0xE0, base + 69), length=2)
    project.hook(base + 71, Sm83SubImmediate(2, base + 73), length=2)
    project.hook(base + 73, AndImmediate(0x1F, base + 75), length=2)
    project.hook(base + 75, OrValue("d", base + 76), length=1)
    project.hook(base + 76, StoreField("map_view_vram_low", base + 79), length=3)
    project.hook(base + 79, Jump(base + 134), length=2)
    project.hook(base + 82, Sm83CpImmediate(1, base + 84), length=2)
    project.hook(base + 84, BranchEq("a", 1, base + 86, base + 109), length=2)
    project.hook(base + 86, LoadField("map_view_vram_low", base + 89), length=3)
    project.hook(base + 89, Sm83AddImmediate(0x40, base + 91), length=2)
    project.hook(base + 91, StoreField("map_view_vram_low", base + 94), length=3)
    project.hook(base + 94, BranchCarry(base + 96, base + 134), length=2)
    project.hook(base + 96, LoadField("map_view_vram_high", base + 99), length=3)
    project.hook(base + 99, Sm83IncRegister("a", base + 100), length=1)
    project.hook(base + 100, AndImmediate(3, base + 102), length=2)
    project.hook(base + 102, OrValue(0x98, base + 104), length=2)
    project.hook(base + 104, StoreField("map_view_vram_high", base + 107), length=3)
    project.hook(base + 107, Jump(base + 134), length=2)
    project.hook(base + 109, Sm83CpImmediate(0xFF, base + 111), length=2)
    project.hook(base + 111, BranchEq("a", 0xFF, base + 113, base + 134), length=2)
    project.hook(base + 113, LoadField("map_view_vram_low", base + 116), length=3)
    project.hook(base + 116, Sm83SubImmediate(0x40, base + 118), length=2)
    project.hook(base + 118, StoreField("map_view_vram_low", base + 121), length=3)
    project.hook(base + 121, BranchCarry(base + 123, base + 134), length=2)
    project.hook(base + 123, LoadField("map_view_vram_high", base + 126), length=3)
    project.hook(base + 126, Sm83DecRegister("a", base + 127), length=1)
    project.hook(base + 127, AndImmediate(3, base + 129), length=2)
    project.hook(base + 129, OrValue(0x98, base + 131), length=2)
    project.hook(base + 131, StoreField("map_view_vram_high", base + 134), length=3)
    project.hook(base + 134, Jump(DONE0), length=0)
    state = project.factory.blank_state(addr=base + 36)
    _setup(state, values)
    return _collect(project, state)


def _assembly_scroll_begin(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, base = _project()
    project.hook(base + 271, LoadField("y_step", base + 274), length=3)
    project.hook(base + 275, LoadField("x_step", base + 278), length=3)
    project.hook(base + 279, Sm83SlaRegister("b", base + 281), length=2)
    project.hook(base + 281, Sm83SlaRegister("c", base + 283), length=2)
    project.hook(base + 283, LoadField("scroll_y", base + 285), length=2)
    project.hook(base + 285, Sm83AddRegister("b", base + 286), length=1)
    project.hook(base + 286, StoreField("scroll_y", base + 288), length=2)
    project.hook(base + 288, LoadField("scroll_x", base + 290), length=2)
    project.hook(base + 290, Sm83AddRegister("c", base + 291), length=1)
    project.hook(base + 291, StoreField("scroll_x", base + 293), length=2)
    project.hook(base + 296, LoadField("num_sprites", base + 299), length=3)
    project.hook(base + 299, AndRegister("a", base + 300), length=1)
    project.hook(base + 300, ScrollBranch(), length=3)
    state = project.factory.blank_state(addr=base + 271)
    _setup(state, values)
    return _collect(project, state)


def _assembly_shift_step(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, base = _project()
    project.hook(base + 303, LoadField("sprite_fetched_y", base + 304), length=1)
    project.hook(base + 304, Sm83SubRegister("b", base + 305), length=1)
    project.hook(base + 305, WriteY(base + 306), length=1)
    project.hook(base + 306, Sm83IncRegister("l", base + 307), length=1)
    project.hook(base + 307, LoadField("sprite_fetched_x", base + 308), length=1)
    project.hook(base + 308, Sm83SubRegister("c", base + 309), length=1)
    project.hook(base + 309, WriteX(base + 310), length=1)
    project.hook(base + 312, Sm83AddRegister("l", base + 313), length=1)
    project.hook(base + 314, Sm83DecRegister("e", base + 315), length=1)
    project.hook(base + 315, BranchContinuation("e"), length=2)
    state = project.factory.blank_state(addr=base + 303)
    _setup(state, values)
    return _collect(project, state)


def _pointer_inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = _inputs(prefix)
    for register in REGISTERS:
        values["pointer_out_" + register] = (
            claripy.Concat(
                claripy.BVS(f"{prefix}_pointer_out_flags", 4),
                claripy.BVV(0, 4),
            )
            if register == "f"
            else claripy.BVS(f"{prefix}_pointer_out_{register}", 8)
        )
    values["pointer_out_low"] = claripy.BVS(f"{prefix}_pointer_out_low", 8)
    values["pointer_out_high"] = claripy.BVS(f"{prefix}_pointer_out_high", 8)
    return values


def _setup_pointer(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    _setup(state, values)
    for register in REGISTERS:
        state.globals["pointer_out_" + register] = values[
            "pointer_out_" + register
        ]
    state.globals["pointer_out_low"] = values["pointer_out_low"]
    state.globals["pointer_out_high"] = values["pointer_out_high"]
    state.globals["call_data"] = claripy.BVV(0, 80)


def _assembly_adjust_map(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, base = _project()
    project.hook(base + 135, AndRegister("a", base + 136), length=1)
    project.hook(base + 136, Jump(base + 138), length=2)
    project.hook(base + 141, LoadField("x_block_coord", base + 142), length=1)
    project.hook(base + 142, Sm83AddRegister("c", base + 143), length=1)
    project.hook(base + 143, StoreField("x_block_coord", base + 144), length=1)
    project.hook(base + 144, Sm83CpImmediate(2, base + 146), length=2)
    project.hook(base + 146, BranchEq("a", 2, base + 148, base + 162), length=2)
    project.hook(base + 148, XorA(base + 149), length=1)
    project.hook(base + 149, StoreField("x_block_coord", base + 150), length=1)
    project.hook(
        base + 153, IncField("x_special_warp_offset", base + 154), length=1
    )
    project.hook(base + 157, PointerSummary(1, base + 160), length=3)
    project.hook(base + 160, Jump(base + 228), length=2)
    project.hook(base + 162, Sm83CpImmediate(0xFF, base + 164), length=2)
    project.hook(base + 164, BranchEq("a", 0xFF, base + 166, base + 181), length=2)
    project.hook(base + 168, StoreField("x_block_coord", base + 169), length=1)
    project.hook(
        base + 172, DecField("x_special_warp_offset", base + 173), length=1
    )
    project.hook(base + 176, PointerSummary(2, base + 179), length=3)
    project.hook(base + 179, Jump(base + 228), length=2)
    project.hook(base + 184, LoadField("y_block_coord", base + 185), length=1)
    project.hook(base + 185, Sm83AddRegister("b", base + 186), length=1)
    project.hook(base + 186, StoreField("y_block_coord", base + 187), length=1)
    project.hook(base + 187, Sm83CpImmediate(2, base + 189), length=2)
    project.hook(base + 189, BranchEq("a", 2, base + 191, base + 208), length=2)
    project.hook(base + 191, XorA(base + 192), length=1)
    project.hook(base + 192, StoreField("y_block_coord", base + 193), length=1)
    project.hook(
        base + 196, IncField("y_special_warp_offset", base + 197), length=1
    )
    project.hook(base + 200, LoadField("map_width", base + 203), length=3)
    project.hook(base + 203, PointerSummary(3, base + 206), length=3)
    project.hook(base + 206, Jump(base + 228), length=2)
    project.hook(base + 208, Sm83CpImmediate(0xFF, base + 210), length=2)
    project.hook(base + 210, BranchEq("a", 0xFF, base + 212, base + 228), length=2)
    project.hook(base + 214, StoreField("y_block_coord", base + 215), length=1)
    project.hook(
        base + 218, DecField("y_special_warp_offset", base + 219), length=1
    )
    project.hook(base + 222, LoadField("map_width", base + 225), length=3)
    project.hook(base + 225, PointerSummary(4, base + 228), length=3)
    project.hook(base + 228, Jump(DONE0), length=0)
    state = project.factory.blank_state(addr=base + 134)
    _setup_pointer(state, values)
    return _collect(project, state)


def _native_adjust_map(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_advance_player_sprite_adjust_map")
    names = (
        "port_move_tile_block_map_pointer_east",
        "port_move_tile_block_map_pointer_west",
        "port_move_tile_block_map_pointer_south",
        "port_move_tile_block_map_pointer_north",
    )
    callees = [project.loader.find_symbol(name) for name in names]
    assert function is not None and all(callees)
    for kind, callee in enumerate(callees, 1):
        assert callee is not None
        project.hook(callee.rebased_addr, NativePointerSummary(kind))
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    for offset, field in enumerate(AUX, 8):
        state.memory.store(NATIVE_STATE + offset, values[field])
    for register in REGISTERS:
        state.globals["pointer_out_" + register] = values[
            "pointer_out_" + register
        ]
    state.globals["pointer_out_low"] = values["pointer_out_low"]
    state.globals["pointer_out_high"] = values["pointer_out_high"]
    state.globals["call_kind"] = claripy.BVV(0, 8)
    state.globals["call_data"] = claripy.BVV(0, 80)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            aux=end.memory.load(NATIVE_STATE + 8, len(AUX)),
            continuation=claripy.BVV(0, 8),
            call_kind=end.globals["call_kind"],
            call_data=end.globals["call_data"],
            marker=claripy.BVV(0, 8),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


def _update_inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = _inputs(prefix)
    for kind, fields in (
        ("view", VIEW_FIELDS),
        ("schedule", SCHEDULE_FIELDS),
    ):
        for register in REGISTERS:
            values[f"{kind}_out_{register}"] = (
                claripy.Concat(
                    claripy.BVS(f"{prefix}_{kind}_out_flags", 4),
                    claripy.BVV(0, 4),
                )
                if register == "f"
                else claripy.BVS(f"{prefix}_{kind}_out_{register}", 8)
            )
        for field in fields:
            values[f"{kind}_out_{field}"] = (
                claripy.Concat(
                    claripy.BVS(f"{prefix}_{kind}_out_{field}_flags", 4),
                    claripy.BVV(0, 4),
                )
                if field == "view_saved_f"
                else claripy.BVS(f"{prefix}_{kind}_out_{field}", 8)
            )
        values[f"{kind}_out_marker"] = claripy.BVS(
            f"{prefix}_{kind}_out_marker", 8
        )
    values["marker"] = claripy.BVS(f"{prefix}_marker", 8)
    return values


def _setup_update(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    _setup(state, values)
    for kind, fields in (
        ("view", VIEW_FIELDS),
        ("schedule", SCHEDULE_FIELDS),
    ):
        for register in REGISTERS:
            state.globals[f"{kind}_out_{register}"] = values[
                f"{kind}_out_{register}"
            ]
        for field in fields:
            state.globals[f"{kind}_out_{field}"] = values[
                f"{kind}_out_{field}"
            ]
        state.globals[f"{kind}_out_marker"] = values[
            f"{kind}_out_marker"
        ]
    state.globals["marker"] = values["marker"]
    state.globals["view_call"] = claripy.BVV(0, 240)
    state.globals["schedule_call"] = claripy.BVV(0, 112)
    state.globals["call_data"] = claripy.BVV(0, 352)


def _assembly_update_view(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, base = _project()
    project.hook(base + 228, ViewSummary(base + 231), length=3)
    project.hook(base + 231, LoadField("y_step", base + 234), length=3)
    project.hook(base + 234, Sm83CpImmediate(1, base + 236), length=2)
    project.hook(base + 236, BranchEq("a", 1, base + 238, base + 243), length=2)
    project.hook(base + 238, ScheduleSummary(1, base + 241), length=3)
    project.hook(base + 241, Jump(base + 271), length=2)
    project.hook(base + 243, Sm83CpImmediate(0xFF, base + 245), length=2)
    project.hook(base + 245, BranchEq("a", 0xFF, base + 247, base + 252), length=2)
    project.hook(base + 247, ScheduleSummary(2, base + 250), length=3)
    project.hook(base + 250, Jump(base + 271), length=2)
    project.hook(base + 252, LoadField("x_step", base + 255), length=3)
    project.hook(base + 255, Sm83CpImmediate(1, base + 257), length=2)
    project.hook(base + 257, BranchEq("a", 1, base + 259, base + 264), length=2)
    project.hook(base + 259, ScheduleSummary(3, base + 262), length=3)
    project.hook(base + 262, Jump(base + 271), length=2)
    project.hook(base + 264, Sm83CpImmediate(0xFF, base + 266), length=2)
    project.hook(base + 266, BranchEq("a", 0xFF, base + 268, base + 271), length=2)
    project.hook(base + 268, ScheduleSummary(4, base + 271), length=3)
    project.hook(base + 271, FinishUpdateView(), length=0)
    state = project.factory.blank_state(addr=base + 228)
    _setup_update(state, values)
    state.memory.store(MARKER, values["marker"])
    return _collect(project, state)


def _native_update_view(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_advance_player_sprite_update_view")
    view = project.loader.find_symbol("port_load_current_map_view")
    schedule_names = (
        "port_schedule_south_row_redraw",
        "port_schedule_north_row_redraw",
        "port_schedule_east_column_redraw",
        "port_schedule_west_column_redraw",
    )
    schedules = [project.loader.find_symbol(name) for name in schedule_names]
    assert function is not None and view is not None and all(schedules)
    project.hook(view.rebased_addr, NativeViewSummary())
    for kind, schedule in enumerate(schedules, 1):
        assert schedule is not None
        project.hook(schedule.rebased_addr, NativeScheduleSummary(kind))
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    for offset, field in enumerate(AUX, 8):
        state.memory.store(NATIVE_STATE + offset, values[field])
    for kind, fields in (
        ("view", VIEW_FIELDS),
        ("schedule", SCHEDULE_FIELDS),
    ):
        for register in REGISTERS:
            state.globals[f"{kind}_out_{register}"] = values[
                f"{kind}_out_{register}"
            ]
        for field in fields:
            state.globals[f"{kind}_out_{field}"] = values[
                f"{kind}_out_{field}"
            ]
        state.globals[f"{kind}_out_marker"] = values[
            f"{kind}_out_marker"
        ]
    state.globals["call_kind"] = claripy.BVV(0, 8)
    state.globals["view_call"] = claripy.BVV(0, 240)
    state.globals["schedule_call"] = claripy.BVV(0, 112)
    state.memory.store(NATIVE_MEMORY + MARKER, values["marker"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            aux=end.memory.load(NATIVE_STATE + 8, len(AUX)),
            continuation=claripy.BVV(0, 8),
            call_kind=end.globals["call_kind"],
            call_data=claripy.Concat(
                end.globals["view_call"], end.globals["schedule_call"]
            ),
            marker=end.memory.load(NATIVE_MEMORY + MARKER, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


ASSEMBLY = {
    "begin": _assembly_begin,
    "adjust_vram": _assembly_adjust_vram,
    "scroll_begin": _assembly_scroll_begin,
    "shift_step": _assembly_shift_step,
}


def _native(stage: str, values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_advance_player_sprite_" + stage)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    for offset, field in enumerate(AUX, 8):
        state.memory.store(NATIVE_STATE + offset, values[field])
    state.globals["call_kind"] = claripy.BVV(0, 8)
    state.globals["call_data"] = claripy.BVV(0, 8)
    state.globals["marker"] = claripy.BVV(0, 8)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    returns = {
        "begin", "scroll_begin", "shift_step",
    }
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            aux=end.memory.load(NATIVE_STATE + 8, len(AUX)),
            continuation=(
                end.regs.rax[7:0] if stage in returns else claripy.BVV(0, 8)
            ),
            call_kind=end.globals["call_kind"],
            call_data=end.globals["call_data"],
            marker=end.globals["marker"],
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("stage", tuple(ASSEMBLY))
def test_advance_player_sprite_pathwise_equivalence(stage: str) -> None:
    location = symbol_location(SYMBOLS, "AdvancePlayerSprite")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    values = _inputs("advance_player_sprite_" + stage)
    assert_pathwise_equivalent(
        ASSEMBLY[stage](values),
        _native(stage, values),
        (*REGISTERS, "aux", "continuation"),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_advance_player_sprite_adjust_map_pathwise_equivalence() -> None:
    location = symbol_location(SYMBOLS, "AdvancePlayerSprite")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    values = _pointer_inputs("advance_player_sprite_adjust_map")
    assert_pathwise_equivalent(
        _assembly_adjust_map(values),
        _native_adjust_map(values),
        (*REGISTERS, "aux", "call_kind", "call_data"),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_advance_player_sprite_update_view_pathwise_equivalence() -> None:
    location = symbol_location(SYMBOLS, "AdvancePlayerSprite")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    values = _update_inputs("advance_player_sprite_update_view")
    assert_pathwise_equivalent(
        _assembly_update_view(values),
        _native_update_view(values),
        (*REGISTERS, "aux", "call_kind", "call_data", "marker"),
    )
