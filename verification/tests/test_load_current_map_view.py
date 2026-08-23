from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

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
    Sm83AddHlRegisterPair,
    Sm83AddImmediate,
    Sm83AddRegister,
    Sm83DecRegister,
    Sm83IncRegister,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_DRAW = 0x110000
NATIVE_MEMORY = 0x120000
DONE = 0xEFFF
EXPECTED = bytes.fromhex(
    "f0b8f5fa2bd5e0b8ea0020fa5fd35ffa60d3572108c50605e5d50e06c5d5e51a"
    "4fcd1d0fe1d1c123232323130d20edd1fa69d3c606835f300114e13e60856f3001"
    "240520d32108c5010000fa63d3a7280401300009fa64d3a728040102000911a0c3"
    "06120e142a12130d20fa3e04856f3001240520eef1e0b8ea0020c9"
)

AUX = (
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
    "saved_a",
    "saved_f",
    "row_d",
    "row_e",
    "row_h",
    "row_l",
    "fetched_block",
    "fetched_copy",
    "written_copy",
    "write_h",
    "write_l",
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
    call_data: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class Jump(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.jump(self.next_address)


class LoadField(Jump):
    def __init__(self, field: str, next_address: int):
        super().__init__(next_address)
        self.field = field

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals[self.field]
        self.jump(self.next_address)


class StoreField(Jump):
    def __init__(self, field: str, next_address: int):
        super().__init__(next_address)
        self.field = field

    def run(self) -> None:  # type: ignore[override]
        self.state.globals[self.field] = self.state.regs.a
        self.jump(self.next_address)


class SaveAf(Jump):
    def run(self) -> None:  # type: ignore[override]
        registers = assembly_registers(self.state)
        self.state.globals["saved_a"] = registers["a"]
        self.state.globals["saved_f"] = registers["f"]
        self.jump(self.next_address)


class RestoreAf(Jump):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals["saved_a"]
        self.state.regs.f = sm83_flags_to_z80(self.state.globals["saved_f"])
        self.jump(self.next_address)


class SavePair(Jump):
    def __init__(self, pair: str, prefix: str, next_address: int):
        super().__init__(next_address)
        self.pair = pair
        self.prefix = prefix

    def run(self) -> None:  # type: ignore[override]
        self.state.globals[self.prefix + "_" + self.pair[0]] = getattr(
            self.state.regs, self.pair[0]
        )
        self.state.globals[self.prefix + "_" + self.pair[1]] = getattr(
            self.state.regs, self.pair[1]
        )
        self.jump(self.next_address)


class RestorePair(SavePair):
    def run(self) -> None:  # type: ignore[override]
        setattr(
            self.state.regs,
            self.pair[0],
            self.state.globals[self.prefix + "_" + self.pair[0]],
        )
        setattr(
            self.state.regs,
            self.pair[1],
            self.state.globals[self.prefix + "_" + self.pair[1]],
        )
        self.jump(self.next_address)


class BranchNonzero(angr.SimProcedure):
    def __init__(
        self, register: str, nonzero_target: int, zero_target: int
    ) -> None:
        super().__init__()
        self.register = register
        self.nonzero_target = nonzero_target
        self.zero_target = zero_target

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        value = getattr(self.state.regs, self.register)
        self.successors.add_successor(
            self.state.copy(), self.nonzero_target, value != 0, "Ijk_Boring"
        )
        self.successors.add_successor(
            self.state.copy(), self.zero_target, value == 0, "Ijk_Boring"
        )


class Sm83AndA(Jump):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x50, 8),
            claripy.BVV(0x10, 8),
        )
        self.jump(self.next_address)


class LoadFetchedBlock(Jump):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals["fetched_block"]
        self.jump(self.next_address)


class DrawSummary(Jump):
    def run(self) -> None:  # type: ignore[override]
        registers = assembly_registers(self.state)
        self.state.globals["call_data"] = claripy.Concat(
            *(registers[r] for r in REGISTERS),
            self.state.globals["tileset_blocks_low"],
            self.state.globals["tileset_blocks_high"],
        )
        for register in REGISTERS:
            value = self.state.globals["callee_" + register]
            if register == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, register, value)
        self.jump(self.next_address)


class LoadCopy(Jump):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals["fetched_copy"]
        self.state.regs.hl = self.state.regs.hl + 1
        self.jump(self.next_address)


class WriteCopy(Jump):
    def run(self) -> None:  # type: ignore[override]
        self.state.globals["written_copy"] = self.state.regs.a
        self.state.globals["write_h"] = self.state.regs.d
        self.state.globals["write_l"] = self.state.regs.e
        self.jump(self.next_address)


class NativeDrawSummary(angr.SimProcedure):
    def run(self, draw: claripy.ast.BV, _memory: claripy.ast.BV) -> None:  # type: ignore[override]
        self.state.globals["call_data"] = self.state.memory.load(draw, 10)
        for offset, register in enumerate(REGISTERS):
            self.state.memory.store(
                draw + offset, self.state.globals["callee_" + register]
            )


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for field in AUX:
        values[field] = (
            claripy.Concat(
                claripy.BVS(f"{prefix}_{field}_flags", 4), claripy.BVV(0, 4)
            )
            if field == "saved_f"
            else claripy.BVS(f"{prefix}_{field}", 8)
        )
    for register in REGISTERS:
        values["callee_" + register] = (
            claripy.Concat(
                claripy.BVS(f"{prefix}_callee_flags", 4), claripy.BVV(0, 4)
            )
            if register == "f"
            else claripy.BVS(f"{prefix}_callee_{register}", 8)
        )
    return values


def _setup_assembly(
    state: angr.SimState, values: dict[str, claripy.ast.BV]
) -> None:
    set_assembly_registers(state, values)
    for field in AUX:
        state.globals[field] = values[field]
    for register in REGISTERS:
        state.globals["callee_" + register] = values["callee_" + register]
    state.globals["call_data"] = claripy.BVV(0, 80)


def _endpoint(
    state: angr.SimState, continuation: claripy.ast.BV | int
) -> Endpoint:
    if isinstance(continuation, int):
        continuation = claripy.BVV(continuation, 8)
    return Endpoint(
        **assembly_registers(state),
        aux=claripy.Concat(*(state.globals[field] for field in AUX)),
        continuation=continuation,
        call_data=state.globals["call_data"],
        constraints=tuple(state.solver.constraints),
    )


def _project() -> tuple[angr.Project, int]:
    location = symbol_location(SYMBOLS, "LoadCurrentMapView")
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


def _collect(
    manager: angr.SimulationManager,
    targets: set[int],
    *,
    step_first: bool = False,
) -> list[angr.SimState]:
    manager.stashes["found"] = []
    if step_first:
        manager.step()
    while manager.active:
        manager.move(
            from_stash="active",
            to_stash="found",
            filter_func=lambda state: state.addr in targets,
        )
        if manager.active:
            manager.step()
    assert not manager.errored
    return manager.found


def _run_assembly(
    values: dict[str, claripy.ast.BV],
    start_offset: int,
    hook: Callable[[angr.Project, int], None],
    targets: dict[int, int],
    *,
    step_first: bool = False,
) -> list[Endpoint]:
    project, base = _project()
    hook(project, base)
    resolved_targets: dict[int, int] = {}
    for index, (target, continuation) in enumerate(targets.items()):
        if target < 0x100:
            sentinel = 0xEE00 + index
            project.hook(base + target, Jump(sentinel), length=0)
            resolved_targets[sentinel] = continuation
        else:
            resolved_targets[target] = continuation
    state = project.factory.blank_state(addr=base + start_offset)
    _setup_assembly(state, values)
    ends = _collect(
        project.factory.simulation_manager(state),
        set(resolved_targets),
        step_first=step_first,
    )
    return [
        _endpoint(
            end,
            resolved_targets[end.addr],
        )
        for end in ends
    ]


def _assembly_begin(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    def hooks(project: angr.Project, base: int) -> None:
        project.hook(base, LoadField("loaded_rom_bank", base + 2), length=2)
        project.hook(base + 2, SaveAf(base + 3), length=1)
        project.hook(base + 3, LoadField("tileset_bank", base + 6), length=3)
        project.hook(base + 6, StoreField("loaded_rom_bank", base + 8), length=2)
        project.hook(base + 8, StoreField("mapper_bank", base + 11), length=3)
        project.hook(
            base + 11, LoadField("map_view_pointer_low", base + 14), length=3
        )
        project.hook(
            base + 15, LoadField("map_view_pointer_high", base + 18), length=3
        )

    return _run_assembly(values, 0, hooks, {24: 0})


def _assembly_begin_render_row(
    values: dict[str, claripy.ast.BV]
) -> list[Endpoint]:
    def hooks(project: angr.Project, base: int) -> None:
        project.hook(base + 24, SavePair("hl", "row", base + 25), length=1)
        project.hook(base + 25, SavePair("de", "row", base + 26), length=1)

    return _run_assembly(values, 24, hooks, {28: 0})


def _assembly_draw_step(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    repeat = 0xED01
    complete = 0xED00

    def hooks(project: angr.Project, base: int) -> None:
        project.hook(base + 28, SavePair("bc", "stack_bc", base + 29), length=1)
        project.hook(base + 29, SavePair("de", "stack_de", base + 30), length=1)
        project.hook(base + 30, SavePair("hl", "stack_hl", base + 31), length=1)
        project.hook(base + 31, LoadFetchedBlock(base + 32), length=1)
        project.hook(base + 33, DrawSummary(base + 36), length=3)
        project.hook(base + 36, RestorePair("hl", "stack_hl", base + 37), length=1)
        project.hook(base + 37, RestorePair("de", "stack_de", base + 38), length=1)
        project.hook(base + 38, RestorePair("bc", "stack_bc", base + 39), length=1)
        project.hook(base + 44, Sm83DecRegister("c", base + 45), length=1)
        project.hook(
            base + 45, BranchNonzero("c", repeat, complete), length=2
        )

    return _run_assembly(values, 28, hooks, {repeat: 1, complete: 0})


def _assembly_next_render_row(
    values: dict[str, claripy.ast.BV]
) -> list[Endpoint]:
    def hooks(project: angr.Project, base: int) -> None:
        project.hook(base + 47, RestorePair("de", "row", base + 48), length=1)
        project.hook(base + 48, LoadField("map_width", base + 51), length=3)
        project.hook(base + 51, Sm83AddImmediate(6, base + 53), length=2)
        project.hook(base + 53, Sm83AddRegister("e", base + 54), length=1)
        project.hook(base + 57, Sm83IncRegister("d", base + 58), length=1)
        project.hook(base + 58, RestorePair("hl", "row", base + 59), length=1)
        project.hook(base + 61, Sm83AddRegister("l", base + 62), length=1)
        project.hook(base + 65, Sm83IncRegister("h", base + 66), length=1)
        project.hook(base + 66, Sm83DecRegister("b", base + 67), length=1)

    return _run_assembly(values, 47, hooks, {24: 1, 69: 0})


def _assembly_prepare_copy(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    def hooks(project: angr.Project, base: int) -> None:
        project.hook(base + 75, LoadField("y_block_coord", base + 78), length=3)
        project.hook(base + 78, Sm83AndA(base + 79), length=1)
        project.hook(base + 84, Sm83AddHlRegisterPair("bc", base + 85), length=1)
        project.hook(base + 85, LoadField("x_block_coord", base + 88), length=3)
        project.hook(base + 88, Sm83AndA(base + 89), length=1)
        project.hook(base + 94, Sm83AddHlRegisterPair("bc", base + 95), length=1)

    return _run_assembly(values, 69, hooks, {100: 0})


def _assembly_begin_copy_row(
    values: dict[str, claripy.ast.BV]
) -> list[Endpoint]:
    return _run_assembly(values, 100, lambda _p, _b: None, {102: 0})


def _assembly_copy_step(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    repeat = 0xEC01
    complete = 0xEC00

    def hooks(project: angr.Project, base: int) -> None:
        project.hook(base + 102, LoadCopy(base + 103), length=1)
        project.hook(base + 103, WriteCopy(base + 104), length=1)
        project.hook(base + 105, Sm83DecRegister("c", base + 106), length=1)
        project.hook(
            base + 106, BranchNonzero("c", repeat, complete), length=2
        )

    return _run_assembly(values, 102, hooks, {repeat: 1, complete: 0})


def _assembly_next_copy_row(
    values: dict[str, claripy.ast.BV]
) -> list[Endpoint]:
    def hooks(project: angr.Project, base: int) -> None:
        project.hook(base + 110, Sm83AddRegister("l", base + 111), length=1)
        project.hook(base + 114, Sm83IncRegister("h", base + 115), length=1)
        project.hook(base + 115, Sm83DecRegister("b", base + 116), length=1)

    return _run_assembly(values, 108, hooks, {100: 1, 118: 0})


def _assembly_finish(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    def hooks(project: angr.Project, base: int) -> None:
        project.hook(base + 118, RestoreAf(base + 119), length=1)
        project.hook(base + 119, StoreField("loaded_rom_bank", base + 121), length=2)
        project.hook(base + 121, StoreField("mapper_bank", base + 124), length=3)
        project.hook(base + 124, Jump(DONE), length=1)

    return _run_assembly(values, 118, hooks, {DONE: 0})


ASSEMBLY = {
    "begin": _assembly_begin,
    "begin_render_row": _assembly_begin_render_row,
    "draw_step": _assembly_draw_step,
    "next_render_row": _assembly_next_render_row,
    "prepare_copy": _assembly_prepare_copy,
    "begin_copy_row": _assembly_begin_copy_row,
    "copy_step": _assembly_copy_step,
    "next_copy_row": _assembly_next_copy_row,
    "finish": _assembly_finish,
}


def _native(
    stage: str, values: dict[str, claripy.ast.BV]
) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_load_current_map_view_" + stage)
    assert function is not None
    draw_function = project.loader.find_symbol("port_draw_tile_block")
    assert draw_function is not None
    if stage == "draw_step":
        project.hook(draw_function.rebased_addr, NativeDrawSummary())
        state = project.factory.call_state(
            function.rebased_addr, NATIVE_STATE, NATIVE_DRAW, NATIVE_MEMORY
        )
    else:
        state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    for offset, field in enumerate(AUX, 8):
        state.memory.store(NATIVE_STATE + offset, values[field])
    for register in REGISTERS:
        state.globals["callee_" + register] = values["callee_" + register]
    state.globals["call_data"] = claripy.BVV(0, 80)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    endpoints = []
    for end in manager.deadended:
        continuation = (
            end.regs.rax[7:0]
            if stage in {
                "draw_step",
                "next_render_row",
                "copy_step",
                "next_copy_row",
            }
            else claripy.BVV(0, 8)
        )
        endpoints.append(
            Endpoint(
                **native_registers(end, NATIVE_STATE),
                aux=end.memory.load(NATIVE_STATE + 8, len(AUX)),
                continuation=continuation,
                call_data=end.globals["call_data"],
                constraints=tuple(end.solver.constraints),
            )
        )
    return endpoints


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("stage", tuple(ASSEMBLY))
def test_load_current_map_view_pathwise_equivalence(stage: str) -> None:
    location = symbol_location(SYMBOLS, "LoadCurrentMapView")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    values = _inputs("load_current_map_view_" + stage)
    observables = (*REGISTERS, "aux", "continuation")
    if stage == "draw_step":
        observables += ("call_data",)
    assert_pathwise_equivalent(
        ASSEMBLY[stage](values), _native(stage, values), observables
    )
