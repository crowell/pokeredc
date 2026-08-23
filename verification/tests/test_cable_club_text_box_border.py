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
MARKER = 0x1234
REPEAT = 0xEFFD
NEXT = 0xEFFE
DONE = 0xEFFF
EXPECTED = bytes.fromhex(
    "e53e78223ccde05a3c77e111140019e53e7b223e7fcde05a3677e11114001905"
    "20ed3e7c223e76cde05a367dc9"
)
FIELDS = (
    "saved_h", "saved_l", "written0", "written1",
    "write0_h", "write0_l", "write1_h", "write1_l",
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
    continuation: claripy.ast.BV
    call: claripy.ast.BV
    marker: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class Jump(angr.SimProcedure):
    def __init__(self, target: int):
        super().__init__()
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.jump(self.target)


class SaveHl(Jump):
    def run(self) -> None:  # type: ignore[override]
        self.state.globals["saved_h"] = self.state.regs.h
        self.state.globals["saved_l"] = self.state.regs.l
        self.jump(self.target)


class RestoreHl(SaveHl):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = self.state.globals["saved_h"]
        self.state.regs.l = self.state.globals["saved_l"]
        self.jump(self.target)


class LoadImmediate(Jump):
    def __init__(self, value: int, target: int):
        super().__init__(target)
        self.value = value

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.value
        self.jump(self.target)


class Write(Jump):
    def __init__(
        self, slot: int, target: int, value: int | None = None,
        increment: bool = False,
    ):
        super().__init__(target)
        self.slot = slot
        self.value = value
        self.increment = increment

    def run(self) -> None:  # type: ignore[override]
        value = self.state.regs.a if self.value is None else self.value
        self.state.globals[f"written{self.slot}"] = value
        self.state.globals[f"write{self.slot}_h"] = self.state.regs.h
        self.state.globals[f"write{self.slot}_l"] = self.state.regs.l
        if self.increment:
            self.state.regs.hl = self.state.regs.hl + 1
        self.jump(self.target)


class IncA(Jump):
    def run(self) -> None:  # type: ignore[override]
        old = self.state.regs.a
        self.state.regs.a = old + 1
        self.state.regs.f = (self.state.regs.f & 1) | claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x40, 8),
            claripy.BVV(0, 8),
        ) | claripy.If(
            (old & 0x0F) == 0x0F,
            claripy.BVV(0x10, 8),
            claripy.BVV(0, 8),
        )
        self.jump(self.target)


class HorizontalSummary(Jump):
    def run(self) -> None:  # type: ignore[override]
        registers = assembly_registers(self.state)
        self.state.globals["call"] = claripy.Concat(
            *(registers[register] for register in REGISTERS),
            self.state.globals["marker"],
        )
        for register in REGISTERS:
            value = self.state.globals["out_" + register]
            if register == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, register, value)
        self.state.globals["marker"] = self.state.globals["out_marker"]
        self.jump(self.target)


class NativeHorizontalSummary(angr.SimProcedure):
    def run(
        self, registers: claripy.ast.BV, memory: claripy.ast.BV | None = None
    ) -> None:  # type: ignore[override]
        if memory is None:
            memory = self.state.regs.rsi
        self.state.globals["call"] = claripy.Concat(
            self.state.memory.load(registers, 8),
            self.state.memory.load(memory + MARKER, 1),
        )
        self.state.memory.store(
            registers,
            claripy.Concat(
                *(self.state.globals["out_" + register]
                  for register in REGISTERS)
            ),
        )
        self.state.memory.store(
            memory + MARKER, self.state.globals["out_marker"]
        )


class SetDe20(Jump):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.d = 0
        self.state.regs.e = 20
        self.jump(self.target)


class AddHlDe(Jump):
    def run(self) -> None:  # type: ignore[override]
        left = self.state.regs.hl
        right = self.state.regs.de
        wide = claripy.ZeroExt(1, left) + claripy.ZeroExt(1, right)
        self.state.regs.hl = wide[15:0]
        self.state.regs.f = (self.state.regs.f & 0x40) | claripy.If(
            (left & 0x0FFF) + (right & 0x0FFF) > 0x0FFF,
            claripy.BVV(0x10, 8),
            claripy.BVV(0, 8),
        ) | claripy.ZeroExt(7, wide[16])
        self.jump(self.target)


class DecBBranch(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        old = self.state.regs.b
        result = old - 1
        flags = (self.state.regs.f & 1) | claripy.BVV(2, 8)
        flags |= claripy.If(
            result == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)
        )
        flags |= claripy.If(
            (old & 0x0F) == 0,
            claripy.BVV(0x10, 8),
            claripy.BVV(0, 8),
        )
        more = self.state.copy()
        done = self.state.copy()
        more.regs.b = result
        done.regs.b = result
        more.regs.f = flags
        done.regs.f = flags
        more.add_constraints(result != 0)
        done.add_constraints(result == 0)
        self.successors.add_successor(
            more, REPEAT, claripy.BoolV(True), "Ijk_Boring"
        )
        self.successors.add_successor(
            done, NEXT, claripy.BoolV(True), "Ijk_Boring"
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
    values["marker"] = claripy.BVS(f"{prefix}_marker", 8)
    values["out_marker"] = claripy.BVS(f"{prefix}_out_marker", 8)
    return values


def _setup_globals(
    state: angr.SimState, values: dict[str, claripy.ast.BV]
) -> None:
    for field in FIELDS:
        state.globals[field] = values[field]
    for register in REGISTERS:
        state.globals["out_" + register] = values["out_" + register]
    state.globals["marker"] = values["marker"]
    state.globals["out_marker"] = values["out_marker"]
    state.globals["call"] = claripy.BVV(0, 72)


def _project() -> tuple[angr.Project, int]:
    location = symbol_location(SYMBOLS, "CableClub_TextBoxBorder")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    return project, location.address


def _end(state: angr.SimState, continuation: int) -> Endpoint:
    return Endpoint(
        **assembly_registers(state),
        state=claripy.Concat(*(state.globals[field] for field in FIELDS)),
        continuation=claripy.BVV(continuation, 8),
        call=state.globals["call"], marker=state.globals["marker"],
        constraints=tuple(state.solver.constraints),
    )


def _assembly(stage: str, values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, q = _project()
    if stage == "top":
        project.hook(q, SaveHl(q + 1), length=1)
        project.hook(q + 1, LoadImmediate(0x78, q + 3), length=2)
        project.hook(q + 3, Write(0, q + 4, increment=True), length=1)
        project.hook(q + 4, IncA(q + 5), length=1)
        project.hook(q + 5, HorizontalSummary(q + 8), length=3)
        project.hook(q + 8, IncA(q + 9), length=1)
        project.hook(q + 9, Write(1, q + 10), length=1)
        project.hook(q + 10, RestoreHl(q + 11), length=1)
        project.hook(q + 11, SetDe20(q + 14), length=3)
        project.hook(q + 14, AddHlDe(NEXT), length=1)
        start, terminals = q, {NEXT: 1}
    elif stage == "row":
        project.hook(q + 15, SaveHl(q + 16), length=1)
        project.hook(q + 16, LoadImmediate(0x7B, q + 18), length=2)
        project.hook(q + 18, Write(0, q + 19, increment=True), length=1)
        project.hook(q + 19, LoadImmediate(0x7F, q + 21), length=2)
        project.hook(q + 21, HorizontalSummary(q + 24), length=3)
        project.hook(q + 24, Write(1, q + 26, value=0x77), length=2)
        project.hook(q + 26, RestoreHl(q + 27), length=1)
        project.hook(q + 27, SetDe20(q + 30), length=3)
        project.hook(q + 30, AddHlDe(q + 31), length=1)
        project.hook(q + 31, DecBBranch(), length=3)
        start, terminals = q + 15, {REPEAT: 1, NEXT: 0}
    else:
        project.hook(q + 34, LoadImmediate(0x7C, q + 36), length=2)
        project.hook(q + 36, Write(0, q + 37, increment=True), length=1)
        project.hook(q + 37, LoadImmediate(0x76, q + 39), length=2)
        project.hook(q + 39, HorizontalSummary(q + 42), length=3)
        project.hook(q + 42, Write(1, DONE, value=0x7D), length=2)
        start, terminals = q + 34, {DONE: 0}
    state = project.factory.blank_state(addr=start)
    set_assembly_registers(state, values)
    _setup_globals(state, values)
    manager = project.factory.simulation_manager(state)
    manager.stashes["finished"] = []
    while manager.active:
        manager.move(from_stash="active", to_stash="finished",
                     filter_func=lambda item: item.addr in terminals)
        if manager.active:
            manager.step()
    assert not manager.errored
    return [_end(end, terminals[end.addr]) for end in manager.finished]


def _native(stage: str, values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(
        "port_cable_club_text_box_border_" + stage
    )
    line = project.loader.find_symbol("port_cable_club_draw_horizontal_line")
    assert function is not None and line is not None
    project.hook(line.rebased_addr, NativeHorizontalSummary())
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
            continuation=(end.regs.rax[7:0] if stage == "row"
                          else claripy.BVV(1 if stage == "top" else 0, 8)),
            call=end.globals["call"],
            marker=end.memory.load(NATIVE_MEMORY + MARKER, 1),
            constraints=tuple(end.solver.constraints),
        ) for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("stage", ("top", "row", "bottom"))
def test_cable_club_text_box_border_pathwise_equivalence(stage: str) -> None:
    values = _inputs("cable_club_text_box_border_" + stage)
    assert_pathwise_equivalent(
        _assembly(stage, values), _native(stage, values),
        (*REGISTERS, "state", "continuation", "call", "marker"),
    )
