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
    collect_returns,
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
RETURN = 0xEFFF
STACK = 0xD000
W_TEXT_BOX_ID = 0xD125
W_STATUS_FLAGS5 = 0xD730
W_UPDATE_SPRITES_ENABLED = 0xCFCB
FUNCTION_TABLE = 0x7387
COORD_TABLE = 0x7391
TEXT_TABLE = 0x73B0
TEXT_SOURCE = 0xC500
TILEMAP = 0xC3A0


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
    constraints: tuple[claripy.ast.Bool, ...]


class LoadTextBoxID(angr.SimProcedure):
    def run(self) -> None:
        self.state.regs.a = self.state.memory.load(W_TEXT_BOX_ID, 1)
        self.jump(self.state.addr + 3)


class SearchTextBoxTable(angr.SimProcedure):
    def run(self) -> None:
        hl = self.state.solver.eval(self.state.regs.hl)
        stride = (self.state.solver.eval(self.state.regs.de) - 1) & 0xFFFF
        wanted = self.state.solver.eval(self.state.regs.c)
        self.state.regs.de = claripy.BVV(stride, 16)
        value = 0
        found = False
        for _ in range(256):
            value = self.state.solver.eval(self.state.memory.load(hl, 1))
            if value == 0xFF:
                break
            if value == wanted:
                found = True
                break
            hl = (hl + 1 + stride) & 0xFFFF
        self.state.regs.a = claripy.BVV(value, 8)
        self.state.regs.hl = claripy.BVV((hl + 1) & 0xFFFF, 16)
        self.state.regs.f = sm83_flags_to_z80(
            claripy.BVV(0x10 if found else 0xC0, 8)
        )
        ret = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp = self.state.regs.sp + 2
        self.jump(ret)


class GetCoords(angr.SimProcedure):
    def run(self) -> None:
        hl = self.state.solver.eval(self.state.regs.hl)
        x0, y0, x1, y1 = [
            self.state.solver.eval(self.state.memory.load(hl + i, 1))
            for i in range(4)
        ]
        self.state.regs.e = claripy.BVV(x0, 8)
        self.state.regs.d = claripy.BVV(y0, 8)
        self.state.regs.c = claripy.BVV((x1 - x0 - 1) & 0xFF, 8)
        self.state.regs.b = claripy.BVV((y1 - y0 - 1) & 0xFF, 8)
        self.state.regs.hl = claripy.BVV((hl + 4) & 0xFFFF, 16)
        self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0x40, 8))
        ret = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp = self.state.regs.sp + 2
        self.jump(ret)


class GetText(angr.SimProcedure):
    def run(self) -> None:
        hl = self.state.solver.eval(self.state.regs.hl)
        text = self.state.solver.eval(self.state.memory.load(hl, 2, endness="Iend_LE"))
        column = self.state.solver.eval(self.state.memory.load(hl + 2, 1))
        row = self.state.solver.eval(self.state.memory.load(hl + 3, 1))
        self.state.regs.de = claripy.BVV(text, 16)
        self.state.regs.hl = claripy.BVV(TILEMAP + row * 20 + column, 16)
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0x80, 8))
        ret = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp = self.state.regs.sp + 2
        self.jump(ret)


class GetAddress(angr.SimProcedure):
    def run(self) -> None:
        row = self.state.solver.eval(self.state.regs.d)
        column = self.state.solver.eval(self.state.regs.e)
        self.state.regs.hl = claripy.BVV(TILEMAP + row * 20 + column, 16)
        self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0x80, 8))
        ret = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp = self.state.regs.sp + 2
        self.jump(ret)


class TextBoxBorder(angr.SimProcedure):
    def run(self) -> None:
        hl = self.state.solver.eval(self.state.regs.hl)
        height = self.state.solver.eval(self.state.regs.b)
        width = self.state.solver.eval(self.state.regs.c)
        row = hl
        self.state.memory.store(row, claripy.BVV(0x79, 8))
        for i in range(width):
            self.state.memory.store(row + 1 + i, claripy.BVV(0x7A, 8))
        self.state.memory.store(row + width + 1, claripy.BVV(0x7B, 8))
        for y in range(1, height + 1):
            base = row + y * 20
            self.state.memory.store(base, claripy.BVV(0x7C, 8))
            for i in range(width):
                self.state.memory.store(base + 1 + i, claripy.BVV(0x7F, 8))
            self.state.memory.store(base + width + 1, claripy.BVV(0x7C, 8))
        base = row + (height + 1) * 20
        self.state.memory.store(base, claripy.BVV(0x7D, 8))
        for i in range(width):
            self.state.memory.store(base + 1 + i, claripy.BVV(0x7A, 8))
        self.state.memory.store(base + width + 1, claripy.BVV(0x7E, 8))
        self.state.regs.a = claripy.BVV(0x7A, 8)
        self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0xC0, 8))
        self.state.regs.b = claripy.BVV(0, 8)
        self.state.regs.d = claripy.BVV(0, 8)
        self.state.regs.e = claripy.BVV(20, 8)
        self.state.regs.hl = claripy.BVV(base + width + 1, 16)
        ret = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp = self.state.regs.sp + 2
        self.jump(ret)


class LoadStatus(angr.SimProcedure):
    def run(self) -> None:
        self.state.regs.a = self.state.memory.load(W_STATUS_FLAGS5, 1)
        self.jump(self.state.addr + 3)


class StoreStatus(angr.SimProcedure):
    def run(self) -> None:
        self.state.memory.store(W_STATUS_FLAGS5, self.state.regs.a)
        self.jump(self.state.addr + 3)


class PlaceStore(angr.SimProcedure):
    def run(self) -> None:
        hl = self.state.regs.hl
        self.state.memory.store(hl, self.state.regs.a)
        self.state.regs.hl = hl + 1
        self.jump(self.state.addr + 1)


class PrintLetterDelay(angr.SimProcedure):
    def run(self) -> None:
        self.state.regs.sp = self.state.regs.sp + 2
        self.jump(0x19E8)


class IncrementDE(angr.SimProcedure):
    def run(self) -> None:
        self.state.regs.de = self.state.regs.de + 1
        self.jump(0x19E9)


class ReturnFromPlaceString(angr.SimProcedure):
    def run(self) -> None:
        ret = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp = self.state.regs.sp + 2
        self.jump(ret)


class ReturnCallee(angr.SimProcedure):
    def run(self) -> None:
        ret = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp = self.state.regs.sp + 2
        self.jump(ret)


class UpdateSprites(angr.SimProcedure):
    def run(self) -> None:
        before = self.state.solver.eval(self.state.memory.load(W_UPDATE_SPRITES_ENABLED, 1))
        value = (before - 1) & 0xFF
        self.state.regs.a = claripy.BVV(value, 8)
        flags = 0x40 | (0x20 if (before & 0x0F) == 0 else 0)
        if value == 0:
            flags |= 0x80
        self.state.regs.f = sm83_flags_to_z80(claripy.BVV(flags, 8))
        ret = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp = self.state.regs.sp + 2
        self.jump(ret)


def _setup(state: angr.SimState, base: int, text: bool = False, text_box_id: int | None = None) -> None:
    if text_box_id is None:
        text_box_id = 0x20 if text else 1
    state.memory.store(base + W_TEXT_BOX_ID, claripy.BVV(text_box_id, 8))
    state.memory.store(base + W_STATUS_FLAGS5, claripy.BVV(0, 8))
    state.memory.store(base + W_UPDATE_SPRITES_ENABLED, claripy.BVV(0, 8))
    state.memory.store(base + FUNCTION_TABLE, claripy.BVV(0xFF, 8))
    for i, value in enumerate((1, 0, 12, 19, 17, 0xFF)):
        state.memory.store(base + COORD_TABLE + i, claripy.BVV(value, 8))
    state.memory.store(base + TEXT_TABLE, claripy.BVV(0x20, 8))
    for i, value in enumerate((0, 0, 4, 2)):
        state.memory.store(base + TEXT_TABLE + 1 + i, claripy.BVV(value, 8))
    for i, value in enumerate((TEXT_SOURCE & 0xFF, TEXT_SOURCE >> 8, 1, 1)):
        state.memory.store(base + TEXT_TABLE + 5 + i, claripy.BVV(value, 8))
    state.memory.store(base + TEXT_TABLE + 9, claripy.BVV(0xFF, 8))
    state.memory.store(base + TEXT_SOURCE, claripy.BVV(0x41, 8))
    state.memory.store(base + TEXT_SOURCE + 1, claripy.BVV(0x50, 8))
    for i in range(0x100):
        state.memory.store(base + TILEMAP + i, claripy.BVV(0, 8))


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        state.memory.load(base + W_TEXT_BOX_ID, 1),
        state.memory.load(base + W_STATUS_FLAGS5, 1),
        state.memory.load(base + FUNCTION_TABLE, 1),
        state.memory.load(base + COORD_TABLE, 1),
        state.memory.load(base + TEXT_TABLE, 10),
        state.memory.load(base + TEXT_SOURCE, 2),
        state.memory.load(base + TILEMAP, 0x100),
    )


def _assembly(values: dict[str, claripy.ast.BV], text: bool = False, text_box_id: int | None = None) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "DisplayTextBoxID_")
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
    project.hook(location.address, LoadTextBoxID(), length=3)
    project.hook(0x734C, SearchTextBoxTable(), length=14)
    project.hook(0x735A, GetCoords(), length=13)
    project.hook(0x7367, GetText(), length=14)
    project.hook(0x7375, GetAddress(), length=18)
    project.hook(0x1922, TextBoxBorder(), length=51)
    if text:
        project.hook(0x7335, LoadStatus(), length=3)
        project.hook(0x7339, LoadStatus(), length=3)
        project.hook(0x733F, StoreStatus(), length=3)
        project.hook(0x7345, StoreStatus(), length=3)
        project.hook(0x19E4, PlaceStore(), length=1)
        project.hook(0x38D3, PrintLetterDelay(), length=3)
        project.hook(0x19E8, IncrementDE(), length=1)
        project.hook(0x195E, ReturnFromPlaceString(), length=1)
        project.hook(0x2429, UpdateSprites(), length=25)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    _setup(state, 0, text, text_box_id)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    return [
        Endpoint(**assembly_registers(end), memory=_memory(end, 0), constraints=tuple(end.solver.constraints))
        for end in collect_returns(project, state, RETURN)
    ]


def _native(values: dict[str, claripy.ast.BV], text: bool = False, text_box_id: int | None = None) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_display_text_box_id")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, NATIVE_MEMORY, text, text_box_id)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    end = manager.deadended[0]
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=_memory(end, NATIVE_MEMORY),
            constraints=tuple(end.solver.constraints),
        )
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_display_text_box_id_coordinate_pathwise_equivalence() -> None:
    values = {register: claripy.BVV(0, 8) for register in REGISTERS}
    values["f"] = claripy.BVV(0, 8)
    assert_pathwise_equivalent(_assembly(values), _native(values), (*REGISTERS, "memory"))


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_display_text_box_id_text_pathwise_equivalence() -> None:
    values = {register: claripy.BVV(0, 8) for register in REGISTERS}
    values["f"] = claripy.BVV(0, 8)
    assert_pathwise_equivalent(_assembly(values, text=True), _native(values, text=True), (*REGISTERS, "memory"))


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_display_text_box_id_no_match_pathwise_equivalence() -> None:
    values = {register: claripy.BVV(0, 8) for register in REGISTERS}
    values["f"] = claripy.BVV(0, 8)
    assert_pathwise_equivalent(_assembly(values, text_box_id=0xFE), _native(values, text_box_id=0xFE), (*REGISTERS, "memory"))
