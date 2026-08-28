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
    rom_window,
    sm83_flags_to_z80,
    symbol_location,
)
from verification.harness.sm83_shims import Sm83StoreAImmediate

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xEFFF
W_STATUS_FLAGS5 = 0xD730
W_TEXT_BOX_ID = 0xD125
W_PLAYER_MONEY = 0xD347
FUNCTION_TABLE = 0x7387
TILEMAP = 0xC3A0
DISPLAY_MONEY_BOX = 0x74BA


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
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(W_TEXT_BOX_ID, 1)
        self.jump(self.state.addr + 3)


class SearchFunctionTable(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        hl = self.state.solver.eval(self.state.regs.hl)
        wanted = self.state.solver.eval(self.state.regs.c)
        for _ in range(256):
            value = self.state.solver.eval(self.state.memory.load(hl, 1))
            if value == 0xFF:
                self.state.regs.a = claripy.BVV(value, 8)
                self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0xC0, 8))
                break
            if value == wanted:
                self.state.regs.a = claripy.BVV(value, 8)
                self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0x10, 8))
                hl += 1
                break
            hl += 3
        self.state.regs.hl = claripy.BVV(hl & 0xFFFF, 16)
        ret = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp += 2
        self.jump(ret)


class JumpDisplayMoneyBox(angr.SimProcedure):
    """Model the dispatcher’s eight-byte function-pointer load and call."""

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.hl = claripy.BVV(DISPLAY_MONEY_BOX, 16)
        self.state.regs.sp -= 2
        self.state.memory.store(
            self.state.regs.sp, claripy.BVV(0x7314, 16), endness="Iend_LE"
        )
        self.jump(DISPLAY_MONEY_BOX)


class ReturnCallee(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        ret = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp += 2
        self.jump(ret)


class NativeReturn(angr.SimProcedure):
    def run(self, *args: claripy.ast.BV) -> None:  # type: ignore[override]
        self.ret()


def _setup(state: angr.SimState, base: int) -> None:
    state.memory.store(base + W_STATUS_FLAGS5, claripy.BVV(0xA5, 8))
    state.memory.store(base + W_TEXT_BOX_ID, claripy.BVV(0x13, 8))
    state.memory.store(base + W_PLAYER_MONEY, claripy.BVV(0x12, 8))
    state.memory.store(base + W_PLAYER_MONEY + 1, claripy.BVV(0x34, 8))
    state.memory.store(base + W_PLAYER_MONEY + 2, claripy.BVV(0x56, 8))
    table = (0x13, DISPLAY_MONEY_BOX & 0xFF, DISPLAY_MONEY_BOX >> 8,
             0x15, 0, 0, 0x04, 0, 0, 0xFF)
    for i, value in enumerate(table):
        state.memory.store(base + FUNCTION_TABLE + i, claripy.BVV(value, 8))
    for i in range(0x100):
        state.memory.store(base + TILEMAP + i, claripy.BVV((0x20 + i) & 0xFF, 8))


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        state.memory.load(base + W_STATUS_FLAGS5, 1),
        state.memory.load(base + W_TEXT_BOX_ID, 1),
        state.memory.load(base + W_PLAYER_MONEY, 3),
        state.memory.load(base + TILEMAP, 0x100),
    )


def _endpoint(state: angr.SimState, *, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    fields = native_registers(state, NATIVE_STATE) if native else assembly_registers(state)
    return Endpoint(**fields, memory=_memory(state, base), constraints=tuple(state.solver.constraints))


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "DisplayTextBoxID_")
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    project.hook(location.address, LoadTextBoxID(), length=3)
    project.hook(0x734C, SearchFunctionTable(), length=14)
    project.hook(0x7315, JumpDisplayMoneyBox(), length=8)
    project.hook(DISPLAY_MONEY_BOX + 7,
                 Sm83StoreAImmediate(W_TEXT_BOX_ID, DISPLAY_MONEY_BOX + 10),
                 length=3)
    project.hook(0x30E8, ReturnCallee(), length=8)
    project.hook(0x18C4, ReturnCallee(), length=20)
    project.hook(0x15CD, ReturnCallee(), length=55)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    _setup(state, 0)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN, num_find=1)
    assert not manager.errored and len(manager.found) == 1
    return [_endpoint(end, native=False) for end in manager.found]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_display_text_box_id_money_dispatch")
    display = project.loader.find_symbol("port_display_text_box_id")
    clear = project.loader.find_symbol("port_clear_screen_area")
    bcd = project.loader.find_symbol("port_print_bcd_number")
    assert function is not None and display is not None and clear is not None and bcd is not None
    project.hook(display.rebased_addr, NativeReturn())
    project.hook(clear.rebased_addr, NativeReturn())
    project.hook(bcd.rebased_addr, NativeReturn())
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, NATIVE_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [_endpoint(end, native=True) for end in manager.deadended]


@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_display_text_box_id_money_dispatch_pathwise_equivalence() -> None:
    values = symbolic_registers("display_text_box_id_money_dispatch")
    assert_pathwise_equivalent(_assembly(values), _native(values), (*REGISTERS, "memory"))
