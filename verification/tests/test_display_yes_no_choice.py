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
from verification.harness.sm83_shims import Sm83StoreAImmediate

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xEFFF
W_TEXT_BOX_ID = 0xD125
H_AUTO_BG_TRANSFER_ENABLED = 0xFFBA
TILEMAP = 0xC3A0
BACKUP = 0xC508
SCREEN_AREA = 0x168
TRACE = 0xD200
TWO_OPTION_MENU = 0x14

INITIAL = symbolic_registers("display_yes_no_choice")
POST = symbolic_registers("display_yes_no_choice_post")


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
    display_call: claripy.ast.BV
    load_call: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _register_concat(state: angr.SimState) -> claripy.ast.BV:
    return claripy.Concat(*(assembly_registers(state)[name]
                            for name in REGISTERS))


def _set_assembly_post(state: angr.SimState) -> None:
    for name in REGISTERS:
        value = POST[name]
        setattr(state.regs, name,
                sm83_flags_to_z80(value) if name == "f" else value)


def _set_native_post(state: angr.SimState, pointer: claripy.ast.BV) -> None:
    for offset, name in enumerate(REGISTERS):
        state.memory.store(pointer + offset, POST[name])


class DisplayBoundary(angr.SimProcedure):
    """Compositional boundary for the independently tested text dispatcher."""

    def run(self) -> None:  # type: ignore[override]
        if self.state.arch.name.startswith("AMD64"):
            pointer = self.state.regs.rdi
            self.state.globals["display_call"] = claripy.Concat(*(
                self.state.memory.load(pointer + offset, 1)
                for offset in range(8)))
            self.state.memory.store(pointer + TRACE, claripy.BVV(1, 8))
            _set_native_post(self.state, pointer)
            self.ret()
            return
        self.state.globals["display_call"] = _register_concat(self.state)
        self.state.memory.store(TRACE, claripy.BVV(1, 8))
        _set_assembly_post(self.state)
        ret = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp += 2
        self.jump(ret)


class LoadBoundary(angr.SimProcedure):
    """Complete transition of the proven LoadScreenTilesFromBuffer1 callee."""

    def _copy_and_finish(self, memory: claripy.ast.BV,
                         set_registers) -> None:
        self.state.memory.store(memory + H_AUTO_BG_TRANSFER_ENABLED,
                                claripy.BVV(0, 8))
        for offset in range(SCREEN_AREA):
            byte = self.state.memory.load(memory + BACKUP + offset, 1)
            self.state.memory.store(memory + TILEMAP + offset, byte)
        self.state.memory.store(memory + H_AUTO_BG_TRANSFER_ENABLED,
                                claripy.BVV(1, 8))
        set_registers()
        self.state.memory.store(memory + TRACE, claripy.BVV(0x12, 8))

    def run(self) -> None:  # type: ignore[override]
        if self.state.arch.name.startswith("AMD64"):
            pointer = self.state.regs.rdi
            memory = self.state.regs.rsi
            self.state.globals["load_call"] = claripy.Concat(*(
                self.state.memory.load(pointer + offset, 1)
                for offset in range(8)))

            def finish() -> None:
                _set_native_post(self.state, pointer)
                for offset, value in enumerate((1, 0x80, 0, 0, 0xC5, 0x08,
                                                 0xC6, 0x70)):
                    self.state.memory.store(pointer + offset,
                                            claripy.BVV(value, 8))

            self._copy_and_finish(memory, finish)
            self.ret()
            return

        self.state.globals["load_call"] = _register_concat(self.state)

        def finish() -> None:
            self.state.regs.a = claripy.BVV(1, 8)
            self.state.regs.f = claripy.BVV(0x40, 8)  # canonical Z -> Z80 Z
            self.state.regs.b = claripy.BVV(0, 8)
            self.state.regs.c = claripy.BVV(0, 8)
            self.state.regs.d = claripy.BVV(0xC5, 8)
            self.state.regs.e = claripy.BVV(0x08, 8)
            self.state.regs.h = claripy.BVV(0xC6, 8)
            self.state.regs.l = claripy.BVV(0x70, 8)

        self._copy_and_finish(claripy.BVV(0, 64), finish)
        ret = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp += 2
        self.jump(ret)


def _setup(state: angr.SimState, base: int,
           source: list[claripy.ast.BV]) -> None:
    state.memory.store(base + W_TEXT_BOX_ID, claripy.BVV(0x99, 8))
    state.memory.store(base + H_AUTO_BG_TRANSFER_ENABLED, claripy.BVV(0xA5, 8))
    state.memory.store(base + TRACE, claripy.BVV(0, 8))
    state.memory.store(base + BACKUP, claripy.Concat(*source))
    state.memory.store(base + TILEMAP,
                       claripy.Concat(*(claripy.BVS(
                           f"display_yes_no_choice_tile{i}", 8)
                           for i in range(SCREEN_AREA))))
    state.memory.store(base + STACK, claripy.BVV(RETURN, 16),
                       endness="Iend_LE")


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        state.memory.load(base + W_TEXT_BOX_ID, 1),
        state.memory.load(base + H_AUTO_BG_TRANSFER_ENABLED, 1),
        state.memory.load(base + TRACE, 1),
        state.memory.load(base + TILEMAP, SCREEN_AREA),
        state.memory.load(base + BACKUP, SCREEN_AREA),
    )


def _endpoint(state: angr.SimState, *, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    fields = (native_registers(state, NATIVE_STATE) if native
              else assembly_registers(state))
    return Endpoint(
        **fields,
        memory=_memory(state, base),
        display_call=state.globals["display_call"],
        load_call=state.globals["load_call"],
        constraints=tuple(state.solver.constraints),
    )


def _assembly(source: list[claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "DisplayYesNoChoice")
    display = symbol_location(SYMBOLS, "DisplayTextBoxID")
    load = symbol_location(SYMBOLS, "LoadScreenTilesFromBuffer1")
    assert display.address == 0x30E8
    assert load.address == 0x3725
    expected = bytes.fromhex("3e14ea25d1cde830c32537")
    assert linked_bytes(ROM, location, len(expected)) == expected
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    project.hook(display.address, DisplayBoundary(), length=1)
    project.hook(load.address, LoadBoundary(), length=1)
    project.hook(location.address + 2,
                 Sm83StoreAImmediate(W_TEXT_BOX_ID, location.address + 5),
                 length=3)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, INITIAL)
    state.regs.sp = STACK
    _setup(state, 0, source)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN, num_find=1)
    assert not manager.errored and len(manager.found) == 1
    return [_endpoint(end, native=False) for end in manager.found]


def _native(source: list[claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_display_yes_no_choice")
    display = project.loader.find_symbol("port_display_text_box_id")
    load = project.loader.find_symbol("port_load_screen_tiles_from_buffer1")
    assert function is not None and display is not None and load is not None
    project.hook(display.rebased_addr, DisplayBoundary())
    project.hook(load.rebased_addr, LoadBoundary())
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, INITIAL)
    _setup(state, NATIVE_MEMORY, source)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [_endpoint(end, native=True) for end in manager.deadended]


@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
def test_display_yes_no_choice_pathwise_equivalence() -> None:
    source = [claripy.BVS(f"display_yes_no_choice_backup{i}", 8)
              for i in range(SCREEN_AREA)]
    assembly = _assembly(source)
    native = _native(source)
    assert_pathwise_equivalent(
        assembly, native,
        list(REGISTERS) + ["memory", "display_call", "load_call"],
    )
