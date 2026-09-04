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
from verification.harness.rom import linked_bytes, rom_window, sm83_flags_to_z80, symbol_location
from verification.harness.sm83_shims import Sm83StoreAImmediate

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xEFFF

W_SAVE_STATUS = 0xD088
W_STATUS_FLAGS5 = 0xD730
CONTROL_BASE = 0xF100
EXPECTED = bytes.fromhex(
    "cd0f19cd8036cda036cd2376380ecd90763809cdbd7638043e021816"
    "2130d7e5cbf6211e76cd493c0e64cd3937e1cbb63e01ea"
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
    memory: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class ReturnCallee(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        ret = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp = self.state.regs.sp + 2
        self.jump(ret)


class NativeNoop(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        return


class LoaderBoundary(angr.SimProcedure):
    def __init__(self, control_offset: int, native: bool) -> None:
        super().__init__()
        self.control_offset = control_offset
        self.native = native

    def run(self, register_address=None, memory_address=None) -> None:  # type: ignore[override]
        if self.native:
            register_address = self.state.regs.rdi
            memory_address = self.state.regs.rsi
            control = self.state.memory.load(memory_address + CONTROL_BASE +
                                             self.control_offset, 1)
            self.state.memory.store(register_address + 1,
                                    claripy.If(control != 0, claripy.BVV(0x10, 8),
                                               claripy.BVV(0, 8)))
            self.state.memory.store(register_address + 0, claripy.BVV(0x44, 8))
            return

        control = self.state.memory.load(CONTROL_BASE + self.control_offset, 1)
        self.state.regs.a = claripy.BVV(0x44, 8)
        self.state.regs.f = sm83_flags_to_z80(claripy.If(
            control != 0, claripy.BVV(0x10, 8), claripy.BVV(0, 8)))
        ret = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp = self.state.regs.sp + 2
        self.jump(ret)


class PrintTextBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        if self.state.arch.name.startswith("AMD64"):
            register_address = self.state.regs.rdi
            memory_address = self.state.regs.rsi
            self.state.memory.store(memory_address + 0xD125, claripy.BVV(1, 8))
            self.state.memory.store(register_address + 2, claripy.BVV(0xC4, 8))
            self.state.memory.store(register_address + 3, claripy.BVV(0x61, 8))
            return
        self.state.memory.store(0xD125, claripy.BVV(1, 8))
        self.state.regs.b = claripy.BVV(0xC4, 8)
        self.state.regs.c = claripy.BVV(0x61, 8)
        ret = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp = self.state.regs.sp + 2
        self.jump(ret)


class DelayBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        if self.state.arch.name.startswith("AMD64"):
            register_address = self.state.regs.rdi
            self.state.memory.store(register_address + 3, claripy.BVV(0, 8))
            self.state.memory.store(register_address + 1, claripy.BVV(0xC0, 8))
            return
        self.state.regs.c = 0
        self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0xC0, 8))
        ret = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp = self.state.regs.sp + 2
        self.jump(ret)


def _setup(state: angr.SimState, base: int, controls: tuple[int, int, int]) -> None:
    state.memory.store(base + W_SAVE_STATUS, claripy.BVV(0xA5, 8))
    state.memory.store(base + W_STATUS_FLAGS5, claripy.BVV(0x20, 8))
    for offset, value in enumerate(controls):
        state.memory.store(base + CONTROL_BASE + offset, claripy.BVV(value, 8))


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        state.memory.load(base + W_SAVE_STATUS, 1),
        state.memory.load(base + W_STATUS_FLAGS5, 1),
        state.memory.load(base + CONTROL_BASE, 3),
    )


def _endpoint(state: angr.SimState, *, native: bool, base: int) -> Endpoint:
    return Endpoint(
        **(native_registers(state, NATIVE_STATE) if native else assembly_registers(state)),
        memory=_memory(state, base),
        constraints=tuple(state.solver.constraints),
    )


def _assembly(values: dict[str, claripy.ast.BV], controls: tuple[int, int, int]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "TryLoadSaveFile")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    b = location.address
    project.hook(b + 0x32, Sm83StoreAImmediate(W_SAVE_STATUS, b + 0x35), length=3)
    project.hook(0x190F, ReturnCallee(), length=3)
    project.hook(0x3680, ReturnCallee(), length=3)
    project.hook(0x36A0, ReturnCallee(), length=3)
    project.hook(0x7623, LoaderBoundary(0, False), length=3)
    project.hook(0x7690, LoaderBoundary(1, False), length=3)
    project.hook(0x76BD, LoaderBoundary(2, False), length=3)
    project.hook(0x3C49, PrintTextBoundary(), length=3)
    project.hook(0x3739, DelayBoundary(), length=3)
    state = project.factory.blank_state(addr=b)
    set_assembly_registers(state, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    _setup(state, 0, controls)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN, num_find=4)
    assert not manager.errored and manager.found
    return [_endpoint(end, native=False, base=0) for end in manager.found]


def _native(values: dict[str, claripy.ast.BV], controls: tuple[int, int, int]) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_try_load_save_file")
    assert function is not None
    for name, offset in (
        ("port_load_main_data", 0),
        ("port_load_current_box_data", 1),
        ("port_load_party_and_dex_data", 2),
    ):
        symbol = project.loader.find_symbol(name)
        assert symbol is not None
        project.hook(symbol.rebased_addr, LoaderBoundary(offset, True))
    clear = project.loader.find_symbol("port_clear_screen")
    font = project.loader.find_symbol("port_load_font_tile_patterns")
    textbox = project.loader.find_symbol("port_load_text_box_tile_patterns")
    print_text = project.loader.find_symbol("port_print_text")
    delay = project.loader.find_symbol("port_delay_frames")
    assert clear is not None and font is not None and textbox is not None
    assert print_text is not None and delay is not None
    for symbol in (clear, font, textbox):
        project.hook(symbol.rebased_addr, NativeNoop())
    project.hook(print_text.rebased_addr, PrintTextBoundary())
    project.hook(delay.rebased_addr, DelayBoundary())
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, NATIVE_MEMORY, controls)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and manager.deadended
    return [_endpoint(end, native=True, base=NATIVE_MEMORY)
            for end in manager.deadended]


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),
                    reason="build artifacts missing")
@pytest.mark.parametrize("controls", (
    (0, 0, 0),
    (1, 0, 0),
    (0, 1, 0),
    (0, 0, 1),
))
def test_try_load_save_file_pathwise_equivalence(controls: tuple[int, int, int]) -> None:
    values = symbolic_registers(f"try_load_save_file_{controls}")
    assert_pathwise_equivalent(
        _assembly(values, controls), _native(values, controls),
        (*REGISTERS, "memory"),
    )
