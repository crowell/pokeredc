from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
    REGISTERS, assembly_registers, native_registers, set_assembly_registers,
    store_native_registers, symbolic_registers,
)
from verification.harness.rom import (
    linked_bytes, rom_window, sm83_flags_to_z80, symbol_location,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xEFFF
W_TEXT_BOX_ID = 0xD125
PRINT_CURSOR = 0xC4B9
EXPECTED = bytes.fromhex("21c82acd493cc3d629")


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
    print_call: claripy.ast.BV
    after_call: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _register_concat(state: angr.SimState) -> claripy.ast.BV:
    return claripy.Concat(*(assembly_registers(state)[name]
                            for name in REGISTERS))


class PrintTextBoundary(angr.SimProcedure):
    def run(self, register_address=None, memory_address=None) -> None:  # type: ignore[override]
        if self.state.arch.name.startswith("AMD64"):
            pointer = self.state.regs.rdi
            memory = self.state.regs.rsi
            self.state.globals["print_call"] = claripy.Concat(*(
                self.state.memory.load(pointer + offset, 1)
                for offset in range(8)))
            self.state.memory.store(memory + W_TEXT_BOX_ID,
                                    claripy.BVV(1, 8))
            self.state.memory.store(pointer + 2,
                                    claripy.BVV(PRINT_CURSOR >> 8, 8))
            self.state.memory.store(pointer + 3,
                                    claripy.BVV(PRINT_CURSOR & 0xff, 8))
            return
        self.state.globals["print_call"] = _register_concat(self.state)
        self.state.memory.store(W_TEXT_BOX_ID, claripy.BVV(1, 8))
        self.state.regs.b = claripy.BVV(PRINT_CURSOR >> 8, 8)
        self.state.regs.c = claripy.BVV(PRINT_CURSOR & 0xff, 8)
        ret = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp = self.state.regs.sp + 2
        self.jump(ret)


class AfterDisplayingTextBoundary(angr.SimProcedure):
    def run(self, register_address=None, memory_address=None) -> None:  # type: ignore[override]
        if self.state.arch.name.startswith("AMD64"):
            pointer = self.state.regs.rdi
            self.state.globals["after_call"] = claripy.Concat(*(
                self.state.memory.load(pointer + offset, 1)
                for offset in range(8)))
            for offset, name in enumerate(REGISTERS):
                self.state.memory.store(pointer + offset,
                                        self.state.globals[f"out_{name}"])
            return
        self.state.globals["after_call"] = _register_concat(self.state)
        for name in REGISTERS:
            value = self.state.globals[f"out_{name}"]
            setattr(self.state.regs, name,
                    sm83_flags_to_z80(value) if name == "f" else value)
        self.inhibit_autoret = True
        self.jump(RETURN)


def _setup(state: angr.SimState, base: int,
           values: dict[str, claripy.ast.BV]) -> None:
    state.memory.store(base + W_TEXT_BOX_ID, values["textbox"])
    state.memory.store(base + STACK, claripy.BVV(RETURN, 16),
                      endness="Iend_LE")
    for name in REGISTERS:
        state.globals[f"out_{name}"] = values[f"out_{name}"]


def _endpoint(state: angr.SimState, *, native: bool, base: int) -> Endpoint:
    return Endpoint(
        **(native_registers(state, NATIVE_STATE)
           if native else assembly_registers(state)),
        memory=state.memory.load(base + W_TEXT_BOX_ID, 1),
        print_call=state.globals["print_call"],
        after_call=state.globals["after_call"],
        constraints=tuple(state.solver.constraints),
    )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "DisplayRepelWoreOffText")
    print_text = symbol_location(SYMBOLS, "PrintText")
    after = symbol_location(SYMBOLS, "AfterDisplayingTextID")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    project.hook(print_text.address, PrintTextBoundary(), length=3)
    project.hook(after.address, AfterDisplayingTextBoundary(), length=1)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.regs.sp = STACK
    _setup(state, 0, values)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN)
    assert not manager.errored and manager.found
    return [_endpoint(end, native=False, base=0) for end in manager.found]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_display_repel_wore_off_text")
    print_text = project.loader.find_symbol("port_print_text")
    after = project.loader.find_symbol("port_after_displaying_text_id")
    assert function is not None and print_text is not None and after is not None
    project.hook(print_text.rebased_addr, PrintTextBoundary())
    project.hook(after.rebased_addr, AfterDisplayingTextBoundary())
    state = project.factory.call_state(function.rebased_addr,
                                       NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, NATIVE_MEMORY, values)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and manager.deadended
    return [_endpoint(end, native=True, base=NATIVE_MEMORY)
            for end in manager.deadended]


@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),
                    reason="run `make red`")
def test_display_repel_wore_off_text_pathwise_equivalence() -> None:
    values = symbolic_registers("display_repel_wore_off_text")
    values["textbox"] = claripy.BVS("display_repel_wore_off_textbox", 8)
    for name in REGISTERS:
        values[f"out_{name}"] = (
            claripy.Concat(claripy.BVS("display_repel_wore_off_flags", 4),
                           claripy.BVV(0, 4))
            if name == "f" else
            claripy.BVS(f"display_repel_wore_off_out_{name}", 8)
        )
    assert_pathwise_equivalent(
        _assembly(values), _native(values),
        (*REGISTERS, "memory", "print_call", "after_call"),
    )
