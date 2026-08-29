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
)
from verification.harness.rom import linked_bytes, rom_window, symbol_location

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
RETURN = 0x7FFF
W_TEXT_PREDEF_FLAG = 0xCF11
W_LIST_MENU_ID = 0xCF94
W_CUR_MAP = 0xD35E
W_CUR_MAP_TEXT_PTR = 0xD36C
W_SPRITE_INDEX = 0xCF13
H_TEXT_ID = 0xFF8C
H_FRAME_COUNTER = 0xFFD5
H_LOADED_ROM_BANK = 0xFFB8
R_ROMB = 0x2000
STACK = 0xD000
EXPECTED = bytes.fromhex(
    "f0b8f50601219670cdd6352111cfcb46cb862006fa5ed3cdbc123e1ee0d"
    "5216cd32a666f1600f08cea13cf"
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
    text_predef: claripy.ast.BV
    list_menu: claripy.ast.BV
    frame_counter: claripy.ast.BV
    sprite_index: claripy.ast.BV
    loaded_bank: claripy.ast.BV
    romb: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class InitBoundary(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        old_bank = self.state.memory.load(H_LOADED_ROM_BANK, 1)
        old_f = self.state.regs.f
        self.state.memory.store(W_LIST_MENU_ID, claripy.BVV(0, 8))
        self.state.regs.b = old_bank
        self.state.regs.c = old_f
        self.state.memory.store(W_TEXT_PREDEF_FLAG, claripy.BVV(0, 8))
        self.state.memory.store(H_FRAME_COUNTER, claripy.BVV(30, 8))
        pointer = self.state.memory.load(W_CUR_MAP_TEXT_PTR, 2, endness="Iend_LE")
        self.state.regs.h = pointer[15:8]
        self.state.regs.l = pointer[7:0]
        self.state.regs.d = claripy.BVV(0, 8)
        self.state.regs.a = self.state.memory.load(H_TEXT_ID, 1)
        self.state.memory.store(W_SPRITE_INDEX, self.state.regs.a)
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)
        )
        self.inhibit_autoret = True
        self.jump(RETURN)


def _endpoint(state: angr.SimState, *, native: bool, base: int) -> Endpoint:
    registers = native_registers(state, NATIVE_STATE) if native else assembly_registers(state)
    return Endpoint(
        **registers,
        text_predef=state.memory.load(base + W_TEXT_PREDEF_FLAG, 1),
        list_menu=state.memory.load(base + W_LIST_MENU_ID, 1),
        frame_counter=state.memory.load(base + H_FRAME_COUNTER, 1),
        sprite_index=state.memory.load(base + W_SPRITE_INDEX, 1),
        loaded_bank=state.memory.load(base + H_LOADED_ROM_BANK, 1),
        romb=state.memory.load(base + R_ROMB, 1),
        constraints=tuple(state.solver.constraints),
    )


def _values() -> dict[str, claripy.ast.BV]:
    return {
        "a": claripy.BVV(0x23, 8), "f": claripy.BVV(0, 8),
        "b": claripy.BVV(0x45, 8), "c": claripy.BVV(0x67, 8),
        "d": claripy.BVV(0x89, 8), "e": claripy.BVV(0xAB, 8),
        "h": claripy.BVV(0xCD, 8), "l": claripy.BVV(0xEF, 8),
    }


def _setup(state: angr.SimState, base: int) -> None:
    state.memory.store(base + W_TEXT_PREDEF_FLAG, claripy.BVV(1, 8))
    state.memory.store(base + W_CUR_MAP, claripy.BVV(0, 8))
    state.memory.store(base + W_CUR_MAP_TEXT_PTR, claripy.BVV(0x34, 8))
    state.memory.store(base + W_CUR_MAP_TEXT_PTR + 1, claripy.BVV(0x12, 8))
    state.memory.store(base + H_TEXT_ID, claripy.BVV(2, 8))
    state.memory.store(base + H_LOADED_ROM_BANK, claripy.BVV(7, 8))
    state.memory.store(base + R_ROMB, claripy.BVV(5, 8))


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "DisplayTextID")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    base = location.address
    project.hook(base, InitBoundary(RETURN), length=0x2b)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _setup(state, 0)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=lambda candidate: candidate.addr == RETURN)
    assert not manager.errored and manager.found
    return [_endpoint(end, native=False, base=0) for end in manager.found]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_display_text_id")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, claripy.BVV(7, 8))
    state.memory.store(NATIVE_STATE + 9, claripy.BVV(5, 8))
    _setup(state, NATIVE_MEMORY)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and manager.deadended
    return [_endpoint(end, native=True, base=NATIVE_MEMORY) for end in manager.deadended]


@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_display_text_id_initialization_prefix_pathwise_equivalence() -> None:
    values = _values()
    assert_pathwise_equivalent(
        _assembly(values), _native(values),
        (*REGISTERS, "text_predef", "list_menu", "frame_counter",
         "sprite_index", "loaded_bank", "romb"),
    )
