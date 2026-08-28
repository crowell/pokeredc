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
from verification.harness.rom import linked_bytes, rom_window, symbol_location

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xEFFF
W_PLAYER_NAME = 0xD158
DESTINATION = 0xC400


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
    callee_call: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _register_concat(state: angr.SimState) -> claripy.ast.BV:
    return claripy.Concat(*(assembly_registers(state)[name]
                            for name in REGISTERS))


class PlaceCommandBoundary(angr.SimProcedure):
    """Compositional boundary for the existing PlaceCommandCharacter port."""

    def run(self) -> None:  # type: ignore[override]
        if self.state.arch.name.startswith("AMD64"):
            pointer = self.state.regs.rdi
            self.state.globals["callee_call"] = claripy.Concat(
                *(self.state.memory.load(pointer + offset, 1)
                  for offset in range(8)),
                self.state.memory.load(pointer + 8, 1),
                self.state.memory.load(pointer + 9, 1),
            )
            self.ret()
            return
        self.state.globals["callee_call"] = claripy.Concat(
            _register_concat(self.state),
            self.state.memory.load(self.state.regs.sp + 1, 1),
            self.state.memory.load(self.state.regs.sp, 1),
        )
        self.inhibit_autoret = True
        self.jump(RETURN)


def _endpoint(state: angr.SimState, *, native: bool) -> Endpoint:
    fields = (native_registers(state, NATIVE_STATE) if native
              else assembly_registers(state))
    return Endpoint(**fields, callee_call=state.globals["callee_call"],
                    constraints=tuple(state.solver.constraints))


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "PrintPlayerName")
    target = symbol_location(SYMBOLS, "PlaceCommandCharacter")
    assert target.address == 0x1A4B
    expected = bytes.fromhex("d51158d1184c")
    assert linked_bytes(ROM, location, len(expected)) == expected
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    project.hook(target.address, PlaceCommandBoundary(), length=1)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.regs.h = claripy.BVV(DESTINATION >> 8, 8)
    state.regs.l = claripy.BVV(DESTINATION, 8)
    state.regs.sp = STACK
    state.memory.store(STACK + 2, claripy.BVV(RETURN, 16),
                       endness="Iend_LE")
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN, num_find=1)
    assert not manager.errored and len(manager.found) == 1
    return [_endpoint(end, native=False) for end in manager.found]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_print_player_name")
    callee = project.loader.find_symbol("port_place_command_character")
    assert function is not None and callee is not None
    project.hook(callee.rebased_addr, PlaceCommandBoundary())
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE,
                                       NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [_endpoint(end, native=True) for end in manager.deadended]


@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
def test_print_player_name_pathwise_equivalence() -> None:
    values = symbolic_registers("print_player_name")
    values["h"] = claripy.BVV(DESTINATION >> 8, 8)
    values["l"] = claripy.BVV(DESTINATION & 0xFF, 8)
    assert_pathwise_equivalent(
        _assembly(values), _native(values),
        list(REGISTERS) + ["callee_call"],
    )
