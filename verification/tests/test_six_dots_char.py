from __future__ import annotations

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
from verification.tests.test_print_player_name import Endpoint, PlaceCommandBoundary

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xEFFF
DESTINATION = 0xC400


def _assembly(values: dict[str, claripy.ast.BV]):
    location = symbol_location(SYMBOLS, "SixDotsChar")
    target = symbol_location(SYMBOLS, "PlaceCommandCharacter")
    expected = bytes.fromhex("d5116f1a1822")
    assert linked_bytes(ROM, location, len(expected)) == expected
    assert target.address == 0x1A4B
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
    state.regs.l = claripy.BVV(DESTINATION & 0xFF, 8)
    state.regs.sp = STACK
    state.memory.store(STACK + 2, claripy.BVV(RETURN, 16),
                       endness="Iend_LE")
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN, num_find=1)
    assert not manager.errored and len(manager.found) == 1
    end = manager.found[0]
    return [Endpoint(**assembly_registers(end),
                     callee_call=end.globals["callee_call"],
                     constraints=tuple(end.solver.constraints))]


def _native(values: dict[str, claripy.ast.BV]):
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_six_dots_char")
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
    end = manager.deadended[0]
    return [Endpoint(**native_registers(end, NATIVE_STATE),
                     callee_call=end.globals["callee_call"],
                     constraints=tuple(end.solver.constraints))]


@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
def test_six_dots_char_pathwise_equivalence() -> None:
    values = symbolic_registers("six_dots_char")
    values["h"] = claripy.BVV(DESTINATION >> 8, 8)
    values["l"] = claripy.BVV(DESTINATION & 0xFF, 8)
    assert_pathwise_equivalent(
        _assembly(values), _native(values), list(REGISTERS) + ["callee_call"])
