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
from verification.harness.rom import collect_returns, rom_window, symbol_location

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
STACK = 0xD000
DONE = 0xEFFF


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
    constraints: tuple[claripy.ast.Bool, ...]


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "DoSpecialEffectByAnimationId.done")
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
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.Concat(values["b"], values["c"]), endness="Iend_LE")
    state.memory.store(STACK + 2, claripy.Concat(values["d"], values["e"]), endness="Iend_LE")
    state.memory.store(STACK + 4, claripy.Concat(values["h"], values["l"]), endness="Iend_LE")
    state.memory.store(STACK + 6, claripy.BVV(DONE, 16), endness="Iend_LE")
    returned = collect_returns(project, state, DONE)
    return [
        Endpoint(**assembly_registers(end), constraints=tuple(end.solver.constraints))
        for end in returned
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_do_special_effect_no_match")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(**native_registers(end, NATIVE_STATE), constraints=tuple(end.solver.constraints))
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_special_effect_no_match_pathwise_equivalence() -> None:
    values = symbolic_registers("special_effect_no_match")
    assert_pathwise_equivalent(_assembly(values), _native(values), REGISTERS)
