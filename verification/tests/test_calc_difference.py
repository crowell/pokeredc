from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode
from pypcode import Context

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.rom import (
    collect_returns,
    linked_bytes,
    rom_window,
    symbol_location,
    z80_flags_to_sm83,
)
from verification.harness.sm83_shims import Sm83SubRegister


ROOT = Path(__file__).resolve().parents[2]
VERIFY = ROOT / "verification"
NATIVE_ELF = VERIFY / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
GB_STACK = 0xD000
GB_RETURN = 0xFFFF
NATIVE_STATE = 0x100000


@dataclass(frozen=True)
class Endpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _assembly_endpoints(a: claripy.ast.BV, b: claripy.ast.BV) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "CalcDifference")
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
    project.hook(
        location.address,
        Sm83SubRegister(register="b", next_address=location.address + 1),
        length=1,
    )
    state = project.factory.blank_state(addr=location.address)
    state.regs.a = a
    state.regs.b = b
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")

    return [
        Endpoint(
            a=end.regs.a,
            f=z80_flags_to_sm83(end.regs.f),
            b=end.regs.b,
            constraints=tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, GB_RETURN)
    ]


def _native_endpoints(a: claripy.ast.BV, b: claripy.ast.BV) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_calc_difference")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    state.memory.store(NATIVE_STATE + 0, a)
    state.memory.store(NATIVE_STATE + 1, claripy.BVV(0, 8))
    state.memory.store(NATIVE_STATE + 2, b)
    state.memory.store(NATIVE_STATE + 3, claripy.BVV(0, 8))

    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            a=end.memory.load(NATIVE_STATE + 0, 1),
            f=end.memory.load(NATIVE_STATE + 1, 1),
            b=end.memory.load(NATIVE_STATE + 2, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_calc_difference_symbolic_equivalence() -> None:
    a = claripy.BVS("calc_difference_a", 8)
    b = claripy.BVS("calc_difference_b", 8)
    assert_pathwise_equivalent(
        _assembly_endpoints(a, b), _native_endpoints(a, b), ("a", "f", "b")
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_calc_difference_uses_z80_compatible_instruction_encodings() -> None:
    location = symbol_location(SYMBOLS, "CalcDifference")
    instructions = Context("z80:LE:16:default").disassemble(
        linked_bytes(ROM, location, 7), location.address
    ).instructions
    assert [(item.mnem, item.body, item.length) for item in instructions] == [
        ("SUB", "B", 1),
        ("RET", "NC", 1),
        ("CPL", "", 1),
        ("ADD", "A, 0x1", 2),
        ("SCF", "", 1),
        ("RET", "", 1),
    ]
