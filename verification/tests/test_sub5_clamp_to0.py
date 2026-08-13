from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode
from pypcode import Context

from verification.harness.rom import (
    collect_returns,
    linked_bytes,
    rom_window,
    symbol_location,
    z80_flags_to_sm83,
)


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
    constraints: tuple[claripy.ast.Bool, ...]


def _assembly_endpoints(value: claripy.ast.BV) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "Sub5ClampTo0")
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
    state.regs.a = value
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")

    return [
        Endpoint(
            a=end.regs.a,
            f=z80_flags_to_sm83(end.regs.f),
            constraints=tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, GB_RETURN)
    ]


def _native_endpoints(value: claripy.ast.BV) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_sub5_clamp_to0")
    assert function is not None

    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    state.memory.store(NATIVE_STATE, value)
    state.memory.store(NATIVE_STATE + 1, claripy.BVV(0, 8))

    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert manager.deadended
    return [
        Endpoint(
            a=end.memory.load(NATIVE_STATE, 1),
            f=end.memory.load(NATIVE_STATE + 1, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


def _difference(left: Endpoint, right: Endpoint) -> claripy.ast.Bool:
    return claripy.Or(left.a != right.a, left.f != right.f)


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_sub5_clamp_to0_symbolic_equivalence() -> None:
    value = claripy.BVS("sub5_clamp_to0_a", 8)
    assembly = _assembly_endpoints(value)
    native = _native_endpoints(value)

    overlaps: list[tuple[int, int]] = []
    for assembly_index, assembly_end in enumerate(assembly):
        for native_index, native_end in enumerate(native):
            solver = claripy.Solver()
            solver.add(assembly_end.constraints)
            solver.add(native_end.constraints)
            if not solver.satisfiable():
                continue
            overlaps.append((assembly_index, native_index))
            solver.add(_difference(assembly_end, native_end))
            assert not solver.satisfiable()

    assert {left for left, _ in overlaps} == set(range(len(assembly)))
    assert {right for _, right in overlaps} == set(range(len(native)))


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_sub5_clamp_to0_uses_z80_compatible_instruction_encodings() -> None:
    location = symbol_location(SYMBOLS, "Sub5ClampTo0")
    code = linked_bytes(ROM, location, 7)
    instructions = Context("z80:LE:16:default").disassemble(
        code, location.address
    ).instructions

    assert [(instruction.mnem, instruction.body, instruction.length) for instruction in instructions] == [
        ("SUB", "0x5", 2),
        ("CP", "0xf0", 2),
        ("RET", "C", 1),
        ("XOR", "A", 1),
        ("RET", "", 1),
    ]
