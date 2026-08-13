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
    sm83_flags_to_z80,
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
REGISTERS = ("a", "f", "b", "c", "d", "e", "h", "l")


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


def _assembly_endpoint(inputs: dict[str, claripy.ast.BV]) -> Endpoint:
    location = symbol_location(SYMBOLS, "WaitLoop_15Iterations")
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
    for register in REGISTERS:
        value = inputs[register]
        if register == "f":
            value = sm83_flags_to_z80(value)
        setattr(state.regs, register, value)
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    assert len(returned) == 1
    end = returned[0]
    values = {register: getattr(end.regs, register) for register in REGISTERS}
    values["f"] = z80_flags_to_sm83(end.regs.f)
    return Endpoint(**values, constraints=tuple(end.solver.constraints))


def _native_endpoint(inputs: dict[str, claripy.ast.BV]) -> Endpoint:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_wait_loop_15_iterations")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    for offset, register in enumerate(REGISTERS):
        state.memory.store(NATIVE_STATE + offset, inputs[register])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    end = manager.deadended[0]
    values = {
        register: end.memory.load(NATIVE_STATE + offset, 1)
        for offset, register in enumerate(REGISTERS)
    }
    return Endpoint(**values, constraints=tuple(end.solver.constraints))


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_wait_loop_15_iterations_symbolic_equivalence() -> None:
    inputs = {
        register: (
            claripy.Concat(claripy.BVS("wait_loop_flags", 4), claripy.BVV(0, 4))
            if register == "f"
            else claripy.BVS(f"wait_loop_{register}", 8)
        )
        for register in REGISTERS
    }
    assert_pathwise_equivalent(
        [_assembly_endpoint(inputs)], [_native_endpoint(inputs)], REGISTERS
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_wait_loop_15_iterations_uses_z80_compatible_encodings() -> None:
    location = symbol_location(SYMBOLS, "WaitLoop_15Iterations")
    instructions = Context("z80:LE:16:default").disassemble(
        linked_bytes(ROM, location, 6), location.address
    ).instructions
    assert [(item.mnem, item.body, item.length) for item in instructions] == [
        ("LD", "A,0xf", 2),
        ("DEC", "A", 1),
        ("JR", "NZ,0x2233", 2),
        ("RET", "", 1),
    ]
