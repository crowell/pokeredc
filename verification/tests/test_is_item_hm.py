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
from verification.harness.sm83_shims import Sm83CpImmediate


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


def _assembly_endpoints(a: claripy.ast.BV) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "IsItemHM")
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
    # The second comparison's H flag is observable at return. The bundled Z80
    # SLEIGH definition incorrectly clears it for every CP.
    project.hook(
        location.address + 4,
        Sm83CpImmediate(immediate=0xC9, next_address=location.address + 6),
        length=2,
    )
    state = project.factory.blank_state(addr=location.address)
    state.regs.a = a
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


def _native_endpoints(a: claripy.ast.BV) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_is_item_hm")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    state.memory.store(NATIVE_STATE, a)
    state.memory.store(NATIVE_STATE + 1, claripy.BVV(0, 8))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            a=end.memory.load(NATIVE_STATE, 1),
            f=end.memory.load(NATIVE_STATE + 1, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_is_item_hm_symbolic_equivalence() -> None:
    a = claripy.BVS("is_item_hm_a", 8)
    assert_pathwise_equivalent(
        _assembly_endpoints(a), _native_endpoints(a), ("a", "f")
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_is_item_hm_uses_z80_compatible_instruction_encodings() -> None:
    location = symbol_location(SYMBOLS, "IsItemHM")
    instructions = Context("z80:LE:16:default").disassemble(
        linked_bytes(ROM, location, 9), location.address
    ).instructions
    assert [(item.mnem, item.body, item.length) for item in instructions] == [
        ("CP", "0xc4", 2),
        ("JR", "C,0x3047", 2),
        ("CP", "0xc9", 2),
        ("RET", "", 1),
        ("AND", "A", 1),
        ("RET", "", 1),
    ]
