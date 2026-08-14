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
from verification.harness.sm83_shims import Sm83CpAtHl


ROOT = Path(__file__).resolve().parents[2]
VERIFY = ROOT / "verification"
NATIVE_ELF = VERIFY / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"

GB_STACK = 0xD000
GB_RETURN = 0xFFFF
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000

# StringCmp lives at a fixed bank-0 address; its CP (HL) opcode needs the
# same half-carry correction the StringCmp proof applies.
STRING_CMP = 0x3A8E
CP_HL_HOOK = STRING_CMP + 1


@dataclass(frozen=True)
class Endpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    c: claripy.ast.BV
    de: claripy.ast.BV
    hl: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _assembly_endpoints(
    symbol: str,
    de_addr: int,
    hl_addr: int,
    length: int,
    left: list[claripy.ast.BV],
    right: list[claripy.ast.BV],
) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, symbol)
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
    # The delegating tail jumps into StringCmp, whose CP (HL) half-carry the
    # bundled Z80 SLEIGH computes incorrectly. Apply the shared correction.
    project.hook(
        CP_HL_HOOK,
        Sm83CpAtHl(next_address=CP_HL_HOOK + 1),
        length=1,
    )
    state = project.factory.blank_state(addr=location.address)
    for index, value in enumerate(left):
        state.memory.store(de_addr + index, value)
    for index, value in enumerate(right):
        state.memory.store(hl_addr + index, value)
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")

    returned = collect_returns(project, state, GB_RETURN)
    return [
        Endpoint(
            a=end.regs.a,
            f=z80_flags_to_sm83(end.regs.f),
            c=end.regs.c,
            de=end.regs.de,
            hl=end.regs.hl,
            constraints=tuple(end.solver.constraints),
        )
        for end in returned
    ]


def _native_endpoints(
    c_symbol: str,
    de_addr: int,
    hl_addr: int,
    length: int,
    left: list[claripy.ast.BV],
    right: list[claripy.ast.BV],
) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(c_symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    state.memory.store(NATIVE_STATE + 0, claripy.BVV(0, 8))  # a
    state.memory.store(NATIVE_STATE + 1, claripy.BVV(0, 8))  # f
    state.memory.store(NATIVE_STATE + 2, claripy.BVV(0, 8))  # c
    state.memory.store(NATIVE_STATE + 3, claripy.BVV(0, 8))  # reserved
    state.memory.store(NATIVE_STATE + 4, claripy.BVV(0, 16), endness="Iend_LE")  # de
    state.memory.store(NATIVE_STATE + 6, claripy.BVV(0, 16), endness="Iend_LE")  # hl
    for index, value in enumerate(left):
        state.memory.store(NATIVE_MEMORY + de_addr + index, value)
    for index, value in enumerate(right):
        state.memory.store(NATIVE_MEMORY + hl_addr + index, value)

    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert manager.deadended
    return [
        Endpoint(
            a=end.memory.load(NATIVE_STATE + 0, 1),
            f=end.memory.load(NATIVE_STATE + 1, 1),
            c=end.memory.load(NATIVE_STATE + 2, 1),
            de=end.memory.load(NATIVE_STATE + 4, 2, endness="Iend_LE"),
            hl=end.memory.load(NATIVE_STATE + 6, 2, endness="Iend_LE"),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("assembly_symbol", "c_symbol", "de_addr", "hl_addr", "length"),
    [
        ("HasEnoughCoins", "port_has_enough_coins", 0xD5A4, 0xFFA0, 2),
        ("HasEnoughMoney", "port_has_enough_money", 0xD347, 0xFF9F, 3),
    ],
)
def test_money_sufficiency_symbolic_equivalence(
    assembly_symbol: str,
    c_symbol: str,
    de_addr: int,
    hl_addr: int,
    length: int,
) -> None:
    left = [claripy.BVS(f"{assembly_symbol}_left_{i}", 8) for i in range(length)]
    right = [claripy.BVS(f"{assembly_symbol}_right_{i}", 8) for i in range(length)]
    assembly = _assembly_endpoints(assembly_symbol, de_addr, hl_addr, length, left, right)
    native = _native_endpoints(c_symbol, de_addr, hl_addr, length, left, right)
    assert_pathwise_equivalent(assembly, native, ("a", "f", "c", "de", "hl"))


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "c_value", "de_addr", "hl_addr"),
    [
        ("HasEnoughCoins", "0x2", 0xD5A4, 0xFFA0),
        ("HasEnoughMoney", "0x3", 0xD347, 0xFF9F),
    ],
)
def test_machine_code_is_z80_compatible(
    symbol: str, c_value: str, de_addr: int, hl_addr: int
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    instructions = Context("z80:LE:16:default").disassemble(
        linked_bytes(ROM, location, 11), location.address
    ).instructions
    assert [(item.mnem, item.body, item.length) for item in instructions] == [
        ("LD", f"DE,0x{de_addr:x}", 3),
        ("LD", f"HL,0x{hl_addr:x}", 3),
        ("LD", f"C,{c_value}", 2),
        ("JP", "0x3a8e", 3),
    ]
