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
from verification.harness.rom import collect_returns, linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import Sm83SbcRegister, Sm83SubRegister


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
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _assembly_endpoints(
    symbol: str, inputs: dict[str, claripy.ast.BV]
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
    if symbol == "UpdateHPBar_CompareNewHPToOldHP":
        subtractions = ((1, "b"), (4, "c"))
        sbcs: tuple[tuple[int, str], ...] = ()
    else:
        subtractions = ((1, "b"), (7, "c"), (14, "e"), (21, "c"))
        sbcs = ((10, "b"), (17, "d"))
    for offset, register in subtractions:
        project.hook(
            location.address + offset,
            Sm83SubRegister(register, location.address + offset + 1),
            length=1,
        )
    for offset, register in sbcs:
        project.hook(
            location.address + offset,
            Sm83SbcRegister(register, location.address + offset + 1),
            length=1,
        )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    return [
        Endpoint(**assembly_registers(end), constraints=tuple(end.solver.constraints))
        for end in collect_returns(project, state, GB_RETURN)
    ]


def _native_endpoints(
    c_symbol: str, inputs: dict[str, claripy.ast.BV]
) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(c_symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("assembly_symbol", "c_symbol"),
    [
        (
            "UpdateHPBar_CompareNewHPToOldHP",
            "port_update_hp_bar_compare_new_hp_to_old_hp",
        ),
        (
            "UpdateHPBar_CalcHPDifference",
            "port_update_hp_bar_calc_hp_difference",
        ),
    ],
)
def test_hp_bar_arithmetic_symbolic_equivalence(
    assembly_symbol: str, c_symbol: str
) -> None:
    inputs = symbolic_registers(assembly_symbol)
    assert_pathwise_equivalent(
        _assembly_endpoints(assembly_symbol, inputs),
        _native_endpoints(c_symbol, inputs),
        REGISTERS,
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "size", "expected"),
    [
        ("UpdateHPBar_CompareNewHPToOldHP", 6, "7a90c07b91c9"),
        (
            "UpdateHPBar_CalcHPDifference",
            30,
            "7a903809280e7b915f7a9857c979935f789a57c97b9138f520ec110000c9",
        ),
    ],
)
def test_hp_bar_arithmetic_machine_code_is_accounted_for(
    symbol: str, size: int, expected: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, size) == bytes.fromhex(expected)
