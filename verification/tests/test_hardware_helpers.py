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
from verification.harness.sm83_shims import Sm83LoadAHighImmediate, Sm83StoreAHighImmediate


ROOT = Path(__file__).resolve().parents[2]
VERIFY = ROOT / "verification"
NATIVE_ELF = VERIFY / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
GB_STACK = 0xD000
GB_RETURN = 0xFFFF
NATIVE_STATE = 0x100000

PORTS = (
    (
        "GBPalNormal",
        "port_gb_pal_normal",
        ((2, "store", 0x47), (6, "store", 0x48)),
        3,
    ),
    (
        "GBPalWhiteOut",
        "port_gb_pal_white_out",
        ((1, "store", 0x47), (3, "store", 0x48), (5, "store", 0x49)),
        3,
    ),
    (
        "EnableLCD",
        "port_enable_lcd",
        ((0, "load", 0x40), (4, "store", 0x40)),
        1,
    ),
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
    hardware0: claripy.ast.BV
    hardware1: claripy.ast.BV
    hardware2: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _assembly(
    symbol: str,
    hooks: tuple[tuple[int, str, int], ...],
    hardware_count: int,
    inputs: dict[str, claripy.ast.BV],
) -> Endpoint:
    location = symbol_location(SYMBOLS, symbol)
    addresses = (0xFF40,) if hardware_count == 1 else (0xFF47, 0xFF48, 0xFF49)
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
    for offset, operation, high_offset in hooks:
        procedure = (
            Sm83LoadAHighImmediate
            if operation == "load"
            else Sm83StoreAHighImmediate
        )
        project.hook(
            location.address + offset,
            procedure(high_offset, location.address + offset + 2),
            length=2,
        )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    for index, address in enumerate(addresses):
        state.memory.store(address, inputs[f"hardware{index}"])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    assert len(returned) == 1
    end = returned[0]
    outputs = {
        f"hardware{index}": (
            end.memory.load(addresses[index], 1)
            if index < len(addresses)
            else inputs[f"hardware{index}"]
        )
        for index in range(3)
    }
    return Endpoint(
        **assembly_registers(end),
        **outputs,
        constraints=tuple(end.solver.constraints),
    )


def _native(c_symbol: str, inputs: dict[str, claripy.ast.BV]) -> Endpoint:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(c_symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    for index in range(3):
        state.memory.store(NATIVE_STATE + 8 + index, inputs[f"hardware{index}"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    end = manager.deadended[0]
    return Endpoint(
        **native_registers(end, NATIVE_STATE),
        **{
            f"hardware{index}": end.memory.load(NATIVE_STATE + 8 + index, 1)
            for index in range(3)
        },
        constraints=tuple(end.solver.constraints),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("symbol,c_symbol,hooks,hardware_count", PORTS)
def test_hardware_helper_symbolic_equivalence(
    symbol: str,
    c_symbol: str,
    hooks: tuple[tuple[int, str, int], ...],
    hardware_count: int,
) -> None:
    inputs = symbolic_registers(symbol.lower())
    for index in range(3):
        inputs[f"hardware{index}"] = claripy.BVS(f"{symbol.lower()}_hardware{index}", 8)
    assert_pathwise_equivalent(
        [_assembly(symbol, hooks, hardware_count, inputs)],
        [_native(c_symbol, inputs)],
        (*REGISTERS, *(f"hardware{index}" for index in range(hardware_count))),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_hardware_helper_exact_linked_bodies() -> None:
    expected = {
        "GBPalNormal": bytes.fromhex("3ee4e0473ed0e048c9"),
        "GBPalWhiteOut": bytes.fromhex("afe047e048e049c9"),
        "EnableLCD": bytes.fromhex("f040cbffe040c9"),
    }
    for symbol, code in expected.items():
        assert linked_bytes(ROM, symbol_location(SYMBOLS, symbol), len(code)) == code
