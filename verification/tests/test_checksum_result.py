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
from verification.harness.sm83_shims import Sm83StoreAImmediate


ROOT = Path(__file__).resolve().parents[2]
VERIFY = ROOT / "verification"
NATIVE_ELF = VERIFY / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
GB_STACK = 0xD000
GB_RETURN = 0xFFFF
NATIVE_STATE = 0x100000
MEMORY_NAMES = ("bank_mode", "ram_gate")
MAPPER_ADDRESSES = (0x6000, 0x0000)


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
    bank_mode: claripy.ast.BV
    ram_gate: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _assembly_endpoint(symbol: str, inputs: dict[str, claripy.ast.BV]) -> Endpoint:
    location = symbol_location(SYMBOLS, symbol)
    prefix_size = 1 if symbol == "CheckSumFailed" else 0
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
    first_store = location.address + prefix_size + 2
    project.hook(
        first_store,
        Sm83StoreAImmediate(MAPPER_ADDRESSES[0], first_store + 3),
        length=3,
    )
    project.hook(
        first_store + 3,
        Sm83StoreAImmediate(MAPPER_ADDRESSES[1], first_store + 6),
        length=3,
    )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    for name, address in zip(MEMORY_NAMES, MAPPER_ADDRESSES, strict=True):
        state.memory.store(address, inputs[name])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    end = collect_returns(project, state, GB_RETURN)[0]
    return Endpoint(
        **assembly_registers(end),
        **{
            name: end.memory.load(address, 1)
            for name, address in zip(MEMORY_NAMES, MAPPER_ADDRESSES, strict=True)
        },
        constraints=tuple(end.solver.constraints),
    )


def _native_endpoint(
    c_symbol: str, inputs: dict[str, claripy.ast.BV]
) -> Endpoint:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(c_symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    for offset, name in enumerate(MEMORY_NAMES, 8):
        state.memory.store(NATIVE_STATE + offset, inputs[name])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    end = manager.deadended[0]
    return Endpoint(
        **native_registers(end, NATIVE_STATE),
        **{
            name: end.memory.load(NATIVE_STATE + offset, 1)
            for offset, name in enumerate(MEMORY_NAMES, 8)
        },
        constraints=tuple(end.solver.constraints),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("assembly_symbol", "c_symbol"),
    [
        ("CheckSumFailed", "port_checksum_failed"),
        ("GoodCheckSum", "port_good_checksum"),
    ],
)
def test_checksum_result_symbolic_equivalence(
    assembly_symbol: str, c_symbol: str
) -> None:
    inputs = symbolic_registers(assembly_symbol)
    for name in MEMORY_NAMES:
        inputs[name] = claripy.BVS(f"{assembly_symbol}_{name}", 8)
    assert_pathwise_equivalent(
        [_assembly_endpoint(assembly_symbol, inputs)],
        [_native_endpoint(c_symbol, inputs)],
        (*REGISTERS, *MEMORY_NAMES),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "size", "expected"),
    [
        ("CheckSumFailed", 10, "373e00ea0060ea0000c9"),
        ("GoodCheckSum", 9, "3e00ea0060ea0000c9"),
    ],
)
def test_checksum_result_machine_code_is_accounted_for(
    symbol: str, size: int, expected: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, size) == bytes.fromhex(expected)
