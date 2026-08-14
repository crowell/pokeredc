from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
    assembly_registers,
    native_registers,
    set_assembly_registers,
    store_native_registers,
    symbolic_registers,
)
from verification.harness.rom import (
    collect_returns,
    linked_bytes,
    rom_window,
    symbol_location,
)
from verification.harness.sm83_shims import (
    Sm83CpImmediate,
    Sm83LoadAAtHlIncrement,
)


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification" / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
GB_STACK = 0xD000
GB_RETURN = 0xFFFF
NATIVE_STATE = 0x100000
W_PLAYER_NAME = 0xD158
NAME_LENGTH = 11
TERMINATOR = 0x50  # '@'
@lru_cache(maxsize=None)
def _name_bvs() -> tuple[claripy.ast.BV, ...]:
    """Symbolic wPlayerName bytes shared between the assembly and native
    endpoints so path constraints refer to the same claripy variables."""
    return tuple(claripy.BVS(f"unlen_name{i}", 8) for i in range(NAME_LENGTH))


def _store_name_buffer(state: angr.SimState) -> None:
    """Make the 11-byte wPlayerName buffer symbolic and force the following
    byte to the '@' terminator so the scan always terminates within bounds."""
    for i in range(NAME_LENGTH):
        state.memory.store(W_PLAYER_NAME + i, _name_bvs()[i])
    state.memory.store(W_PLAYER_NAME + NAME_LENGTH, claripy.BVV(TERMINATOR, 8))


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


def _assembly_endpoint(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "UnusedPlayerNameLengthFunc")
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
    base = location.address
    # 0x2A (ld a,[hli]) is mis-decoded by the z80 pcode as a 3-byte load that
    # swallows the following `cp $50`; shim it and the comparison.
    project.hook(base + 0x06, Sm83LoadAAtHlIncrement(base + 0x07), length=1)
    project.hook(base + 0x07, Sm83CpImmediate(0x50, base + 0x09), length=2)
    _store_name_buffer(state)
    set_assembly_registers(state, inputs)
    state.regs.sp = claripy.BVV(GB_STACK, 16)
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    return [
        Endpoint(
            **assembly_registers(end),
            constraints=tuple(end.solver.constraints),
        )
        for end in returned
    ]


def _native_endpoint(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(
        "port_unused_player_name_length_func"
    )
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, claripy.BVV(0, 64)
    )
    store_native_registers(state, NATIVE_STATE, inputs)
    _store_name_buffer(state)
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
def test_unused_player_name_length_func_symbolic_equivalence() -> None:
    inputs = symbolic_registers("unlen")
    assembly = _assembly_endpoint(inputs)
    native = _native_endpoint(inputs)
    assert_pathwise_equivalent(
        assembly,
        native,
        ("a", "f", "b", "c", "d", "e", "h", "l"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_unused_player_name_length_func_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "UnusedPlayerNameLengthFunc")
    expected = bytes.fromhex("2158d10100ff2afe50c80d18f9")
    assert linked_bytes(ROM, location, len(expected)) == expected
