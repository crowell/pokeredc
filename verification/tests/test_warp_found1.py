"""Proof for the WarpFound1 warp-entry transfers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS, assembly_registers, native_registers, set_assembly_registers, store_native_registers, symbolic_registers
from verification.harness.rom import linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import Sm83LoadAAtHlIncrement, Sm83StoreAHighImmediate, Sm83StoreAImmediate

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
SOURCE = 0xD500
W_DESTINATION_WARP_ID = 0xD42F
H_WARP_DESTINATION_MAP = 0xFF8B
EXPECTED = bytes.fromhex("2aea2fd42ae08b")


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
    memory: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _endpoint(state: angr.SimState, *, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    return Endpoint(
        **(native_registers(state, NATIVE_STATE) if native else assembly_registers(state)),
        memory=claripy.Concat(
            state.memory.load(base + W_DESTINATION_WARP_ID, 1),
            state.memory.load(base + H_WARP_DESTINATION_MAP, 1),
            state.memory.load(base + SOURCE, 2),
        ),
        constraints=tuple(state.solver.constraints),
    )


def _assembly(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "WarpFound1")
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
    project.hook(location.address + 0x00, Sm83LoadAAtHlIncrement(location.address + 0x01), length=1)
    project.hook(location.address + 0x01, Sm83StoreAImmediate(W_DESTINATION_WARP_ID, location.address + 0x04), length=3)
    project.hook(location.address + 0x04, Sm83LoadAAtHlIncrement(location.address + 0x05), length=1)
    project.hook(location.address + 0x05, Sm83StoreAHighImmediate(0x8B, location.address + 0x07), length=2)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    state.regs.h = SOURCE >> 8
    state.regs.l = SOURCE & 0xFF
    state.memory.store(SOURCE, claripy.BVV(0x12, 8))
    state.memory.store(SOURCE + 1, claripy.BVV(0x34, 8))
    manager = project.factory.simulation_manager(state)
    manager.explore(find=lambda candidate: candidate.addr == location.address + 0x07)
    assert not manager.errored
    return [_endpoint(end, native=False) for end in manager.found]


def _native(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_warp_found1")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_MEMORY + SOURCE, claripy.BVV(0x12, 8))
    state.memory.store(NATIVE_MEMORY + SOURCE + 1, claripy.BVV(0x34, 8))
    native = native_registers(state, NATIVE_STATE)
    state.memory.store(NATIVE_STATE + 6, claripy.BVV(SOURCE >> 8, 8))
    state.memory.store(NATIVE_STATE + 7, claripy.BVV(SOURCE & 0xFF, 8))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [_endpoint(end, native=True) for end in manager.deadended]


@pytest.mark.skipif(not ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_warp_found1_pathwise_equivalence() -> None:
    inputs = symbolic_registers("warp_found1")
    assert_pathwise_equivalent(_assembly(inputs), _native(inputs), (*REGISTERS, "memory"))


def test_warp_found1_exact_prefix() -> None:
    location = symbol_location(SYMBOLS, "WarpFound1")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
