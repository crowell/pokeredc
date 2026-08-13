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


def _addresses() -> tuple[int, ...]:
    pointer = symbol_location(SYMBOLS, "wSpriteOutputPtr").address
    cached = symbol_location(SYMBOLS, "wSpriteOutputPtrCached").address
    return pointer, cached, pointer + 1, cached + 1


def _assembly(inputs: dict[str, claripy.ast.BV]) -> Endpoint:
    location = symbol_location(SYMBOLS, "StoreSpriteOutputPointer")
    addresses = _addresses()
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
    for offset, address in zip((1, 4, 8, 11), addresses):
        project.hook(
            location.address + offset,
            Sm83StoreAImmediate(address, location.address + offset + 3),
            length=3,
        )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    for index, address in enumerate(addresses):
        state.memory.store(address, inputs[f"memory{index}"])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    assert len(returned) == 1
    end = returned[0]
    return Endpoint(
        **assembly_registers(end),
        memory=claripy.Concat(*(end.memory.load(address, 1) for address in addresses)),
        constraints=tuple(end.solver.constraints),
    )


def _native(inputs: dict[str, claripy.ast.BV]) -> Endpoint:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_store_sprite_output_pointer")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    for index in range(5):
        state.memory.store(NATIVE_STATE + 8 + index, inputs[f"memory{index}"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    end = manager.deadended[0]
    return Endpoint(
        **native_registers(end, NATIVE_STATE),
        memory=end.memory.load(NATIVE_STATE + 8, 4),
        constraints=tuple(end.solver.constraints),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_store_sprite_output_pointer_symbolic_equivalence() -> None:
    inputs = symbolic_registers("store_sprite_output_pointer")
    for index in range(5):
        inputs[f"memory{index}"] = claripy.BVS(f"sprite_output_memory{index}", 8)
    assert_pathwise_equivalent(
        [_assembly(inputs)], [_native(inputs)], (*REGISTERS, "memory")
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_store_sprite_output_pointer_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "StoreSpriteOutputPointer")
    assert linked_bytes(ROM, location, 15) == bytes.fromhex(
        "7deaadd0eaafd07ceaaed0eab0d0c9"
    )
