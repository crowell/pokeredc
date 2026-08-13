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
from verification.harness.sm83_shims import Sm83LoadAHighImmediate, Sm83StoreAAtHlIncrement


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


def _assembly(inputs: dict[str, claripy.ast.BV]) -> Endpoint:
    location = symbol_location(SYMBOLS, "RestoreMapTextPointer")
    destination = symbol_location(SYMBOLS, "wCurMapTextPtr").address
    source = symbol_location(SYMBOLS, "hSavedMapTextPtr").address
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
    project.hook(
        location.address + 3,
        Sm83LoadAHighImmediate(source, location.address + 5),
        length=2,
    )
    project.hook(
        location.address + 5,
        Sm83StoreAAtHlIncrement(location.address + 6),
        length=1,
    )
    project.hook(
        location.address + 6,
        Sm83LoadAHighImmediate(source + 1, location.address + 8),
        length=2,
    )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    for index, address in enumerate((source, source + 1, destination, destination + 1)):
        state.memory.store(address, inputs[f"memory{index}"])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    assert len(returned) == 1
    end = returned[0]
    return Endpoint(
        **assembly_registers(end),
        memory=claripy.Concat(
            end.memory.load(source, 1),
            end.memory.load(source + 1, 1),
            end.memory.load(destination, 1),
            end.memory.load(destination + 1, 1),
        ),
        constraints=tuple(end.solver.constraints),
    )


def _native(inputs: dict[str, claripy.ast.BV]) -> Endpoint:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_restore_map_text_pointer")
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
def test_restore_map_text_pointer_symbolic_equivalence() -> None:
    inputs = symbolic_registers("restore_map_text_pointer")
    for index in range(5):
        inputs[f"memory{index}"] = claripy.BVS(f"restore_map_text_memory{index}", 8)
    assert_pathwise_equivalent(
        [_assembly(inputs)], [_native(inputs)], (*REGISTERS, "memory")
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_restore_map_text_pointer_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "RestoreMapTextPointer")
    assert linked_bytes(ROM, location, 10) == bytes.fromhex("216cd3f0ec22f0ed77c9")
