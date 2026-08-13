from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS, assembly_registers, native_registers, set_assembly_registers, store_native_registers, symbolic_registers
from verification.harness.rom import collect_returns, linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import Sm83AddRegister, Sm83CpRegister, Sm83IncRegister, Sm83LoadAImmediate

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification" / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
GB_STACK = 0xd000
GB_RETURN = 0xffff
NATIVE_STATE = 0x100000
MEMORY_NAMES = ("wYCoord", "wCurMapHeight", "wXCoord", "wCurMapWidth")


@dataclass(frozen=True)
class Endpoint:
    a: claripy.ast.BV; f: claripy.ast.BV; b: claripy.ast.BV; c: claripy.ast.BV
    d: claripy.ast.BV; e: claripy.ast.BV; h: claripy.ast.BV; l: claripy.ast.BV
    memory: claripy.ast.BV; constraints: tuple[claripy.ast.Bool, ...]


def assembly(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "IsPlayerJustOutsideMap")
    addresses = tuple(symbol_location(SYMBOLS, name).address for name in MEMORY_NAMES)
    project = angr.Project(rom_window(ROM, location.bank), auto_load_libs=False, rebase_granularity=0x100, main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0, "entry_point": location.address})
    for offset, address in zip((0, 4, 11, 15), addresses, strict=True):
        project.hook(location.address + offset, Sm83LoadAImmediate(address, location.address + offset + 3), length=3)
    project.hook(location.address + 18, Sm83AddRegister("a", location.address + 19), length=1)
    project.hook(location.address + 19, Sm83CpRegister("b", location.address + 20), length=1)
    project.hook(location.address + 21, Sm83IncRegister("b", location.address + 22), length=1)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    for index, address in enumerate(addresses):
        state.memory.store(address, inputs[f"memory{index}"])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    return [Endpoint(**assembly_registers(end), memory=claripy.Concat(*(end.memory.load(address, 1) for address in addresses)), constraints=tuple(end.solver.constraints)) for end in collect_returns(project, state, GB_RETURN)]


def native(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_is_player_just_outside_map")
    assert function
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    for index in range(4):
        state.memory.store(NATIVE_STATE + 8 + index, inputs[f"memory{index}"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and manager.deadended
    return [Endpoint(**native_registers(end, NATIVE_STATE), memory=end.memory.load(NATIVE_STATE + 8, 4), constraints=tuple(end.solver.constraints)) for end in manager.deadended]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
def test_is_player_just_outside_map_equivalence() -> None:
    inputs = symbolic_registers("player_outside_map")
    for index, name in enumerate(("y", "height", "x", "width")):
        inputs[f"memory{index}"] = claripy.BVS(f"outside_{name}", 8)
    assert_pathwise_equivalent(assembly(inputs), native(inputs), (*REGISTERS, "memory"))


def test_is_player_just_outside_map_exact_body() -> None:
    location = symbol_location(SYMBOLS, "IsPlayerJustOutsideMap")
    y, height, x, width = (symbol_location(SYMBOLS, name).address for name in MEMORY_NAMES)
    helper = location.address + 18
    expected = bytes((0xfa, y & 0xff, y >> 8, 0x47, 0xfa, height & 0xff, height >> 8, 0xcd, helper & 0xff, helper >> 8, 0xc8, 0xfa, x & 0xff, x >> 8, 0x47, 0xfa, width & 0xff, width >> 8)) + bytes.fromhex("87b8c804c9")
    assert linked_bytes(ROM, location, len(expected)) == expected
