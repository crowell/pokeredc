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
from verification.harness.sm83_shims import Sm83CpImmediate, Sm83DecRegister, Sm83IncRegister, Sm83LoadAImmediate

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification" / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
GB_STACK = 0xd000
GB_RETURN = 0xffff
NATIVE_STATE = 0x100000
MEMORY_NAMES = ("wYCoord", "wXCoord", "wSpritePlayerStateData1FacingDirection")


@dataclass(frozen=True)
class Endpoint:
    a: claripy.ast.BV; f: claripy.ast.BV; b: claripy.ast.BV; c: claripy.ast.BV
    d: claripy.ast.BV; e: claripy.ast.BV; h: claripy.ast.BV; l: claripy.ast.BV
    memory: claripy.ast.BV; constraints: tuple[claripy.ast.Bool, ...]


def assembly(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "GetCoordsInFrontOfPlayer")
    addresses = tuple(symbol_location(SYMBOLS, name).address for name in MEMORY_NAMES)
    project = angr.Project(rom_window(ROM, location.bank), auto_load_libs=False, rebase_granularity=0x100, main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0, "entry_point": location.address})
    for offset, address in zip((0, 4, 8), addresses, strict=True):
        project.hook(location.address + offset, Sm83LoadAImmediate(address, location.address + offset + 3), length=3)
    project.hook(location.address + 16, Sm83CpImmediate(4, location.address + 18), length=2)
    project.hook(location.address + 22, Sm83CpImmediate(8, location.address + 24), length=2)
    for offset, procedure, register in ((14, Sm83IncRegister, "d"), (20, Sm83DecRegister, "d"), (26, Sm83DecRegister, "e"), (28, Sm83IncRegister, "e")):
        project.hook(location.address + offset, procedure(register, location.address + offset + 1), length=1)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    for index, address in enumerate(addresses):
        state.memory.store(address, inputs[f"memory{index}"])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    return [Endpoint(**assembly_registers(end), memory=claripy.Concat(*(end.memory.load(address, 1) for address in addresses)), constraints=tuple(end.solver.constraints)) for end in collect_returns(project, state, GB_RETURN)]


def native(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_get_coords_in_front_of_player")
    assert function
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    for index in range(3):
        state.memory.store(NATIVE_STATE + 8 + index, inputs[f"memory{index}"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and manager.deadended
    return [Endpoint(**native_registers(end, NATIVE_STATE), memory=end.memory.load(NATIVE_STATE + 8, 3), constraints=tuple(end.solver.constraints)) for end in manager.deadended]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
def test_get_coords_in_front_equivalence() -> None:
    inputs = symbolic_registers("coords_in_front")
    for index, name in enumerate(("y", "x", "facing")):
        inputs[f"memory{index}"] = claripy.BVS(f"coords_{name}", 8)
    assert_pathwise_equivalent(assembly(inputs), native(inputs), (*REGISTERS, "memory"))


def test_get_coords_in_front_exact_body() -> None:
    location = symbol_location(SYMBOLS, "GetCoordsInFrontOfPlayer")
    y, x, facing = (symbol_location(SYMBOLS, name).address for name in MEMORY_NAMES)
    expected = bytes((0xfa, y & 0xff, y >> 8, 0x57, 0xfa, x & 0xff, x >> 8, 0x5f, 0xfa, facing & 0xff, facing >> 8)) + bytes.fromhex("a7200214c9fe04200215c9fe0820021dc91cc9")
    assert linked_bytes(ROM, location, len(expected)) == expected
