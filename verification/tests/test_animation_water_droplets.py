from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS, assembly_registers, native_registers, set_assembly_registers, store_native_registers, symbolic_registers
from verification.harness.rom import rom_window, symbol_location
from verification.harness.sm83_shims import (
    Sm83CpImmediate,
    Sm83LoadAImmediate,
    Sm83StoreAAtHlIncrement,
    Sm83StoreAImmediate,
    Sm83XorImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF
W_SHADOW_OAM = 0xC300
W_BASE_COORD_X = 0xD081
W_BASE_COORD_Y = 0xD082
W_DROPLET_TILE = 0xD09F
OAM_SIZE = 160

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
    base_x: claripy.ast.BV
    base_y: claripy.ast.BV
    oam: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]
class LoadShadowOAMPointer(angr.SimProcedure):
    def run(self) -> None:
        self.state.regs.h = claripy.BVV(0xC3, 8)
        self.state.regs.l = claripy.BVV(0x00, 8)
        self.jump(self.addr + 3)


class CleanOAMInline(angr.SimProcedure):
    def __init__(self, continuation: int):
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:
        self.state.memory.store(W_SHADOW_OAM, claripy.BVV(0, OAM_SIZE * 8), endness="Iend_BE")
        self.jump(self.continuation)


class DelayFrameTerminal(angr.SimProcedure):
    def run(self) -> None:
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x50, 8)
        self.jump(DONE)

def _constraints(state: angr.SimState, base_y: claripy.ast.BV) -> None:
    state.solver.add(claripy.Or(base_y == 16, base_y == 24))
def _endpoint(state: angr.SimState, memory_base: int, register_base: int) -> Endpoint:
    return Endpoint(
        **(assembly_registers(state) if register_base == 0 else native_registers(state, register_base)),
        base_x=state.memory.load(memory_base + W_BASE_COORD_X, 1),
        base_y=state.memory.load(memory_base + W_BASE_COORD_Y, 1),
        oam=state.memory.load(memory_base + W_SHADOW_OAM, OAM_SIZE),
        constraints=tuple(state.solver.constraints),
    )

def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "_AnimationWaterDroplets")
    project = angr.Project(rom_window(ROM, location.bank), auto_load_libs=False, rebase_granularity=0x100, main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0, "entry_point": location.address})
    project.hook(location.address + 46, CleanOAMInline(location.address + 49), length=3)
    project.hook(location.address + 49, DelayFrameTerminal(), length=3)
    project.hook(location.address, LoadShadowOAMPointer(), length=3)
    project.hook(location.address + 6, Sm83StoreAAtHlIncrement(location.address + 7), length=1)
    project.hook(location.address + 15, Sm83StoreAAtHlIncrement(location.address + 16), length=1)
    project.hook(location.address + 19, Sm83StoreAAtHlIncrement(location.address + 20), length=1)
    project.hook(location.address + 20, Sm83XorImmediate(0, location.address + 21), length=1)
    project.hook(location.address + 21, Sm83StoreAAtHlIncrement(location.address + 22), length=1)
    project.hook(location.address + 3, Sm83LoadAImmediate(W_BASE_COORD_Y, location.address + 6), length=3)
    project.hook(location.address + 7, Sm83LoadAImmediate(W_BASE_COORD_X, location.address + 10), length=3)
    project.hook(location.address + 12, Sm83StoreAImmediate(W_BASE_COORD_X, location.address + 15), length=3)
    project.hook(location.address + 16, Sm83LoadAImmediate(W_DROPLET_TILE, location.address + 19), length=3)
    project.hook(location.address + 22, Sm83LoadAImmediate(W_BASE_COORD_X, location.address + 25), length=3)
    project.hook(location.address + 25, Sm83CpImmediate(144, location.address + 27), length=2)
    project.hook(location.address + 31, Sm83StoreAImmediate(W_BASE_COORD_X, location.address + 34), length=3)
    project.hook(location.address + 34, Sm83LoadAImmediate(W_BASE_COORD_Y, location.address + 37), length=3)
    project.hook(location.address + 39, Sm83StoreAImmediate(W_BASE_COORD_Y, location.address + 42), length=3)
    project.hook(location.address + 42, Sm83CpImmediate(112, location.address + 44), length=2)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    base_x = values["base_x"]
    base_y = values["base_y"]
    tile = values["tile"]
    state.memory.store(W_BASE_COORD_X, base_x)
    state.memory.store(W_BASE_COORD_Y, base_y)
    state.memory.store(W_DROPLET_TILE, tile)
    state.memory.store(W_SHADOW_OAM, values["oam"], endness="Iend_BE")
    _constraints(state, base_y)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=256)
    assert not manager.errored
    return [_endpoint(end, 0, 0) for end in manager.found]

def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_animation_water_droplets")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    base_x = values["base_x"]
    base_y = values["base_y"]
    tile = values["tile"]
    state.memory.store(NATIVE_MEMORY + W_BASE_COORD_X, base_x)
    state.memory.store(NATIVE_MEMORY + W_BASE_COORD_Y, base_y)
    state.memory.store(NATIVE_MEMORY + W_DROPLET_TILE, tile)
    state.memory.store(NATIVE_MEMORY + W_SHADOW_OAM, values["oam"], endness="Iend_BE")
    _constraints(state, base_y)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [_endpoint(end, NATIVE_MEMORY, NATIVE_STATE) for end in manager.deadended]

@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_animation_water_droplets_pathwise_equivalence() -> None:
    values = symbolic_registers("animation_water_droplets")
    values["base_x"] = claripy.BVS("water_base_x", 8)
    values["base_y"] = claripy.BVS("water_base_y", 8)
    values["tile"] = claripy.BVS("water_droplet_tile", 8)
    values["oam"] = claripy.BVS("water_oam", OAM_SIZE * 8)
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "base_x", "base_y", "oam"),
    )
