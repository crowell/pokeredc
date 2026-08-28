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
from verification.harness.sm83_shims import (Sm83CpImmediate, Sm83DecRegister,
                                              Sm83IncRegister, Sm83LoadAImmediate,
                                              Sm83StoreAImmediate)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
RETURN = 0xEFFF
W_Y = 0xD361
W_X = 0xD362
W_FACING = 0xC109
W_TILE = 0xCFC6
W_TILEMAP = 0xC3A0


@dataclass(frozen=True)
class Endpoint:
    a: claripy.ast.BV; f: claripy.ast.BV; b: claripy.ast.BV; c: claripy.ast.BV
    d: claripy.ast.BV; e: claripy.ast.BV; h: claripy.ast.BV; l: claripy.ast.BV
    tile: claripy.ast.BV; constraints: tuple[claripy.ast.Bool, ...]


class PredefRegisters(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__(); self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.jump(self.target)


class Return(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(RETURN)


def _setup(state: angr.SimState, base: int, y: claripy.ast.BV,
           x: claripy.ast.BV, facing: claripy.ast.BV) -> None:
    state.memory.store(base + W_Y, y)
    state.memory.store(base + W_X, x)
    state.memory.store(base + W_FACING, facing)
    for address, value in ((W_TILEMAP + 8 + 11 * 20, 0x11),
                           (W_TILEMAP + 8 + 7 * 20, 0x22),
                           (W_TILEMAP + 6 + 9 * 20, 0x33),
                           (W_TILEMAP + 10 + 9 * 20, 0x44)):
        state.memory.store(base + address, claripy.BVV(value, 8))


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    loc = symbol_location(SYMBOLS, "GetTileAndCoordsInFrontOfPlayer")
    end = symbol_location(SYMBOLS, "GetTileTwoStepsInFrontOfPlayer")
    body = linked_bytes(ROM, loc, end.address - loc.address)
    assert len(body) == 56
    project = angr.Project(rom_window(ROM, loc.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": loc.address})
    project.hook(loc.address, PredefRegisters(loc.address + 3), length=3)
    for offset, address in ((3, W_Y), (7, W_X), (0x0B, W_FACING),
                            (0x11, W_TILEMAP + 8 + 11 * 20),
                            (0x1B, W_TILEMAP + 8 + 7 * 20),
                            (0x25, W_TILEMAP + 6 + 9 * 20),
                            (0x2F, W_TILEMAP + 10 + 9 * 20)):
        project.hook(loc.address + offset, Sm83LoadAImmediate(address, loc.address + offset + 3), length=3)
    for offset, immediate in ((0x17, 4), (0x21, 8), (0x2B, 12)):
        project.hook(loc.address + offset, Sm83CpImmediate(immediate, loc.address + offset + 2), length=2)
    for offset, register, shim in ((0x14, "d", Sm83IncRegister),
                                   (0x1E, "d", Sm83DecRegister),
                                   (0x28, "e", Sm83DecRegister),
                                   (0x32, "e", Sm83IncRegister)):
        project.hook(loc.address + offset, shim(register, loc.address + offset + 1), length=1)
    project.hook(loc.address + 0x34, Sm83StoreAImmediate(W_TILE, loc.address + 0x37), length=3)
    project.hook(loc.address + 0x37, Return(), length=1)
    state = project.factory.blank_state(addr=loc.address)
    set_assembly_registers(state, values); _setup(state, 0, values["y"], values["x"], values["facing"])
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state); manager.explore(find=RETURN, num_find=16)
    assert not manager.errored and manager.found
    return [Endpoint(**assembly_registers(x), tile=x.memory.load(W_TILE, 1), constraints=tuple(x.solver.constraints)) for x in manager.found]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_get_tile_and_coords_in_front"); assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values); _setup(state, NATIVE_MEMORY, values["y"], values["x"], values["facing"])
    manager = project.factory.simulation_manager(state); manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [Endpoint(**native_registers(x, NATIVE_STATE), tile=x.memory.load(NATIVE_MEMORY + W_TILE, 1), constraints=tuple(x.solver.constraints)) for x in manager.deadended]


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(), reason="build artifacts missing")
@pytest.mark.parametrize("facing", (0, 4, 8, 12))
def test_get_tile_and_coords_in_front_pathwise_equivalence(facing: int) -> None:
    values = symbolic_registers("get_tile_front")
    values["y"] = claripy.BVS("get_tile_front_y", 8)
    values["x"] = claripy.BVS("get_tile_front_x", 8)
    values["facing"] = claripy.BVV(facing, 8)
    assert_pathwise_equivalent(_assembly(values), _native(values), (*REGISTERS, "tile"))
