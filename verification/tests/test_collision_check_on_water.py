from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
    REGISTERS, assembly_registers, native_registers, set_assembly_registers,
    store_native_registers,
)
from verification.harness.rom import linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import (
    Sm83AndRegister, Sm83BitRegister, Sm83LoadAImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xEFFF

W_STATUS = 0xD730
W_MOVEMENT = 0xD736
W_DIRECTION = 0xD52A
W_COLLISION = 0xC10C
W_TILE_FRONT = 0xCFC6
W_TILEMAP = 0xC3A0
W_CUR_TILESET = 0xD367
W_COLLISION_PTR = 0xD530
W_WALK_SURF = 0xD700
W_CHANNEL5 = 0xC02A
W_FACING = 0xC109
W_Y_COORD = 0xD361
W_X_COORD = 0xD362
W_TILEMAP = 0xC3A0


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


class Boundary(angr.SimProcedure):
    def __init__(self, next_address: int, carry: bool = False) -> None:
        super().__init__()
        self.next_address = next_address
        self.carry = carry

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.f = claripy.BVV(0x10 if self.carry else 0, 8)
        self.jump(self.next_address)


class GetTileBoundary(angr.SimProcedure):
    def __init__(self, next_address: int, tile_address: int) -> None:
        super().__init__()
        self.next_address = next_address
        self.tile_address = tile_address

    def run(self) -> None:  # type: ignore[override]
        tile = self.state.memory.load(self.tile_address, 1)
        self.state.regs.a = tile
        self.state.regs.c = tile
        self.jump(self.next_address)


class JumpingWaterNoCollision(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        tile = self.state.memory.load(W_TILEMAP + 11 * 20 + 8, 1)
        self.state.regs.a = claripy.BVV(0xFF, 8)
        self.state.regs.b = claripy.BVV(1, 8)
        self.state.regs.c = tile
        self.state.regs.d = claripy.BVV(1, 8)
        self.state.regs.e = claripy.BVV(0, 8)
        self.state.regs.h = claripy.BVV(0x0C, 8)
        self.state.regs.l = claripy.BVV(0xA1, 8)
        self.state.regs.f = claripy.BVV(0x10, 8)
        self.state.memory.store(W_TILE_FRONT, tile)
        self.jump(self.next_address)


class GetTileWaterBoundary(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        tile = self.state.memory.load(W_TILEMAP + 11 * 20 + 8, 1)
        self.state.regs.a = tile
        self.state.regs.c = tile
        self.state.regs.d = claripy.BVV(1, 8)
        self.state.regs.e = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0, 8)
        self.state.memory.store(W_TILE_FRONT, tile)
        self.jump(self.next_address)


def _setup(state: angr.SimState, base: int, *, status: int, direction: int,
           collision: int, tile: int, tileset: int, channel5: int,
           collision_ptr: int) -> None:
    for address, value in (
        (W_STATUS, status), (W_MOVEMENT, 0), (W_DIRECTION, direction),
        (W_COLLISION, collision), (W_TILE_FRONT, tile),
        (W_CUR_TILESET, tileset), (W_CHANNEL5, channel5),
        (W_WALK_SURF, 2),
    ):
        state.memory.store(base + address, claripy.BVV(value, 8))
    state.memory.store(base + W_COLLISION_PTR,
                       claripy.BVV(collision_ptr, 16), endness="Iend_LE")
    # Native GetTile reads the tile map; the assembly call is bounded below.
    state.memory.store(base + W_TILEMAP + 9 * 20 + 8,
                       claripy.BVV(0, 8))
    state.memory.store(base + W_TILEMAP + 11 * 20 + 8,
                       claripy.BVV(tile, 8))
    # A $ff first entry makes the tile-pair scan a no-collision path.
    state.memory.store(base + 0x0CA0, claripy.BVV(0xFF, 8))
    state.memory.store(base + collision_ptr, claripy.BVV(0xFF, 8))
    state.memory.store(base + W_FACING, claripy.BVV(0, 8))
    state.memory.store(base + W_Y_COORD, claripy.BVV(0, 8))
    state.memory.store(base + W_X_COORD, claripy.BVV(0, 8))


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(*(state.memory.load(base + address, 1) for address in (
        W_STATUS, W_DIRECTION, W_COLLISION, W_TILE_FRONT,
        W_WALK_SURF, W_CHANNEL5,
    )))


def _endpoint(state: angr.SimState, *, native: bool, base: int) -> Endpoint:
    return Endpoint(
        **(native_registers(state, NATIVE_STATE) if native else assembly_registers(state)),
        memory=_memory(state, base), constraints=tuple(state.solver.constraints)
    )


def _assembly(values: dict[str, claripy.ast.BV], **case: int) -> list[Endpoint]:
    loc = symbol_location(SYMBOLS, "CollisionCheckOnWater")
    end = symbol_location(SYMBOLS, "RunMapScript")
    assert linked_bytes(ROM, loc, end.address - loc.address) == bytes.fromhex(
        "fa30d7cb7fc20410fa2ad557fa0cc1a2201c21a00ccd2a0c38243e35cd6d3efac6cffe142827fe322831fe48281f2130d52a666f2afeff2805b9281318f6fa2ac0feb428053eb4cdb123371801a7c9afea00d7cd9709cd072318f2fa67d3fe0e20eb18eb"
    )
    project = angr.Project(rom_window(ROM, loc.bank), auto_load_libs=False,
                           rebase_granularity=0x100,
                           main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                                      "base_addr": 0, "entry_point": loc.address})
    q = loc.address
    nested = case.pop("nested", 0)
    project.hook(q + 0x00, Sm83LoadAImmediate(W_STATUS, q + 3), length=3)
    project.hook(q + 0x03, Sm83BitRegister(7, "a", q + 5), length=2)
    project.hook(q + 0x08, Sm83LoadAImmediate(W_DIRECTION, q + 0x0B), length=3)
    project.hook(q + 0x0C, Sm83LoadAImmediate(W_COLLISION, q + 0x0F), length=3)
    project.hook(q + 0x0F, Sm83AndRegister("d", q + 0x10), length=1)
    project.hook(q + 0x15, (JumpingWaterNoCollision(q + 0x18)
                            if nested else Boundary(q + 0x18)), length=3)
    project.hook(q + 0x1C, (GetTileWaterBoundary(q + 0x1F)
                            if nested else GetTileBoundary(q + 0x1F, W_TILE_FRONT)), length=3)
    project.hook(q + 0x47, Boundary(q + 0x4A), length=3)
    project.hook(q + 0x4D, Sm83AndRegister("a", q + 0x4E), length=1)
    state = project.factory.blank_state(addr=loc.address)
    set_assembly_registers(state, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    _setup(state, 0, **case)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN, num_find=8)
    assert not manager.errored and manager.found
    return [_endpoint(end_state, native=False, base=0) for end_state in manager.found]


def _native(values: dict[str, claripy.ast.BV], **case: int) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_collision_check_on_water")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    case.pop("nested", 0)
    _setup(state, NATIVE_MEMORY, **case)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and manager.deadended
    return [_endpoint(end_state, native=True, base=NATIVE_MEMORY)
            for end_state in manager.deadended]


CASES = (
    dict(status=0x80, direction=1, collision=1, tile=0x14,
         tileset=1, channel5=0, collision_ptr=0x700),
    dict(status=0, direction=1, collision=0, tile=0x14,
         tileset=1, channel5=0, collision_ptr=0x700, nested=1),
    dict(status=0, direction=1, collision=0, tile=0x48,
         tileset=1, channel5=0, collision_ptr=0x700, nested=1),
    dict(status=0, direction=1, collision=0, tile=0x32,
         tileset=1, channel5=0, collision_ptr=0x700, nested=1),
)


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),
                    reason="build artifacts missing")
@pytest.mark.parametrize("case", CASES)
def test_collision_check_on_water_pathwise_equivalence(case: dict[str, int]) -> None:
    values = {register: claripy.BVV(0, 8) for register in REGISTERS}
    values["c"] = claripy.BVV(0xF0, 8)
    assert_pathwise_equivalent(
        _assembly(values, **case), _native(values, **case),
        (*REGISTERS, "memory"),
    )
