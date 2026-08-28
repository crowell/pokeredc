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
    Sm83AndRegister, Sm83BitRegister, Sm83CpImmediate,
    Sm83LoadAHighImmediate, Sm83LoadAImmediate, Sm83Scf,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xEFFF

W_MOVEMENT = 0xD736
W_SIMULATED = 0xCD38
W_DIRECTION = 0xD52A
W_COLLISION = 0xC10C
W_CHANNEL5 = 0xC02A
W_FACING = 0xC109
W_Y_COORD = 0xD361
W_X_COORD = 0xD362
W_NUM_SPRITES = 0xD4E1
W_TILE_FRONT = 0xCFC6
W_TILE_STANDING = 0xC45C
W_TILEMAP = 0xC3A0
W_CUR_TILESET = 0xD367
W_COLLISION_PTR = 0xD530


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


class PlaySoundBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(self.addr + 3)


class SpriteFrontNoSprites(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__()
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.d = claripy.BVV(0x10, 8)
        self.state.regs.b = claripy.BVV(0x2C, 8)
        self.state.regs.c = claripy.BVV(0x40, 8)
        self.state.memory.store(0xD52A, claripy.BVV(4, 8))
        self.state.regs.a = self.state.memory.load(W_NUM_SPRITES, 1)
        self.state.regs.f = claripy.BVV(0x40, 8)
        self.jump(self.target)


class CheckForJumpingNoCollision(angr.SimProcedure):
    def __init__(self, target: int, carry: bool = False) -> None:
        super().__init__()
        self.target = target
        self.carry = carry

    def run(self) -> None:  # type: ignore[override]
        tile = self.state.memory.load(W_TILEMAP + 11 * 20 + 8, 1)
        self.state.regs.d = claripy.BVV(1, 8)
        self.state.regs.e = claripy.BVV(0, 8)
        self.state.regs.a = claripy.BVV(0xFF, 8)
        self.state.regs.b = claripy.BVV(0 if self.carry else 1, 8)
        self.state.regs.c = tile
        self.state.regs.h = claripy.BVV(0x0C, 8)
        self.state.regs.l = claripy.BVV(0x80 if self.carry else 0x7F, 8)
        self.state.regs.f = claripy.BVV(0x01 if self.carry else 0x10, 8)
        self.state.memory.store(W_TILE_FRONT, tile)
        self.state.memory.store(W_TILE_STANDING,
                                 self.state.memory.load(W_TILEMAP + 9 * 20 + 8, 1))
        self.jump(self.target)


class CheckTilePassableNoCollision(angr.SimProcedure):
    def __init__(self, target: int, carry: bool = False) -> None:
        super().__init__()
        self.target = target
        self.carry = carry

    def run(self) -> None:  # type: ignore[override]
        tile = self.state.memory.load(W_TILEMAP + 11 * 20 + 8, 1)
        pointer = self.state.memory.load(W_COLLISION_PTR, 2, endness="Iend_LE")
        self.state.regs.d = claripy.BVV(1, 8)
        self.state.regs.e = claripy.BVV(0, 8)
        self.state.regs.a = tile
        self.state.regs.c = tile
        self.state.regs.h = claripy.LShR(pointer + 1, 8)
        self.state.regs.l = (pointer + 1) & 0xFF
        self.state.regs.f = claripy.BVV(0x01 if self.carry else 0x42, 8)
        self.state.memory.store(W_TILE_FRONT, tile)
        self.jump(self.target)


def _setup(state: angr.SimState, base: int, *, movement: int, simulated: int,
           direction: int, collision: int, channel5: int,
           num_sprites: int = 0, tile_pair_collision: bool = False) -> None:
    for offset in range(0x100):
        state.memory.store(base + 0xC100 + offset, claripy.BVV(0, 8))
    for address, value in ((W_MOVEMENT, movement), (W_SIMULATED, simulated),
                           (W_DIRECTION, direction), (W_COLLISION, collision),
                           (W_CHANNEL5, channel5)):
        state.memory.store(base + address, claripy.BVV(value, 8))
    state.memory.store(base + W_FACING, claripy.BVV(0, 8))
    state.memory.store(base + W_Y_COORD, claripy.BVV(0, 8))
    state.memory.store(base + W_X_COORD, claripy.BVV(0, 8))
    state.memory.store(base + W_NUM_SPRITES, claripy.BVV(num_sprites, 8))
    state.memory.store(base + W_CUR_TILESET, claripy.BVV(1, 8))
    state.memory.store(base + W_TILEMAP + 11 * 20 + 8, claripy.BVV(1, 8))
    state.memory.store(base + W_TILEMAP + 9 * 20 + 8, claripy.BVV(0, 8))
    state.memory.store(base + W_TILE_FRONT, claripy.BVV(0, 8))
    state.memory.store(base + W_TILE_STANDING, claripy.BVV(0, 8))
    state.memory.store(base + W_COLLISION_PTR, claripy.BVV(0x700, 16), endness="Iend_LE")
    state.memory.store(base + 0x700, claripy.BVV(1, 8))
    if tile_pair_collision:
        for offset, value in enumerate((1, 0, 1, 0xFF)):
            state.memory.store(base + 0x0C7E + offset,
                               claripy.BVV(value, 8))
    else:
        state.memory.store(base + 0x0C7E, claripy.BVV(0xFF, 8))


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(*(state.memory.load(base + address, 1) for address in (
        W_MOVEMENT, W_SIMULATED, W_DIRECTION, W_COLLISION, W_CHANNEL5,
        W_FACING, W_TILE_FRONT, W_TILE_STANDING, W_NUM_SPRITES)))


def _endpoint(state: angr.SimState, *, native: bool, base: int) -> Endpoint:
    return Endpoint(
        **(native_registers(state, NATIVE_STATE) if native else assembly_registers(state)),
        memory=_memory(state, base), constraints=tuple(state.solver.constraints)
    )


def _assembly(values: dict[str, claripy.ast.BV], **case: int) -> list[Endpoint]:
    loc = symbol_location(SYMBOLS, "CollisionCheckOnLand")
    end = symbol_location(SYMBOLS, "CheckTilePassable")
    assert linked_bytes(ROM, loc, end.address - loc.address) == bytes.fromhex(
        "fa36d7cb772036fa38cda72030fa2ad557fa0cc1a22018afe08ccd6b0bf08ca7200d217e0ccd2a0c3805cd100c300efa2ac0feb428053eb4cdb12337c9a7c9"
    )
    project = angr.Project(rom_window(ROM, loc.bank), auto_load_libs=False,
                           rebase_granularity=0x100,
                           main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                                      "base_addr": 0, "entry_point": loc.address})
    q = loc.address
    project.hook(q + 0x00, Sm83LoadAImmediate(W_MOVEMENT, q + 3), length=3)
    project.hook(q + 0x03, Sm83BitRegister(6, "a", q + 5), length=2)
    project.hook(q + 0x07, Sm83LoadAImmediate(W_SIMULATED, q + 0x0A), length=3)
    project.hook(q + 0x0A, Sm83AndRegister("a", q + 0x0B), length=1)
    project.hook(q + 0x0D, Sm83LoadAImmediate(W_DIRECTION, q + 0x10), length=3)
    project.hook(q + 0x11, Sm83LoadAImmediate(W_COLLISION, q + 0x14), length=3)
    project.hook(q + 0x14, Sm83AndRegister("d", q + 0x15), length=1)
    project.hook(q + 0x2F, Sm83LoadAImmediate(W_CHANNEL5, q + 0x32), length=3)
    project.hook(q + 0x32, Sm83CpImmediate(0xB4, q + 0x34), length=2)
    project.hook(q + 0x38, PlaySoundBoundary(), length=3)
    project.hook(q + 0x3B, Sm83Scf(q + 0x3C), length=1)
    project.hook(q + 0x3D, Sm83AndRegister("a", q + 0x3E), length=1)
    nested = case.pop("nested", 0)
    pair_collision = bool(case.get("tile_pair_collision", 0))
    if nested:
        project.hook(q + 0x1A, SpriteFrontNoSprites(q + 0x1D), length=3)
        project.hook(q + 0x1D, Sm83LoadAHighImmediate(0x8C, q + 0x1F), length=2)
        project.hook(q + 0x1F, Sm83AndRegister("a", q + 0x20), length=1)
        project.hook(q + 0x25, CheckForJumpingNoCollision(
            q + 0x28, pair_collision), length=3)
        project.hook(q + 0x2A, CheckTilePassableNoCollision(
            q + 0x2D, bool(case.pop("passable_carry", 0))), length=3)
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
    function = project.loader.find_symbol("port_collision_check_on_land")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    case.pop("nested", 0)
    passable_carry = case.pop("passable_carry", 0)
    _setup(state, NATIVE_MEMORY, **case)
    if passable_carry:
        state.memory.store(NATIVE_MEMORY + 0x700, claripy.BVV(0xFF, 8))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and manager.deadended
    return [_endpoint(end_state, native=True, base=NATIVE_MEMORY) for end_state in manager.deadended]


CASES = (
    dict(movement=0x40, simulated=0, direction=1, collision=1, channel5=0),
    dict(movement=0, simulated=1, direction=1, collision=1, channel5=0),
    dict(movement=0, simulated=0, direction=1, collision=1, channel5=0xB4),
    dict(movement=0, simulated=0, direction=1, collision=1, channel5=0),
    dict(movement=0, simulated=0, direction=1, collision=0, channel5=0,
         nested=1),
    dict(movement=0, simulated=0, direction=1, collision=0, channel5=0,
         nested=1, passable_carry=1),
    dict(movement=0, simulated=0, direction=1, collision=0, channel5=0,
         nested=1, num_sprites=1),
    dict(movement=0, simulated=0, direction=1, collision=0, channel5=0,
         nested=1, tile_pair_collision=1),
)


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),
                    reason="build artifacts missing")
@pytest.mark.parametrize("case", CASES)
def test_collision_check_on_land_pathwise_equivalence(case: dict[str, int]) -> None:
    values = {register: claripy.BVV(0, 8) for register in REGISTERS}
    assert_pathwise_equivalent(
        _assembly(values, **case), _native(values, **case),
        (*REGISTERS, "memory"),
    )
