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
from verification.harness.rom import collect_returns, linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import Sm83BitAtHl, Sm83BitRegister, Sm83LoadAImmediate, Sm83XorA

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xEFFF

H_SPRITE_INDEX = 0xFF8C
H_JOY_HELD = 0xFFB4
W_MISC_FLAGS = 0xCD60
W_STATUS_FLAGS1 = 0xD728
W_BOULDER_INDEX = 0xD718
W_TILE_RESULT = 0xD71C
W_FACING = 0xC109
W_NUM_SPRITES = 0xD4E1


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


class NoSpriteBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x40, 8)
        self.state.regs.b = claripy.BVV(0x3C, 8)
        self.state.regs.c = claripy.BVV(0x40, 8)
        self.state.regs.d = claripy.BVV(0x10, 8)
        self.ret()


def _setup(state: angr.SimState, base: int, *, status: int, misc: int,
           sprites: int = 0) -> None:
    for address, value in (
        (W_STATUS_FLAGS1, status), (W_MISC_FLAGS, misc),
        (H_SPRITE_INDEX, 0), (H_JOY_HELD, 0), (W_BOULDER_INDEX, 0),
        (W_TILE_RESULT, 0), (W_FACING, 0), (W_NUM_SPRITES, sprites),
    ):
        state.memory.store(base + address, claripy.BVV(value, 8))


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(*(state.memory.load(base + address, 1) for address in (
        H_SPRITE_INDEX, W_MISC_FLAGS, W_BOULDER_INDEX, W_TILE_RESULT,
        W_FACING, W_NUM_SPRITES,
    )))


def _endpoint(state: angr.SimState, *, native: bool, base: int) -> Endpoint:
    return Endpoint(
        **(native_registers(state, NATIVE_STATE) if native else assembly_registers(state)),
        memory=_memory(state, base), constraints=tuple(state.solver.constraints),
    )


def _assembly(values: dict[str, claripy.ast.BV], *, status: int, misc: int,
              sprites: int) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "TryPushingBoulder")
    tail = symbol_location(SYMBOLS, "DoBoulderDustAnimation")
    assert linked_bytes(ROM, location, tail.address - location.address) == bytes.fromhex(
        "fa28d7cb47c8fa60cdcb4fc0afe08ccd6b0bf08cea18d7a7cadd722101c11600f08ccb375f19cbbecd58357efe10c2dd722160cdcb76cbf6c8f0b4e6f0c83e5acd6d3efa1cd7a7c2dd72f0b447fa09c1fe042810fe082814fe0c2818cb78c811af721816cb70c811ad72180ecb68c811b1721806cb60c811b372cd3a363ea8cdb1232160cdcbcec940ff00ff80ffc0ff"
    )
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    q = location.address
    project.hook(q + 0x00, Sm83LoadAImmediate(W_STATUS_FLAGS1, q + 0x03), length=3)
    project.hook(q + 0x03, Sm83BitRegister(0, "a", q + 0x05), length=2)
    project.hook(q + 0x06, Sm83LoadAImmediate(W_MISC_FLAGS, q + 0x09), length=3)
    project.hook(q + 0x09, Sm83BitRegister(1, "a", q + 0x0b), length=2)
    project.hook(q + 0x0c, Sm83XorA(q + 0x0d), length=1)
    if sprites == 0:
        project.hook(0x0B6B, NoSpriteBoundary(), length=2)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    _setup(state, 0, status=status, misc=misc, sprites=sprites)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    return [_endpoint(end, native=False, base=0)
            for end in collect_returns(project, state, RETURN)]


def _native(values: dict[str, claripy.ast.BV], *, status: int, misc: int,
            sprites: int) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_try_pushing_boulder")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, NATIVE_MEMORY, status=status, misc=misc, sprites=sprites)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and manager.deadended
    return [_endpoint(end, native=True, base=NATIVE_MEMORY)
            for end in manager.deadended]


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),
                    reason="build artifacts missing")
@pytest.mark.parametrize("status,misc,sprites", ((0, 0, 0), (1, 2, 0)))
def test_try_pushing_boulder_pathwise_equivalence(status: int, misc: int,
                                                   sprites: int) -> None:
    values = {register: claripy.BVV(0, 8) for register in REGISTERS}
    assert_pathwise_equivalent(
        _assembly(values, status=status, misc=misc, sprites=sprites),
        _native(values, status=status, misc=misc, sprites=sprites),
        (*REGISTERS, "memory"),
    )
