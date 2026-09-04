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
    Sm83AndRegister, Sm83CpRegister, Sm83LoadAImmediate, Sm83Scf,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xEFFF

W_Y = 0xD361
W_X = 0xD362
W_HEIGHT = 0xD368
W_WIDTH = 0xD369
W_FACING = 0xC109


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
    carry: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class Dispatch(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__()
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        direction = self.state.solver.eval(
            self.state.memory.load(W_FACING, 1) >> 1
        )
        self.state.regs.c = claripy.BVV(direction, 8)
        self.state.regs.b = claripy.BVV(0, 8)
        targets = (self.target + 0x2B, self.target + 0x35,
                   self.target + 0x3B, self.target + 0x41)
        # The test domain uses concrete valid facing values (0, 4, 8, 12).
        chosen = targets[direction >> 1]
        self.state.regs.hl = claripy.BVV(chosen, 16)
        self.jump(self.target + 0x12)


def _setup(state: angr.SimState, base: int, *, facing: int, y: int,
           x: int, height: int, width: int) -> None:
    for address, value in ((W_FACING, facing), (W_Y, y), (W_X, x),
                           (W_HEIGHT, height), (W_WIDTH, width)):
        state.memory.store(base + address, claripy.BVV(value, 8))


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(*(state.memory.load(base + address, 1)
                            for address in (W_FACING, W_Y, W_X, W_HEIGHT, W_WIDTH)))


def _endpoint(state: angr.SimState, *, native: bool, carry: claripy.ast.BV) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    regs = native_registers(state, NATIVE_STATE) if native else assembly_registers(state)
    return Endpoint(**regs, memory=_memory(state, base), carry=carry,
                    constraints=tuple(state.solver.constraints))


def _assembly(values: dict[str, claripy.ast.BV], *, facing: int, y: int,
              x: int, height: int, width: int) -> list[Endpoint]:
    loc = symbol_location(SYMBOLS, "IsPlayerFacingEdgeOfMap")
    end = symbol_location(SYMBOLS, "IsWarpTileInFrontOfPlayer")
    assert len(linked_bytes(ROM, loc, end.address - loc.address)) == 79
    project = angr.Project(
        rom_window(ROM, loc.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": loc.address},
    )
    q = loc.address
    # Absolute loads, SRL, table dispatch, and branch tails are instruction seams.
    project.hook(q + 0x03, Sm83LoadAImmediate(W_FACING, q + 0x06), length=3)
    project.hook(q + 0x0B, Dispatch(q), length=7)
    project.hook(q + 0x12, Sm83LoadAImmediate(W_Y, q + 0x15), length=3)
    project.hook(q + 0x16, Sm83LoadAImmediate(W_X, q + 0x19), length=3)
    project.hook(q + 0x2B, Sm83LoadAImmediate(W_HEIGHT, q + 0x2E), length=3)
    project.hook(q + 0x30, Sm83CpRegister("b", q + 0x31), length=1)
    project.hook(q + 0x36, Sm83AndRegister("a", q + 0x37), length=1)
    project.hook(q + 0x3C, Sm83AndRegister("a", q + 0x3D), length=1)
    project.hook(q + 0x41, Sm83LoadAImmediate(W_WIDTH, q + 0x44), length=3)
    project.hook(q + 0x46, Sm83CpRegister("c", q + 0x47), length=1)
    project.hook(q + 0x4B, Sm83AndRegister("a", q + 0x4C), length=1)
    project.hook(q + 0x4D, Sm83Scf(q + 0x4E), length=1)
    state = project.factory.blank_state(addr=loc.address)
    set_assembly_registers(state, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    _setup(state, 0, facing=facing, y=y, x=x, height=height, width=width)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN, num_find=16)
    assert not manager.errored and manager.found
    return [_endpoint(end_state, native=False,
                      carry=claripy.If(end_state.regs.f & 1,
                                       claripy.BVV(1, 8), claripy.BVV(0, 8)))
            for end_state in manager.found]


def _native(values: dict[str, claripy.ast.BV], **case: int) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_is_player_facing_edge_of_map")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, NATIVE_MEMORY, **case)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and manager.deadended
    return [_endpoint(end_state, native=True,
                      carry=end_state.regs.rax[7:0] & claripy.BVV(1, 8))
            for end_state in manager.deadended]


CASES = tuple(
    {"facing": facing, "y": y, "x": x, "height": 10, "width": 12}
    for facing, y, x in (
        (0, 19, 7), (0, 18, 7), (4, 0, 7), (4, 1, 7),
        (8, 7, 0), (8, 7, 1), (12, 7, 23), (12, 7, 22),
    )
)


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),
                    reason="build artifacts missing")
@pytest.mark.parametrize("case", CASES)
def test_is_player_facing_edge_of_map_pathwise_equivalence(case: dict[str, int]) -> None:
    values = {register: claripy.BVV(0, 8) for register in REGISTERS}
    assert_pathwise_equivalent(
        _assembly(values, **case), _native(values, **case),
        (*REGISTERS, "memory", "carry"),
    )


def test_exact_body() -> None:
    loc = symbol_location(SYMBOLS, "IsPlayerFacingEdgeOfMap")
    end = symbol_location(SYMBOLS, "IsWarpTileInFrontOfPlayer")
    assert linked_bytes(ROM, loc, end.address - loc.address) == bytes.fromhex(
        "e5d5c5fa09c1cb3f4f0600212244092a666ffa61d347fa62d34f111e44d5e9"
        "c1d1e1c92a4434443a444044fa68d3873db8281a181678a72814181079a728"
        "0e180afa69d3873db928041800a7c937c9"
    )
