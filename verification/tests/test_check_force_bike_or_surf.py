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
from verification.harness.rom import linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import (
    Sm83CpImmediate,
    Sm83CpRegister,
    Sm83LoadAAtHlIncrement,
    Sm83LoadAImmediate,
    Sm83SetAtHl,
    Sm83StoreAImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF

W_CUR_MAP = 0xD35E
W_Y_COORD = 0xD361
W_X_COORD = 0xD362
W_B3F_SCRIPT = 0xD666
W_B4F_SCRIPT = 0xD668
W_WALK_STATE = 0xD700
W_WALK_STATE_COPY = 0xD11A
W_STATUS6 = 0xD732
TABLE = 0x43E6
TABLE_BYTES = bytes((0x1B, 10, 17, 0x1B, 11, 17, 0x1D, 8, 33,
                     0x1D, 9, 33, 0xA1, 7, 18, 0xA1, 7, 19,
                     0xA2, 14, 4, 0xA2, 14, 5, 0xFF))


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
    status6: claripy.ast.BV
    b3f_script: claripy.ast.BV
    b4f_script: claripy.ast.BV
    walk_state: claripy.ast.BV
    walk_state_copy: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class BranchZ(angr.SimProcedure):
    def __init__(self, taken: int, fallthrough: int, *, nonzero: bool = False) -> None:
        super().__init__()
        self.taken = taken
        self.fallthrough = fallthrough
        self.nonzero = nonzero

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        zero = (self.state.regs.f & 0x40) != 0
        condition = claripy.Not(zero) if self.nonzero else zero
        self.successors.add_successor(self.state.copy(), self.taken, condition, "Ijk_Boring")
        self.successors.add_successor(self.state.copy(), self.fallthrough, claripy.Not(condition), "Ijk_Boring")


class SurfingBranch(angr.SimProcedure):
    def __init__(self, false_target: int) -> None:
        super().__init__()
        self.false_target = false_target

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        zero = (self.state.regs.f & 0x40) != 0
        taken = self.state.copy()
        taken.regs.a = claripy.BVV(2, 8)
        taken.memory.store(W_WALK_STATE, claripy.BVV(2, 8))
        taken.memory.store(W_WALK_STATE_COPY, claripy.BVV(2, 8))
        self.successors.add_successor(taken, DONE, zero, "Ijk_Boring")
        self.successors.add_successor(self.state.copy(), self.false_target, claripy.Not(zero), "Ijk_Boring")


class LoadImmediateKeepFlags(angr.SimProcedure):
    def __init__(self, value: int, target: int) -> None:
        super().__init__()
        self.value = value
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(self.value, 8)
        self.jump(self.target)


class LoadHLImmediate(angr.SimProcedure):
    def __init__(self, value: int, target: int) -> None:
        super().__init__()
        self.value = value
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.hl = claripy.BVV(self.value, 16)
        self.jump(self.target)


class IncHL(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__()
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.hl = self.state.regs.hl + 1
        self.jump(self.target)


class Jump(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__()
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.jump(self.target)


class Return(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(DONE)


def _setup(state: angr.SimState, base: int, *, status6: int, current_map: int,
           y: int, x: int) -> None:
    state.memory.store(base + W_STATUS6, claripy.BVV(status6, 8))
    state.memory.store(base + W_CUR_MAP, claripy.BVV(current_map, 8))
    state.memory.store(base + W_Y_COORD, claripy.BVV(y, 8))
    state.memory.store(base + W_X_COORD, claripy.BVV(x, 8))
    state.memory.store(base + W_B3F_SCRIPT, claripy.BVV(0x77, 8))
    state.memory.store(base + W_B4F_SCRIPT, claripy.BVV(0x77, 8))
    state.memory.store(base + W_WALK_STATE, claripy.BVV(0x77, 8))
    state.memory.store(base + W_WALK_STATE_COPY, claripy.BVV(0x77, 8))
    for offset, value in enumerate(TABLE_BYTES):
        state.memory.store(base + TABLE + offset, claripy.BVV(value, 8))


def _endpoint(state: angr.SimState, base: int, *, register_base: int | None = None) -> Endpoint:
    if register_base is None:
        register_base = base
    return Endpoint(
        **(assembly_registers(state) if base == 0 else native_registers(state, register_base)),
        status6=state.memory.load(base + W_STATUS6, 1),
        b3f_script=state.memory.load(base + W_B3F_SCRIPT, 1),
        b4f_script=state.memory.load(base + W_B4F_SCRIPT, 1),
        walk_state=state.memory.load(base + W_WALK_STATE, 1),
        walk_state_copy=state.memory.load(base + W_WALK_STATE_COPY, 1),
        constraints=tuple(state.solver.constraints),
    )


def _assembly(values: dict[str, claripy.ast.BV], **kwargs: int) -> list[Endpoint]:
    loc = symbol_location(SYMBOLS, "CheckForceBikeOrSurf")
    project = angr.Project(
        rom_window(ROM, loc.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": loc.address},
    )
    b = loc.address
    project.hook(b + 0x00, LoadHLImmediate(W_STATUS6, b + 0x03), length=3)
    project.hook(b + 0x03, Sm83BitAtHl(b + 0x05), length=2)
    project.hook(b + 0x05, BranchZ(DONE, b + 0x06, nonzero=True), length=1)
    project.hook(b + 0x06, LoadHLImmediate(TABLE, b + 0x09), length=3)
    project.hook(b + 0x09, Sm83LoadAImmediate(W_Y_COORD, b + 0x0C), length=3)
    project.hook(b + 0x0D, Sm83LoadAImmediate(W_X_COORD, b + 0x10), length=3)
    project.hook(b + 0x11, Sm83LoadAImmediate(W_CUR_MAP, b + 0x14), length=3)
    project.hook(b + 0x15, Sm83LoadAAtHlIncrement(b + 0x16), length=1)
    project.hook(b + 0x18, BranchZ(DONE, b + 0x19), length=1)
    project.hook(b + 0x19, Sm83CpRegister("d", b + 0x1A), length=1)
    project.hook(b + 0x1A, BranchZ(b + 0x4C, b + 0x1C, nonzero=True), length=2)
    project.hook(b + 0x1C, Sm83LoadAAtHlIncrement(b + 0x1D), length=1)
    project.hook(b + 0x1E, BranchZ(b + 0x4D, b + 0x20, nonzero=True), length=2)
    project.hook(b + 0x20, Sm83LoadAAtHlIncrement(b + 0x21), length=1)
    project.hook(b + 0x22, BranchZ(b + 0x15, b + 0x24, nonzero=True), length=2)
    project.hook(b + 0x4C, IncHL(b + 0x4D), length=1)
    project.hook(b + 0x4D, IncHL(b + 0x4E), length=1)
    project.hook(b + 0x4E, Jump(b + 0x15), length=2)
    project.hook(b + 0x24, Sm83LoadAImmediate(W_CUR_MAP, b + 0x27), length=3)
    project.hook(b + 0x27, Sm83CpImmediate(0xA1, b + 0x29), length=2)
    project.hook(b + 0x29, LoadImmediateKeepFlags(2, b + 0x2B), length=2)
    project.hook(b + 0x2B, Sm83StoreAImmediate(W_B3F_SCRIPT, b + 0x2E), length=3)
    project.hook(b + 0x2E, SurfingBranch(b + 0x30), length=2)
    project.hook(b + 0x30, Sm83LoadAImmediate(W_CUR_MAP, b + 0x33), length=3)
    project.hook(b + 0x33, Sm83CpImmediate(0xA2, b + 0x35), length=2)
    project.hook(b + 0x35, LoadImmediateKeepFlags(2, b + 0x37), length=2)
    project.hook(b + 0x37, Sm83StoreAImmediate(W_B4F_SCRIPT, b + 0x3A), length=3)
    project.hook(b + 0x3A, SurfingBranch(b + 0x3C), length=2)
    project.hook(b + 0x3C, LoadHLImmediate(W_STATUS6, b + 0x3F), length=3)
    project.hook(b + 0x3F, Sm83SetAtHl(5, b + 0x41), length=2)
    project.hook(b + 0x41, LoadImmediateKeepFlags(1, b + 0x43), length=2)
    project.hook(b + 0x43, Sm83StoreAImmediate(W_WALK_STATE, b + 0x46), length=3)
    project.hook(b + 0x46, Sm83StoreAImmediate(W_WALK_STATE_COPY, b + 0x49), length=3)
    project.hook(b + 0x49, Return(), length=1)
    project.hook(b + 0x50, LoadImmediateKeepFlags(2, b + 0x52), length=2)
    project.hook(b + 0x52, Sm83StoreAImmediate(W_WALK_STATE, b + 0x55), length=3)
    project.hook(b + 0x55, Sm83StoreAImmediate(W_WALK_STATE_COPY, b + 0x58), length=3)
    project.hook(b + 0x59, Return(), length=1)
    state = project.factory.blank_state(addr=b)
    set_assembly_registers(state, values)
    _setup(state, 0, **kwargs)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=16)
    assert not manager.errored and manager.found
    return [_endpoint(found, 0) for found in manager.found]


class Sm83BitAtHl(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__()
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        value = self.state.memory.load(self.state.regs.hl, 1)
        self.state.regs.f = (self.state.regs.f & 0x01) | 0x10 | claripy.If(
            value & 0x20 == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        self.jump(self.target)


def _native(values: dict[str, claripy.ast.BV], **kwargs: int) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_check_force_bike_or_surf")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, NATIVE_MEMORY, **kwargs)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [_endpoint(manager.deadended[0], NATIVE_MEMORY, register_base=NATIVE_STATE)]


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(), reason="build artifacts missing")
@pytest.mark.parametrize("status6,current_map,y,x", [
    (0x20, 0x1B, 10, 17),   # already forced bike: early return
    (0x00, 0x55, 0, 0),     # sentinel / no match
    (0x00, 0x1B, 10, 17),   # Route 16 bike
    (0x00, 0x1D, 9, 33),    # Route 18 bike
    (0x00, 0xA1, 7, 18),    # Seafoam B3F surfing
    (0x00, 0xA2, 14, 5),    # Seafoam B4F surfing
    (0x00, 0x1B, 10, 99),   # same map/Y, wrong X then scan to sentinel
    (0x00, 0x55, 10, 17),   # wrong-map and wrong-Y skips
])
def test_check_force_bike_or_surf_pathwise_equivalence(status6: int, current_map: int,
                                                        y: int, x: int) -> None:
    values = symbolic_registers("cfbos")
    assert_pathwise_equivalent(
        _assembly(values, status6=status6, current_map=current_map, y=y, x=x),
        _native(values, status6=status6, current_map=current_map, y=y, x=x),
        (*REGISTERS, "status6", "b3f_script", "b4f_script", "walk_state", "walk_state_copy"),
    )


def test_check_force_bike_or_surf_exact_linked_body() -> None:
    loc = symbol_location(SYMBOLS, "CheckForceBikeOrSurf")
    assert linked_bytes(ROM, loc, 0x5B) == bytes.fromhex(
        "2132d7cb6ec021e643fa61d347fa62d34ffa5ed3572afeffc8ba20302ab8202d2ab920f1fa5ed3fea13e02ea66d62820fa5ed3fea23e02ea68d628142132d7cbee3e01ea00d7ea1ad1c3ed12232318c53e02ea00d7ea1ad1c3ed12"
    )
