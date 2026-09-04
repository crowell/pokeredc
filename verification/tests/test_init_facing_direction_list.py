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
    Sm83CpAtHl,
    Sm83LoadAImmediate,
    Sm83StoreAImmediate,
)


ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xd000
RETURN = 0xffff
IMAGE = 0xc102
YPOS = 0xc104
FACING_LIST = 0xcd48
SAVED_Y = 0xcd4f
SAVED_FACING = 0xcd50
SPIN_ORDER = 0x4713
FACING_ORDER = (0, 8, 4, 12)
BODY = bytes.fromhex(
    "fa02c1ea50cdfa04c1ea4fcd2113471148cd010400cdb500"
    "fa02c12148cdbe2320fc2bc9"
)


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
    state: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class CopyData(angr.SimProcedure):
    """The complete four-byte transition of the independently proven CopyData."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        source = self.state.regs.hl
        destination = self.state.regs.de
        for _ in range(4):
            self.state.memory.store(destination, self.state.memory.load(source, 1))
            source += 1
            destination += 1
        self.state.regs.hl = source
        self.state.regs.de = destination
        self.state.regs.bc = claripy.BVV(0, 16)
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x40, 8)
        self.jump(self.next_address)


class Return(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        target = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp += 2
        self.jump(target)


def setup(state: angr.SimState, base: int, values: dict[str, claripy.ast.BV]) -> None:
    state.memory.store(base + IMAGE, values["image"])
    state.memory.store(base + YPOS, values["y"])
    state.memory.store(base + SAVED_Y, values["saved_y"])
    state.memory.store(base + SAVED_FACING, values["saved_facing"])
    for offset, facing in enumerate(FACING_ORDER):
        state.memory.store(base + SPIN_ORDER + offset, claripy.BVV(facing, 8))
        state.memory.store(base + FACING_LIST + offset, values[f"list_{offset}"])


def endpoint(state: angr.SimState, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    registers = native_registers(state, NATIVE_STATE) if native else assembly_registers(state)
    watched = (IMAGE, YPOS, SAVED_Y, SAVED_FACING, *(FACING_LIST + i for i in range(4)))
    return Endpoint(
        **registers,
        state=claripy.Concat(*(state.memory.load(base + address, 1) for address in watched)),
        constraints=tuple(state.solver.constraints),
    )


def assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "InitFacingDirectionList")
    assert linked_bytes(ROM, location, len(BODY)) == BODY
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
    start = location.address
    project.hook(start, Sm83LoadAImmediate(IMAGE, start + 3), length=3)
    project.hook(start + 3, Sm83StoreAImmediate(SAVED_FACING, start + 6), length=3)
    project.hook(start + 6, Sm83LoadAImmediate(YPOS, start + 9), length=3)
    project.hook(start + 9, Sm83StoreAImmediate(SAVED_Y, start + 12), length=3)
    project.hook(start + 21, CopyData(start + 24), length=3)
    project.hook(start + 24, Sm83LoadAImmediate(IMAGE, start + 27), length=3)
    project.hook(start + 30, Sm83CpAtHl(start + 31), length=1)
    project.hook(start + 35, Return(), length=1)

    state = project.factory.blank_state(addr=start)
    set_assembly_registers(state, values)
    setup(state, 0, values)
    state.regs.sp = claripy.BVV(STACK, 16)
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN)
    assert not manager.errored and len(manager.found) == 1
    return [endpoint(manager.found[0], False)]


def native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_init_facing_direction_list")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    setup(state, NATIVE_MEMORY, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [endpoint(manager.deadended[0], True)]


@pytest.mark.skipif(
    not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),
    reason="build artifacts missing",
)
@pytest.mark.parametrize("facing", FACING_ORDER)
def test_init_facing_direction_list_pathwise_equivalence(facing: int) -> None:
    values = symbolic_registers(f"init_facing_{facing}")
    values["image"] = claripy.BVV(facing, 8)
    values["y"] = claripy.BVS(f"init_facing_{facing}_y", 8)
    values["saved_y"] = claripy.BVS(f"init_facing_{facing}_saved_y", 8)
    values["saved_facing"] = claripy.BVS(f"init_facing_{facing}_saved_facing", 8)
    for offset in range(4):
        values[f"list_{offset}"] = claripy.BVS(
            f"init_facing_{facing}_list_{offset}", 8
        )
    assert_pathwise_equivalent(
        assembly(values), native(values), (*REGISTERS, "state")
    )
