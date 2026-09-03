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
    Sm83AddImmediate,
    Sm83AndRegister,
    Sm83CpImmediate,
    Sm83IncRegister,
    Sm83StoreAHighImmediate,
    Sm83SubImmediate,
)


ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification" / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xd000
RETURN = 0xffff
SPRITE_DATA2 = 0xc200
CURRENT_OFFSET = 0xffda
BODY = bytes.fromhex(
    "26c1243e0e6fd60e4fe0da7ea72809e5d5c5cd544cc1d1e1"
    "7dc610fe0e20e6c9fe01c25c4cc3314e"
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


class RegisterCopy(angr.SimProcedure):
    def __init__(self, destination: str, source: str, next_address: int) -> None:
        super().__init__()
        self.destination = destination
        self.source = source
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.destination, getattr(self.state.regs, self.source))
        self.jump(self.next_address)


class LoadAtHL(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self.state.regs.hl, 1)
        self.jump(self.next_address)


class BranchZ(angr.SimProcedure):
    def __init__(self, when_set: int, when_clear: int) -> None:
        super().__init__()
        self.when_set = when_set
        self.when_clear = when_clear

    def run(self) -> None:  # type: ignore[override]
        condition = (self.state.regs.f & 0x40) != 0
        yes = self.state.copy()
        no = self.state.copy()
        yes.solver.add(condition)
        no.solver.add(~condition)
        yes.regs.ip = claripy.BVV(self.when_set, 16)
        no.regs.ip = claripy.BVV(self.when_clear, 16)
        self.inhibit_autoret = True
        self.successors.add_successor(yes, self.when_set, condition, "Ijk_Boring")
        self.successors.add_successor(no, self.when_clear, ~condition, "Ijk_Boring")


class Return(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        target = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp += 2
        self.jump(target)


def setup(state: angr.SimState, base: int) -> None:
    for offset in range(0x100):
        state.memory.store(base + SPRITE_DATA2 + offset, claripy.BVV(0, 8))
    state.memory.store(base + CURRENT_OFFSET, claripy.BVV(0x55, 8))


def endpoint(state: angr.SimState, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    registers = (
        native_registers(state, NATIVE_STATE)
        if native
        else assembly_registers(state)
    )
    watched = (*(SPRITE_DATA2 + 14 + 16 * slot for slot in range(16)), CURRENT_OFFSET)
    return Endpoint(
        **registers,
        state=claripy.Concat(*(state.memory.load(base + address, 1) for address in watched)),
        constraints=tuple(state.solver.constraints),
    )


def assembly(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "_UpdateSprites")
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
    project.hook(start + 2, Sm83IncRegister("h", start + 3), length=1)
    project.hook(start + 5, RegisterCopy("l", "a", start + 6), length=1)
    project.hook(start + 6, Sm83SubImmediate(14, start + 8), length=2)
    project.hook(start + 8, RegisterCopy("c", "a", start + 9), length=1)
    project.hook(start + 9, Sm83StoreAHighImmediate(CURRENT_OFFSET, start + 11), length=2)
    project.hook(start + 11, LoadAtHL(start + 12), length=1)
    project.hook(start + 12, Sm83AndRegister("a", start + 13), length=1)
    project.hook(start + 13, BranchZ(start + 24, start + 15), length=2)
    project.hook(start + 24, RegisterCopy("a", "l", start + 25), length=1)
    project.hook(start + 25, Sm83AddImmediate(16, start + 27), length=2)
    project.hook(start + 27, Sm83CpImmediate(14, start + 29), length=2)
    project.hook(start + 29, BranchZ(start + 31, start + 5), length=2)
    project.hook(start + 31, Return(), length=1)

    state = project.factory.blank_state(addr=start)
    set_assembly_registers(state, inputs)
    setup(state, 0)
    state.regs.sp = claripy.BVV(STACK, 16)
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN)
    assert not manager.errored and len(manager.found) == 1
    return [endpoint(manager.found[0], False)]


def native(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_update_sprites_private")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, inputs)
    setup(state, NATIVE_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [endpoint(manager.deadended[0], True)]


@pytest.mark.skipif(
    not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),
    reason="build artifacts missing",
)
def test_update_sprites_private_pathwise_equivalence() -> None:
    inputs = symbolic_registers("update_sprites_private")

    assert_pathwise_equivalent(
        assembly(inputs),
        native(inputs),
        (*REGISTERS, "state"),
    )
