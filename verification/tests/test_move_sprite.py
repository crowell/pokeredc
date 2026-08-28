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
    Sm83CpImmediate, Sm83DecRegister, Sm83IncRegister, Sm83LdAFromRegPreserveF,
    Sm83SetAtHl, Sm83StoreAImmediate, Sm83XorA,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xEFFF

H_SPRITE_INDEX = 0xFF8C
W_NPC_DIRECTIONS = 0xCC5B
W_NPC_STEPS = 0xCF0F
W_STATUS_FLAGS5 = 0xD730
W_OVERRIDE = 0xCD3B
W_SIMULATED_END = 0xCCD3
W_JOY_IGNORE = 0xCD6B
W_UNUSED_INDEX = 0xCD3A


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


class LoadHLImmediate(angr.SimProcedure):
    def __init__(self, value: int, next_address: int) -> None:
        super().__init__()
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.hl = claripy.BVV(self.value, 16)
        self.jump(self.next_address)


class GetMovementPointerBoundary(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.hl = claripy.BVV(0xC216, 16)
        self.jump(self.next_address)


class SetMovementBytesBoundary(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(0xC216, claripy.BVV(0xFF, 8))
        self.state.memory.store(0xD4E4, claripy.BVV(0xFF, 8))
        self.jump(self.next_address)


class LoadAAtDE(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self.state.regs.de, 1)
        self.jump(self.next_address)


class StoreAAtHLIncrement(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(self.state.regs.hl, self.state.regs.a)
        self.state.regs.hl = self.state.regs.hl + 1
        self.jump(self.next_address)


class StoreAAtHL(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(self.state.regs.hl, self.state.regs.a)
        self.jump(self.next_address)


class BranchNZ(angr.SimProcedure):
    def __init__(self, taken: int, fallthrough: int) -> None:
        super().__init__()
        self.taken = taken
        self.fallthrough = fallthrough

    def run(self) -> None:  # type: ignore[override]
        condition = (self.state.regs.f & 0x40) == 0
        self.inhibit_autoret = True
        self.successors.add_successor(self.state.copy(), self.taken,
                                      condition, "Ijk_Boring")
        self.successors.add_successor(self.state.copy(), self.fallthrough,
                                      claripy.Not(condition), "Ijk_Boring")


class LoadCImmediate(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.c = claripy.BVV(0, 8)
        self.jump(self.next_address)


def _setup(state: angr.SimState, base: int, sequence: tuple[int, ...]) -> None:
    for address, value in (
        (H_SPRITE_INDEX, 1), (W_STATUS_FLAGS5, 0xA0),
        (W_OVERRIDE, 0x33), (W_SIMULATED_END, 0x44),
        (W_JOY_IGNORE, 0x55), (W_UNUSED_INDEX, 0x66),
        (W_NPC_STEPS, 0x77), (0xC216, 0x11), (0xD4E4, 0x22),
    ):
        state.memory.store(base + address, claripy.BVV(value, 8))
    state.memory.store(base + W_NPC_DIRECTIONS,
                       claripy.BVV(0x5A, 8), endness="Iend_LE")
    for offset, value in enumerate(sequence):
        state.memory.store(base + 0x0700 + offset,
                           claripy.BVV(value, 8))
    for offset in range(1, 180):
        state.memory.store(base + W_NPC_DIRECTIONS + offset,
                           claripy.BVV(0x5A, 8))


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        state.memory.load(base + W_NPC_DIRECTIONS, 180),
        *(state.memory.load(base + address, 1) for address in (
            H_SPRITE_INDEX, W_NPC_STEPS, W_STATUS_FLAGS5, W_OVERRIDE,
            W_SIMULATED_END, W_JOY_IGNORE, W_UNUSED_INDEX, 0xC216, 0xD4E4,
        )),
    )


def _endpoint(state: angr.SimState, *, native: bool, base: int) -> Endpoint:
    return Endpoint(
        **(native_registers(state, NATIVE_STATE) if native else assembly_registers(state)),
        memory=_memory(state, base), constraints=tuple(state.solver.constraints)
    )


def _assembly(values: dict[str, claripy.ast.BV], sequence: tuple[int, ...]) -> list[Endpoint]:
    loc = symbol_location(SYMBOLS, "MoveSprite")
    end = symbol_location(SYMBOLS, "DivideBytes")
    assert linked_bytes(ROM, loc, end.address - loc.address) == bytes.fromhex(
        "cd4135e5c5cd4e35af77215bcc0e001a22130cfeff20f879ea0fcfc12130d7cbc6e1afea3bcdead3cc3dea6bcdea3acdc9"
    )
    project = angr.Project(rom_window(ROM, loc.bank), auto_load_libs=False,
                           rebase_granularity=0x100,
                           main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                                      "base_addr": 0, "entry_point": loc.address})
    q = loc.address
    project.hook(q + 0x00, SetMovementBytesBoundary(q + 0x03), length=3)
    project.hook(q + 0x05, GetMovementPointerBoundary(q + 0x08), length=3)
    project.hook(q + 0x09, StoreAAtHL(q + 0x0A), length=1)
    project.hook(q + 0x0A, LoadHLImmediate(W_NPC_DIRECTIONS, q + 0x0D), length=3)
    project.hook(q + 0x0D, LoadCImmediate(q + 0x0F), length=2)
    project.hook(q + 0x0F, LoadAAtDE(q + 0x10), length=1)
    project.hook(q + 0x10, StoreAAtHLIncrement(q + 0x11), length=1)
    project.hook(q + 0x12, Sm83IncRegister("c", q + 0x13), length=1)
    project.hook(q + 0x13, Sm83CpImmediate(0xFF, q + 0x15), length=2)
    project.hook(q + 0x15, BranchNZ(q + 0x0F, q + 0x17), length=2)
    project.hook(q + 0x17, Sm83LdAFromRegPreserveF("c", q + 0x18), length=1)
    project.hook(q + 0x18, Sm83StoreAImmediate(W_NPC_STEPS, q + 0x1B), length=3)
    project.hook(q + 0x1C, LoadHLImmediate(W_STATUS_FLAGS5, q + 0x1F), length=3)
    project.hook(q + 0x1F, Sm83SetAtHl(0, q + 0x21), length=2)
    project.hook(q + 0x22, Sm83XorA(q + 0x23), length=1)
    project.hook(q + 0x23, Sm83StoreAImmediate(W_OVERRIDE, q + 0x26), length=3)
    project.hook(q + 0x26, Sm83StoreAImmediate(W_SIMULATED_END, q + 0x29), length=3)
    project.hook(q + 0x29, Sm83DecRegister("a", q + 0x2C), length=1)
    project.hook(q + 0x2C, Sm83StoreAImmediate(W_JOY_IGNORE, q + 0x2F), length=3)
    project.hook(q + 0x2F, Sm83StoreAImmediate(W_UNUSED_INDEX, q + 0x30), length=3)
    state = project.factory.blank_state(addr=loc.address)
    set_assembly_registers(state, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    _setup(state, 0, sequence)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN, num_find=8)
    assert not manager.errored and manager.found
    return [_endpoint(end_state, native=False, base=0) for end_state in manager.found]


def _native(values: dict[str, claripy.ast.BV], sequence: tuple[int, ...]) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_move_sprite")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, NATIVE_MEMORY, sequence)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and manager.deadended
    return [_endpoint(end_state, native=True, base=NATIVE_MEMORY)
            for end_state in manager.deadended]


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),
                    reason="build artifacts missing")
@pytest.mark.parametrize("sequence", ((0xFF,), (0x01, 0x02, 0xFF)))
def test_move_sprite_pathwise_equivalence(sequence: tuple[int, ...]) -> None:
    values = {
        "a": claripy.BVV(0x9A, 8), "f": claripy.BVV(0x90, 8),
        "b": claripy.BVV(0x56, 8), "c": claripy.BVV(0x78, 8),
        "d": claripy.BVV(0x07, 8), "e": claripy.BVV(0x00, 8),
        "h": claripy.BVV(0x12, 8), "l": claripy.BVV(0x34, 8),
    }
    assert_pathwise_equivalent(
        _assembly(values, sequence), _native(values, sequence),
        (*REGISTERS, "memory"),
    )
