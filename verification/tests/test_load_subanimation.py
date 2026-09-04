from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
    assembly_registers,
    native_registers,
    set_assembly_registers,
    store_native_registers,
    symbolic_registers,
)
from verification.harness.rom import linked_bytes, rom_window, symbol_location

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF
POINTER = 0xC500
SUBANIMATION = 0xC600
W_SUBANIM_COUNTER = 0xD087
W_SUBANIM_TRANSFORM = 0xD08B
W_SUBANIM_ADDR_PTR = 0xD094
W_SUBANIM_SUBENTRY_ADDR = 0xD096
H_WHOSE_TURN = 0xFFF3
ENDPOINT_MEMORY = 10


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


class LoadAAbsolute(angr.SimProcedure):
    def __init__(self, address: int, next_address: int) -> None:
        super().__init__()
        self.address = address
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self.address, 1)
        self.jump(self.next_address)


class StoreAAbsolute(angr.SimProcedure):
    def __init__(self, address: int, next_address: int) -> None:
        super().__init__()
        self.address = address
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(self.address, self.state.regs.a)
        self.jump(self.next_address)


class LoadAAtHLIncrement(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        value = self.state.memory.load(self.state.regs.hl, 1)
        self.state.regs.a = value
        self.state.regs.hl = self.state.regs.hl + 1
        self.jump(self.addr + 1)


class LoadAAtHL(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self.state.regs.hl, 1)
        self.jump(self.addr + 1)


class LoadHAtHL(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = self.state.memory.load(self.state.regs.hl, 1)
        self.jump(self.addr + 1)


class LoadAAtDE(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self.state.regs.de, 1)
        self.jump(self.addr + 1)


class AndImmediate(angr.SimProcedure):
    def __init__(self, immediate: int, next_address: int) -> None:
        super().__init__()
        self.immediate = immediate
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.regs.a & self.immediate
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0, claripy.BVV(0x50, 8), claripy.BVV(0x10, 8)
        )
        self.jump(self.next_address)


class OrA(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)
        )
        self.jump(self.addr + 1)


class XorA(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x40, 8)
        self.jump(self.addr + 1)


class ShiftRightA(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        old = self.state.regs.a
        self.state.regs.a = claripy.LShR(old, 1)
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)
        ) | claripy.ZeroExt(7, old[0])
        self.jump(self.addr + 2)


class SwapA(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        value = self.state.regs.a
        self.state.regs.a = ((value & 0x0F) << 4) | ((value & 0xF0) >> 4)
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)
        )
        self.jump(self.addr + 2)


class CompareImmediate(angr.SimProcedure):
    def __init__(self, immediate: int, next_address: int) -> None:
        super().__init__()
        self.immediate = immediate
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        left = self.state.regs.a
        right = claripy.BVV(self.immediate, 8)
        flags = claripy.BVV(0x02, 8)
        flags |= claripy.If(left == right, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        flags |= claripy.If(
            (left & 0x0F).ULT(right & 0x0F), claripy.BVV(0x10, 8), claripy.BVV(0, 8)
        )
        flags |= claripy.If(left.ULT(right), claripy.BVV(1, 8), claripy.BVV(0, 8))
        self.state.regs.f = flags
        self.jump(self.next_address)


class AddHLPair(angr.SimProcedure):
    def __init__(self, pair: str) -> None:
        super().__init__()
        self.pair = pair

    def run(self) -> None:  # type: ignore[override]
        left = self.state.regs.hl
        right = getattr(self.state.regs, self.pair)
        result = left + right
        flags = self.state.regs.f & 0x42
        flags |= claripy.If(
            (left & 0x0FFF) + (right & 0x0FFF) > 0x0FFF,
            claripy.BVV(0x10, 8),
            claripy.BVV(0, 8),
        )
        flags |= claripy.If(
            claripy.ZeroExt(1, left) + claripy.ZeroExt(1, right) > 0xFFFF,
            claripy.BVV(1, 8),
            claripy.BVV(0, 8),
        )
        self.state.regs.hl = result
        self.state.regs.f = flags
        self.jump(self.addr + 1)


class IncDE(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.de = self.state.regs.de + 1
        self.jump(self.addr + 1)


class DecA(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        old = self.state.regs.a
        self.state.regs.a = old - 1
        flags = self.state.regs.f & 1
        flags |= 0x02
        flags |= claripy.If(self.state.regs.a == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        flags |= claripy.If((old & 0x0F) == 0, claripy.BVV(0x10, 8), claripy.BVV(0, 8))
        self.state.regs.f = flags
        self.jump(self.addr + 1)


class BranchNZ(angr.SimProcedure):
    def __init__(self, target: int, next_address: int) -> None:
        super().__init__()
        self.target = target
        self.next_address = next_address
    def run(self) -> None:  # type: ignore[override]
        zero_mask = self.state.solver.eval(self.state.regs.f & 0x40, cast_to=int)
        if zero_mask == 0:
            self.jump(self.target)
        else:
            self.jump(self.next_address)


class TransformSummary(angr.SimProcedure):
    def __init__(self, enemy: bool, next_address: int) -> None:
        super().__init__()
        self.enemy = enemy
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        turn = self.state.memory.load(H_WHOSE_TURN, 1)
        incoming = self.state.regs.a
        if self.enemy:
            self.state.regs.a = claripy.If(
                turn == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)
            )
            self.state.regs.f = claripy.BVV(0x50, 8)
        else:
            self.state.regs.a = claripy.If(
                turn == 0, claripy.BVV(0, 8), incoming
            )
            self.state.regs.b = incoming
            self.state.regs.f = claripy.If(
                turn == 0, claripy.BVV(0x50, 8), claripy.BVV(0x10, 8)
            )
        self.jump(self.next_address)


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    return symbolic_registers(prefix)


def _setup_memory(state: angr.SimState, base: int, packed: int, turn: int) -> None:
    state.memory.store(base + W_SUBANIM_ADDR_PTR, claripy.BVV(POINTER & 0xFF, 8))
    state.memory.store(base + W_SUBANIM_ADDR_PTR + 1, claripy.BVV(POINTER >> 8, 8))
    state.memory.store(base + POINTER, claripy.BVV(SUBANIMATION & 0xFF, 8))
    state.memory.store(base + POINTER + 1, claripy.BVV(SUBANIMATION >> 8, 8))
    state.memory.store(base + SUBANIMATION, claripy.BVV(packed, 8))
    state.memory.store(base + H_WHOSE_TURN, claripy.BVV(turn, 8))




def _endpoint(state: angr.SimState, base: int, native: bool) -> Endpoint:
    registers = native_registers(state, NATIVE_STATE) if native else assembly_registers(state)
    return Endpoint(
        **registers,
        memory=claripy.Concat(
            *(state.memory.load(base + address, 1) for address in (
                W_SUBANIM_COUNTER,
                W_SUBANIM_TRANSFORM,
                W_SUBANIM_SUBENTRY_ADDR,
                W_SUBANIM_SUBENTRY_ADDR + 1,
                W_SUBANIM_ADDR_PTR,
                W_SUBANIM_ADDR_PTR + 1,
                POINTER,
                POINTER + 1,
                SUBANIMATION,
                H_WHOSE_TURN,
            ))
        ),
        constraints=tuple(state.solver.constraints),
    )


def _assembly(values: dict[str, claripy.ast.BV], packed: int, turn: int) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "LoadSubanimation")
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
    body = linked_bytes(ROM, location, 70)
    base = location.address
    for offset, opcode in enumerate(body):
        address = base + offset
        if opcode == 0xFA:
            target = body[offset + 1] | (body[offset + 2] << 8)
            project.hook(address, LoadAAbsolute(target, address + 3), length=3)
        elif opcode == 0xEA:
            target = body[offset + 1] | (body[offset + 2] << 8)
            project.hook(address, StoreAAbsolute(target, address + 3), length=3)
        elif opcode == 0xF0:
            project.hook(address, LoadAAbsolute(0xFF00 + body[offset + 1], address + 2), length=2)
        elif opcode == 0x2A:
            project.hook(address, LoadAAtHLIncrement(), length=1)
        elif opcode == 0x7E:
            project.hook(address, LoadAAtHL(), length=1)
        elif opcode == 0x66:
            project.hook(address, LoadHAtHL(), length=1)
        elif opcode == 0x1A:
            project.hook(address, LoadAAtDE(), length=1)
        elif opcode == 0xE6:
            project.hook(address, AndImmediate(body[offset + 1], address + 2), length=2)
        elif opcode == 0xB7:
            project.hook(address, OrA(), length=1)
        elif opcode == 0xAF:
            project.hook(address, XorA(), length=1)
        elif opcode == 0xCB and body[offset + 1] == 0x3F:
            project.hook(address, ShiftRightA(), length=2)
        elif opcode == 0xCB and body[offset + 1] == 0x37:
            project.hook(address, SwapA(), length=2)
        elif opcode == 0xFE:
            project.hook(address, CompareImmediate(body[offset + 1], address + 2), length=2)
        elif opcode == 0x09:
            project.hook(address, AddHLPair("bc"), length=1)
        elif opcode == 0x19:
            project.hook(address, AddHLPair("de"), length=1)
        elif opcode == 0x13:
            project.hook(address, IncDE(), length=1)
        elif opcode == 0x3D:
            project.hook(address, DecA(), length=1)
        elif opcode == 0x20:
            displacement = body[offset + 1]
            if displacement & 0x80:
                displacement -= 0x100
            project.hook(address, BranchNZ(address + 2 + displacement, address + 2), length=2)
        elif opcode == 0xCD:
            target = body[offset + 1] | (body[offset + 2] << 8)
            enemy = target == symbol_location(SYMBOLS, "GetSubanimationTransform2").address
            project.hook(address, TransformSummary(enemy, address + 3), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _setup_memory(state, 0, packed, turn)
    state.regs.sp = 0xD000
    state.memory.store(0xD000, claripy.BVV(DONE, 16), endness="Iend_LE")
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=4)
    assert not manager.errored
    assert len(manager.found) == 1
    return [_endpoint(manager.found[0], 0, False)]


def _native(values: dict[str, claripy.ast.BV], packed: int, turn: int) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_load_subanimation")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup_memory(state, NATIVE_MEMORY, packed, turn)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    return [_endpoint(manager.deadended[0], NATIVE_MEMORY, True)]


@pytest.mark.parametrize(
    "packed,turn",
    [
        (subanimation_type << 5 | counter, turn)
        for subanimation_type in range(8)
        for counter in (1, 3)
        for turn in (0, 1)
    ],
)
@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_load_subanimation_pathwise_equivalence(packed: int, turn: int) -> None:
    values = _inputs(f"load_subanimation_{packed:02x}_{turn}")
    if packed == 1 and turn == 0:
        location = symbol_location(SYMBOLS, "LoadSubanimation")
        assert linked_bytes(ROM, location, 70) == bytes.fromhex(
            "fa95d067fa94d06f2a5f7e571a47e61fea87d078e6e0fea02005cdca411803cdc241cb3fcb37ea8bd0fe04210000200bfa87d03d010300093d20fc13197dea96d07cea97d0c9"
        )
    assert_pathwise_equivalent(
        _assembly(values, packed, turn),
        _native(values, packed, turn),
        ("a", "f", "b", "c", "d", "e", "h", "l", "memory"),
    )
