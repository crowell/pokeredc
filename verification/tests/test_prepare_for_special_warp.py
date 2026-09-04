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
    store_native_registers, symbolic_registers,
)
from verification.harness.rom import linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import Sm83StoreAImmediate

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xEFFF
W_CUR_MAP = 0xD35E
W_CURRENT_BLOCK_PTR = 0xD35F
W_CUR_MAP_TILESET = 0xD367
W_LAST_MAP = 0xD365
W_DESTINATION_MAP = 0xD71A
W_STATUS_FLAGS3 = 0xD72D
W_STATUS_FLAGS6 = 0xD732


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


class LoadSpecialWarpData(angr.SimProcedure):
    """New-game transition from the independently proven warp-data port."""

    def run(self) -> None:  # type: ignore[override]
        # NewGameWarp = 26 12 c7 06 03 00 01 04.
        values = (0x26, 0x12, 0xC7, 0x06, 0x03, 0x00, 0x01)
        for offset, value in enumerate(values):
            self.state.memory.store(W_CUR_MAP + offset, claripy.BVV(value, 8))
        self.state.memory.store(W_CUR_MAP_TILESET, claripy.BVV(0x04, 8))
        self.state.memory.store(0xD42F, claripy.BVV(0xFF, 8))
        self.state.memory.store(0xD370, claripy.BVV(0, 8))
        self.state.memory.store(0xD371, claripy.BVV(0, 8))
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x40, 8)
        self.jump(self.state.addr + 3)


class NativeLoadSpecialWarpData(angr.SimProcedure):
    def run(self, state_ptr, memory_ptr) -> None:  # type: ignore[override]
        base = self.state.solver.eval(memory_ptr)
        registers = self.state.solver.eval(state_ptr)
        values = (0x26, 0x12, 0xC7, 0x06, 0x03, 0x00, 0x01)
        for offset, value in enumerate(values):
            self.state.memory.store(base + W_CUR_MAP + offset, claripy.BVV(value, 8))
        self.state.memory.store(base + W_CUR_MAP_TILESET, claripy.BVV(0x04, 8))
        self.state.memory.store(base + 0xD42F, claripy.BVV(0xFF, 8))
        self.state.memory.store(base + 0xD370, claripy.BVV(0, 8))
        self.state.memory.store(base + 0xD371, claripy.BVV(0, 8))
        self.state.memory.store(registers + 0, claripy.BVV(0, 8))
        self.state.memory.store(registers + 1, claripy.BVV(0x80, 8))
        self.state.memory.store(registers + 20, claripy.BVV(0, 8))
        self.state.memory.store(registers + 21, claripy.BVV(0, 8))
        self.state.memory.store(registers + 22, claripy.BVV(0xFF, 8))


class NativeTilesetBoundary(angr.SimProcedure):
    def run(self, *args, **kwargs) -> None:  # type: ignore[override]
        return


class Noop(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__(); self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.jump(self.target)


class SetFlagsAndJump(angr.SimProcedure):
    def __init__(self, flags: int, target: int) -> None:
        super().__init__(); self.flags = flags; self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.f = claripy.BVV(self.flags, 8)
        self.jump(self.target)


class LoadConst(angr.SimProcedure):
    def __init__(self, value: int, target: int) -> None:
        super().__init__(); self.value = value; self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(self.value, 8)
        self.jump(self.target)


class LoadPairConst(angr.SimProcedure):
    def __init__(self, value: int, target: int) -> None:
        super().__init__(); self.value = value; self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = claripy.BVV(self.value >> 8, 8)
        self.state.regs.l = claripy.BVV(self.value & 0xff, 8)
        self.jump(self.target)


class LoadAFrom(angr.SimProcedure):
    def __init__(self, address: int, target: int) -> None:
        super().__init__(); self.address = address; self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self.address, 1)
        self.jump(self.target)


class MoveBtoA(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__(); self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.regs.b
        self.jump(self.target)


class LoadTilesetNoop(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x40, 8)
        self.jump(self.state.addr + 3)


class NativeNoop(angr.SimProcedure):
    def run(self, *args, **kwargs) -> None:  # type: ignore[override]
        return


class BitMemory(angr.SimProcedure):
    def __init__(self, address: int, bit: int, target: int) -> None:
        super().__init__(); self.address = address; self.bit = bit; self.target = target

    def run(self) -> None:  # type: ignore[override]
        value = self.state.memory.load(self.address, 1)
        carry = self.state.regs.f & 0x01
        self.state.regs.f = carry | 0x10 | claripy.If(
            (value & (1 << self.bit)) == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)
        )
        self.jump(self.target)


class ResMemory(angr.SimProcedure):
    def __init__(self, address: int, bit: int, target: int) -> None:
        super().__init__(); self.address = address; self.bit = bit; self.target = target

    def run(self) -> None:  # type: ignore[override]
        value = self.state.memory.load(self.address, 1)
        self.state.memory.store(self.address, value & ~(1 << self.bit))
        self.jump(self.target)


class BranchZ(angr.SimProcedure):
    def __init__(self, taken: int, fallthrough: int) -> None:
        super().__init__(); self.taken = taken; self.fallthrough = fallthrough

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        condition = (self.state.regs.f & 0x40) != 0
        self.successors.add_successor(self.state.copy(), self.taken, condition, "Ijk_Boring")
        self.successors.add_successor(self.state.copy(), self.fallthrough, ~condition, "Ijk_Boring")


class ReturnNZ(angr.SimProcedure):
    """Model the one-byte RET NZ while retaining the BIT flags."""

    def __init__(self, zero_target: int, return_target: int) -> None:
        super().__init__(); self.zero_target = zero_target; self.return_target = return_target

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        condition = (self.state.regs.f & 0x40) != 0
        self.successors.add_successor(self.state.copy(), self.zero_target, condition, "Ijk_Boring")
        self.successors.add_successor(self.state.copy(), self.return_target, ~condition, "Ijk_Ret")


class AndA(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__(); self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.f = 0x10 | claripy.If(
            self.state.regs.a == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)
        )
        self.jump(self.target)


class MoveAtoB(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__(); self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.b = self.state.regs.a
        self.jump(self.target)


def _setup(state: angr.SimState, base: int, status3: int, status6: int, destination: int) -> None:
    state.memory.store(base + W_STATUS_FLAGS3, claripy.BVV(status3, 8))
    state.memory.store(base + W_STATUS_FLAGS6, claripy.BVV(status6, 8))
    state.memory.store(base + W_DESTINATION_MAP, claripy.BVV(destination, 8))
    state.memory.store(base + W_LAST_MAP, claripy.BVV(0xAA, 8))
    state.memory.store(base + W_CUR_MAP, claripy.BVV(0x55, 8))
    state.memory.store(base + W_CUR_MAP_TILESET, claripy.BVV(0, 8))
    state.memory.store(base + W_CURRENT_BLOCK_PTR, claripy.BVV(0, 16), endness="Iend_LE")
    state.memory.store(base + 0xD42F, claripy.BVV(0, 8))
    state.memory.store(base + 0xD370, claripy.BVV(0x99, 8))
    state.memory.store(base + 0xD371, claripy.BVV(0x88, 8))


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(*(state.memory.load(base + address, 1) for address in (
        W_CUR_MAP, W_CURRENT_BLOCK_PTR, W_CUR_MAP_TILESET, W_LAST_MAP,
        W_STATUS_FLAGS3, W_STATUS_FLAGS6, 0xD370, 0xD371, 0xD42F,
    )))


def _endpoint(state: angr.SimState, *, native: bool, base: int) -> Endpoint:
    return Endpoint(
        **(native_registers(state, NATIVE_STATE) if native else assembly_registers(state)),
        memory=_memory(state, base), constraints=tuple(state.solver.constraints),
    )


def _assembly(values: dict[str, claripy.ast.BV], status3: int, status6: int, destination: int) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "PrepareForSpecialWarp")
    assert linked_bytes(ROM, location, 49) == bytes.fromhex(
        "cdff623e19cd6d3e2132d7cb56cb962805fa1ad71809cb4e2803cdea643e0047fa2dd7a72001782132d7cb66c0ea65d3c9"
    )
    q = location.address
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": q},
    )
    project.hook(q + 0x00, LoadSpecialWarpData(), length=3)
    project.hook(q + 0x03, LoadConst(0x19, q + 0x05), length=2)
    project.hook(q + 0x05, LoadTilesetNoop(), length=3)
    project.hook(q + 0x08, LoadPairConst(W_STATUS_FLAGS6, q + 0x0B), length=3)
    project.hook(q + 0x0B, BitMemory(W_STATUS_FLAGS6, 2, q + 0x0D), length=2)
    project.hook(q + 0x0D, ResMemory(W_STATUS_FLAGS6, 2, q + 0x0F), length=2)
    project.hook(q + 0x0F, BranchZ(q + 0x16, q + 0x11), length=2)
    project.hook(q + 0x11, LoadAFrom(W_DESTINATION_MAP, q + 0x14), length=3)
    project.hook(q + 0x14, Noop(q + 0x1F), length=2)
    project.hook(q + 0x16, BitMemory(W_STATUS_FLAGS6, 1, q + 0x18), length=2)
    project.hook(q + 0x18, BranchZ(q + 0x1D, q + 0x1A), length=2)
    project.hook(q + 0x1A, Noop(q + 0x1D), length=3)
    project.hook(q + 0x1D, LoadConst(0x00, q + 0x1F), length=2)
    project.hook(q + 0x1F, MoveAtoB(q + 0x20), length=1)
    project.hook(q + 0x20, LoadAFrom(W_STATUS_FLAGS3, q + 0x23), length=3)
    project.hook(q + 0x23, AndA(q + 0x25), length=1)
    project.hook(q + 0x25, BranchZ(q + 0x26, q + 0x27), length=2)
    project.hook(q + 0x26, MoveBtoA(q + 0x27), length=1)
    project.hook(q + 0x27, LoadPairConst(W_STATUS_FLAGS6, q + 0x2A), length=3)
    project.hook(q + 0x2A, BitMemory(W_STATUS_FLAGS6, 4, q + 0x2C), length=2)
    # RET NZ is split explicitly so both the wLastMap store and early return
    # preserve the flags produced by the preceding BIT instruction.
    project.hook(q + 0x2C, ReturnNZ(q + 0x2D, RETURN), length=1)
    project.hook(q + 0x2D, Sm83StoreAImmediate(W_LAST_MAP, q + 0x30), length=3)
    project.hook(q + 0x30, SetFlagsAndJump(0x50, RETURN), length=1)
    state = project.factory.blank_state(addr=q)
    set_assembly_registers(state, values)
    _setup(state, 0, status3, status6, destination)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN, num_find=4)
    assert not manager.errored and manager.found
    return [_endpoint(x, native=False, base=0) for x in manager.found]


def _native(values: dict[str, claripy.ast.BV], status3: int, status6: int, destination: int) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_prepare_for_special_warp")
    special = project.loader.find_symbol("port_load_special_warp_data")
    tileset = project.loader.find_symbol("port_load_tileset_header")
    assert function is not None and special is not None and tileset is not None
    project.hook(special.rebased_addr, NativeLoadSpecialWarpData())
    project.hook(tileset.rebased_addr, NativeTilesetBoundary())
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, NATIVE_MEMORY, status3, status6, destination)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [_endpoint(x, native=True, base=NATIVE_MEMORY) for x in manager.deadended]


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(), reason="build artifacts missing")
@pytest.mark.parametrize("status3", (0, 1, 0xFF))
@pytest.mark.parametrize("status6,destination", ((0, 0x42), (0x02, 0x42), (0x04, 0x42), (0x10, 0x42), (0x14, 0x42)))
def test_prepare_for_special_warp_pathwise_equivalence(status3: int, status6: int, destination: int) -> None:
    values = symbolic_registers("prepare_for_special_warp")
    assert_pathwise_equivalent(
        _assembly(values, status3, status6, destination), _native(values, status3, status6, destination),
        (*REGISTERS, "memory"),
    )
