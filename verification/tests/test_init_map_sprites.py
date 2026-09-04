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
    Sm83AddRegister,
    Sm83LoadAImmediate,
)


ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xFFFF
W_CUR_MAP = 0xD35E
W_NUM_SPRITES = 0xD4E1
W_SPRITE_SET_ID = 0xD3A8
W_FONT_LOADED = 0xCFC4
W_SPRITE_SET = 0xD39D
DATA1 = 0xC100
DATA2 = 0xC200
DATA_BYTES = 0x100


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
    data1: claripy.ast.BV
    data2: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class OutsideBoundary(angr.SimProcedure):
    def __init__(self, next_address: int, *, outdoor: bool) -> None:
        super().__init__()
        self.next_address = next_address
        self.outdoor = outdoor

    def run(self) -> None:  # type: ignore[override]
        if self.outdoor:
            # Proven InitOutsideMapSprites map-0 transition: the matching
            # sprite set leaves each unused slot's image index at zero,
            # preserves B=1, and returns with carry set.
            for index in range(1, 16):
                self.state.memory.store(
                    DATA2 + 0x0E + index * 0x10,
                    claripy.BVV(0, 8),
                )
            self.state.regs.a = claripy.BVV(0, 8)
            self.state.regs.f = claripy.BVV(0x41, 8)  # Z80-layout Z|carry
            self.state.regs.b = claripy.BVV(1, 8)
            self.state.regs.c = claripy.BVV(0, 8)
            self.state.regs.h = claripy.BVV(0xC1, 8)
            self.state.regs.l = claripy.BVV(0, 8)
        else:
            # Indoor map: InitOutsideMapSprites returns with carry clear and
            # InitMapSprites performs the picture-ID copy below.
            self.state.regs.f = claripy.BVV(0, 8)
        self.jump(self.next_address)


class RetCStack(angr.SimProcedure):
    """Model InitMapSprites' conditional return after InitOutsideMapSprites."""

    def __init__(self, fallthrough: int) -> None:
        super().__init__()
        self.fallthrough = fallthrough

    def run(self) -> None:  # type: ignore[override]
        condition = (self.state.regs.f & 1) != 0
        sp = self.state.solver.eval(self.state.regs.sp)
        lo = self.state.memory.load(sp, 1)
        hi = self.state.memory.load(sp + 1, 1)
        taken = self.state.copy()
        fallthrough = self.state.copy()
        taken.solver.add(condition)
        fallthrough.solver.add(claripy.Not(condition))
        taken.regs.sp = claripy.BVV(sp + 2, 16)
        taken.regs.ip = claripy.Concat(hi, lo)
        fallthrough.regs.ip = claripy.BVV(self.fallthrough, 16)
        self.inhibit_autoret = True
        self.successors.add_successor(taken, taken.regs.ip, condition, "Ijk_Boring")
        self.successors.add_successor(
            fallthrough,
            self.fallthrough,
            claripy.Not(condition),
            "Ijk_Boring",
        )


class Jump(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.jump(self.next_address)


class StoreAAtDE(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        address = claripy.Concat(self.state.regs.d, self.state.regs.e)
        self.state.memory.store(address, self.state.regs.a)
        self.jump(self.next_address)


class LoadConst(angr.SimProcedure):
    def __init__(self, value: int, next_address: int) -> None:
        super().__init__()
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(self.value, 8)
        self.jump(self.next_address)


class LoadPairConst(angr.SimProcedure):
    def __init__(self, high: str, low: str, value: int, next_address: int) -> None:
        super().__init__()
        self.high = high
        self.low = low
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.high, claripy.BVV(self.value >> 8, 8))
        setattr(self.state.regs, self.low, claripy.BVV(self.value & 0xFF, 8))
        self.jump(self.next_address)


class MoveA(angr.SimProcedure):
    def __init__(self, register: str, next_address: int) -> None:
        super().__init__()
        self.register = register
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.register, self.state.regs.a)
        self.jump(self.next_address)


class LoadAAtHL(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        address = claripy.Concat(self.state.regs.h, self.state.regs.l)
        self.state.regs.a = self.state.memory.load(address, 1)
        self.jump(self.next_address)


class AndA(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x40, 8),
            claripy.BVV(0, 8),
        )
        self.jump(self.next_address)


class BranchNZ(angr.SimProcedure):
    def __init__(self, taken: int, fallthrough: int) -> None:
        super().__init__()
        self.taken = taken
        self.fallthrough = fallthrough

    def run(self) -> None:  # type: ignore[override]
        condition = (self.state.regs.f & 0x40) == 0
        taken = self.state.copy()
        fallthrough = self.state.copy()
        taken.solver.add(condition)
        fallthrough.solver.add(claripy.Not(condition))
        taken.regs.ip = claripy.BVV(self.taken, 16)
        fallthrough.regs.ip = claripy.BVV(self.fallthrough, 16)
        self.inhibit_autoret = True
        self.successors.add_successor(taken, self.taken, condition, "Ijk_Boring")
        self.successors.add_successor(
            fallthrough, self.fallthrough, claripy.Not(condition), "Ijk_Boring"
        )


def _values() -> dict[str, claripy.ast.BV]:
    values = symbolic_registers("init_map_sprites")
    values["data1"] = claripy.BVS("init_map_sprites_data1", DATA_BYTES * 8)
    values["data2"] = claripy.BVS("init_map_sprites_data2", DATA_BYTES * 8)
    return values


def _seed(state: angr.SimState, base: int, values: dict[str, claripy.ast.BV],
          cur_map: int) -> None:
    state.memory.store(base + W_CUR_MAP, claripy.BVV(cur_map, 8))
    state.memory.store(base + W_NUM_SPRITES, claripy.BVV(0, 8))
    state.memory.store(base + W_SPRITE_SET_ID, claripy.BVV(1, 8))
    state.memory.store(base + W_FONT_LOADED, claripy.BVV(0, 8))
    for index, value in enumerate((1, 1, 2, 2, 3, 4, 5, 0x0A, 1, 6, 7)):
        state.memory.store(base + W_SPRITE_SET + index, claripy.BVV(value, 8))
    state.memory.store(base + DATA1, values["data1"])
    state.memory.store(base + DATA2, values["data2"])


def _endpoint(state: angr.SimState, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    return Endpoint(
        **(native_registers(state, NATIVE_STATE) if native else assembly_registers(state)),
        data1=state.memory.load(base + DATA1, DATA_BYTES),
        data2=state.memory.load(base + DATA2, DATA_BYTES),
        constraints=tuple(state.solver.constraints),
    )


def _assembly(values: dict[str, claripy.ast.BV], *, cur_map: int) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "InitMapSprites")
    base = location.address
    assert linked_bytes(ROM, location, 0x1D) == bytes.fromhex(
        "cd7b79d82100c1110dc27e123e10835f3e10856f20f4fae1d4a72001c9"
    )
    project = angr.Project(
        rom_window(ROM, location.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": base,
        },
    )
    project.hook(base, OutsideBoundary(base + 3, outdoor=cur_map == 0), length=3)
    project.hook(base + 3, RetCStack(base + 4), length=1)
    project.hook(base + 4, LoadPairConst("h", "l", 0xC100, base + 7), length=3)
    project.hook(base + 7, LoadPairConst("d", "e", 0xC20D, base + 0x0A), length=3)
    project.hook(base + 0x0A, LoadAAtHL(base + 0x0B), length=1)
    project.hook(base + 0x0B, StoreAAtDE(base + 0x0C), length=1)
    project.hook(base + 0x0C, LoadConst(0x10, base + 0x0E), length=2)
    project.hook(base + 0x0E, Sm83AddRegister("e", base + 0x0F), length=1)
    project.hook(base + 0x0F, MoveA("e", base + 0x10), length=1)
    project.hook(base + 0x10, LoadConst(0x10, base + 0x12), length=2)
    project.hook(base + 0x12, Sm83AddRegister("l", base + 0x13), length=1)
    project.hook(base + 0x13, MoveA("l", base + 0x14), length=1)
    project.hook(base + 0x14, BranchNZ(base + 0x0A, base + 0x16), length=2)
    project.hook(base + 0x16, Sm83LoadAImmediate(W_NUM_SPRITES, base + 0x19), length=3)
    project.hook(base + 0x19, AndA(base + 0x1A), length=1)
    project.hook(base + 0x1A, Jump(base + 0x1C), length=2)

    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _seed(state, 0, values, cur_map)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    manager = project.factory.simulation_manager(state)
    manager.explore(find=lambda candidate: candidate.addr == RETURN)
    assert not manager.errored
    assert len(manager.found) == 1
    return [_endpoint(manager.found[0], native=False)]


def _native(values: dict[str, claripy.ast.BV], *, cur_map: int) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_init_map_sprites")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _seed(state, NATIVE_MEMORY, values, cur_map)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    return [_endpoint(manager.deadended[0], native=True)]


@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_init_map_sprites_pathwise_equivalence() -> None:
    values = _values()
    assert_pathwise_equivalent(
        _assembly(values, cur_map=0x25),
        _native(values, cur_map=0x25),
        (*REGISTERS, "data1", "data2"),
    )


@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_init_map_sprites_outdoor_return_pathwise_equivalence() -> None:
    values = _values()
    values["data1"] = claripy.BVV(0, DATA_BYTES * 8)
    assert_pathwise_equivalent(
        _assembly(values, cur_map=0),
        _native(values, cur_map=0),
        (*REGISTERS, "data1", "data2"),
    )
