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
    Sm83BitRegister,
    Sm83CpImmediate,
    Sm83CpRegister,
    Sm83LoadAImmediate,
    Sm83Scf,
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
W_Y_COORD = 0xD361
W_X_COORD = 0xD362
W_SPRITE_SET = 0xD39D
W_SPRITE_SET_ID = 0xD3A8
W_NUM_SPRITES = 0xD4E1
W_FONT_LOADED = 0xCFC4
DATA1 = 0xC100
DATA2 = 0xC200
DATA2_BYTES = 0x100


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
    sprite_set: claripy.ast.BV
    sprite_set_id: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class LoadAAtHL(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self.state.regs.hl, 1)
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
        )  # Z80-layout Z for AND A
        self.jump(self.next_address)


class Jump(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.jump(self.next_address)


class Branch(angr.SimProcedure):
    def __init__(self, flag_bit: int, taken: int, fallthrough: int, invert: bool) -> None:
        super().__init__()
        self.flag_bit = flag_bit
        self.taken = taken
        self.fallthrough = fallthrough
        self.invert = invert

    def run(self) -> None:  # type: ignore[override]
        bit = (self.state.regs.f >> self.flag_bit) & 1
        condition = bit == (0 if self.invert else 1)
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


class PushHL(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        sp = int(self.state.solver.eval(self.state.regs.sp))
        self.state.memory.store(sp - 2, self.state.regs.hl, endness="Iend_LE")
        self.state.regs.sp = claripy.BVV(sp - 2, 16)
        self.jump(self.next_address)


class PopHL(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        sp = int(self.state.solver.eval(self.state.regs.sp))
        self.state.regs.hl = self.state.memory.load(sp, 2, endness="Iend_LE")
        self.state.regs.sp = claripy.BVV(sp + 2, 16)
        self.jump(self.next_address)


def _values() -> dict[str, claripy.ast.BV]:
    values = symbolic_registers("init_outside")
    values["data2"] = claripy.BVS("init_outside_data2", DATA2_BYTES * 8)
    values["sprite_set"] = claripy.BVS("init_outside_sprite_set", 11 * 8)
    values["sprite_set_id"] = claripy.BVV(1, 8)
    return values


def _seed(state: angr.SimState, base: int, values: dict[str, claripy.ast.BV]) -> None:
    state.memory.store(base + W_CUR_MAP, claripy.BVV(0, 8))
    state.memory.store(base + W_Y_COORD, claripy.BVV(0, 8))
    state.memory.store(base + W_X_COORD, claripy.BVV(0, 8))
    state.memory.store(base + W_SPRITE_SET_ID, values["sprite_set_id"])
    state.memory.store(base + W_FONT_LOADED, claripy.BVV(0, 8))
    state.memory.store(base + W_NUM_SPRITES, claripy.BVV(0, 8))
    state.memory.store(base + DATA1, claripy.BVV(0, 0x100 * 8))
    state.memory.store(base + DATA2, values["data2"])
    state.memory.store(base + W_SPRITE_SET, values["sprite_set"])


def _endpoint(state: angr.SimState, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    return Endpoint(
        **(native_registers(state, NATIVE_STATE) if native else assembly_registers(state)),
        data1=state.memory.load(base + DATA1, 0x100),
        data2=state.memory.load(base + DATA2, DATA2_BYTES),
        sprite_set=state.memory.load(base + W_SPRITE_SET, 11),
        sprite_set_id=state.memory.load(base + W_SPRITE_SET_ID, 1),
        constraints=tuple(state.solver.constraints),
    )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "InitOutsideMapSprites")
    base = location.address
    assert linked_bytes(ROM, location, 6) == bytes.fromhex("fa5ed3fe25d0")
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
    project.hook(base, Sm83LoadAImmediate(W_CUR_MAP, base + 3), length=3)
    project.hook(base + 3, Sm83CpImmediate(0x25, base + 5), length=2)
    project.hook(base + 5, Jump(base + 6), length=1)
    project.hook(base + 9, Sm83AddRegister("l", base + 10), length=1)
    project.hook(base + 0x0E, LoadAAtHL(base + 0x0F), length=1)
    project.hook(base + 0x0F, Sm83CpImmediate(0xF0, base + 0x11), length=2)
    project.hook(base + 0x11, Jump(base + 0x14), length=3)
    project.hook(base + 0x15, Sm83LoadAImmediate(W_FONT_LOADED, base + 0x18), length=3)
    project.hook(base + 0x18, Sm83BitRegister(0, "a", base + 0x1A), length=2)
    project.hook(base + 0x1A, Jump(base + 0x1C), length=2)
    project.hook(base + 0x1C, Sm83LoadAImmediate(W_SPRITE_SET_ID, base + 0x1F), length=3)
    project.hook(base + 0x1F, Sm83CpRegister("b", base + 0x20), length=1)
    project.hook(base + 0x20, Jump(base + 0x79), length=2)
    project.hook(base + 0x7E, LoadAAtHL(base + 0x7F), length=1)
    project.hook(base + 0x7F, AndA(base + 0x80), length=1)
    project.hook(base + 0x80, Jump(base + 0x8D), length=2)
    project.hook(base + 0x8D, PushHL(base + 0x8E), length=1)
    project.hook(base + 0x95, PopHL(base + 0x96), length=1)
    project.hook(base + 0x9A, AndA(base + 0x9B), length=1)
    project.hook(base + 0x9B, Branch(6, base + 0x7C, base + 0x9D, True), length=2)
    project.hook(base + 0x9D, Sm83Scf(base + 0x9E), length=1)

    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _seed(state, 0, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    manager = project.factory.simulation_manager(state)
    manager.explore(find=lambda candidate: candidate.addr == RETURN)
    assert not manager.errored
    assert len(manager.found) == 1
    return [_endpoint(manager.found[0], native=False)]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_init_outside_map_sprites")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _seed(state, NATIVE_MEMORY, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    return [_endpoint(manager.deadended[0], native=True)]


@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_init_outside_map_sprites_pathwise_equivalence() -> None:
    values = _values()
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "data1", "data2", "sprite_set", "sprite_set_id"),
    )
