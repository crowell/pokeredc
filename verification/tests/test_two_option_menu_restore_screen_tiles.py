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
from verification.harness.sm83_shims import Sm83AddHlRegisterPair, Sm83DecRegister

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xEFFF
W_BUFFER = 0xCEE9
W_UPDATE_SPRITES_ENABLED = 0xCFCB
DESTINATION = 0xC3A0
COPY_LENGTH = 30


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


class RestoreFetch(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__()
        self.target = target

    def run(self) -> None:
        de = self.state.regs.de
        self.state.regs.a = self.state.memory.load(de, 1)
        self.jump(self.target)


class IncrementDE(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__()
        self.target = target

    def run(self) -> None:
        self.state.regs.de = self.state.regs.de + 1
        self.jump(self.target)


class StoreHLI(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__()
        self.target = target

    def run(self) -> None:
        hl = self.state.regs.hl
        self.state.memory.store(hl, self.state.regs.a)
        self.state.regs.hl = hl + 1
        self.jump(self.target)


class UpdateSpritesEarlyReturn(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__()
        self.target = target

    def run(self) -> None:
        before = self.state.memory.load(W_UPDATE_SPRITES_ENABLED, 1)
        value = before - 1
        self.state.regs.a = value
        flags = (self.state.regs.f & claripy.BVV(0x01, 8)) | claripy.BVV(0x02, 8)
        flags |= claripy.If(value == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        flags |= claripy.If(
            (before & 0x0F) == 0,
            claripy.BVV(0x10, 8),
            claripy.BVV(0, 8),
        )
        self.state.regs.f = flags
        self.jump(self.target)


def _inputs() -> dict[str, claripy.ast.BV]:
    values = symbolic_registers("restore")
    values["h"] = claripy.BVV(DESTINATION >> 8, 8)
    values["l"] = claripy.BVV(DESTINATION & 0xFF, 8)
    for i in range(COPY_LENGTH):
        values[f"source_{i}"] = claripy.BVS(f"restore_source_{i}", 8)
        values[f"destination_{i}"] = claripy.BVS(f"restore_destination_{i}", 8)
    return values


def _setup_assembly(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    set_assembly_registers(state, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    for i in range(COPY_LENGTH):
        state.memory.store(W_BUFFER + i, values[f"source_{i}"])
        state.memory.store(DESTINATION + i, values[f"destination_{i}"])
    state.memory.store(W_UPDATE_SPRITES_ENABLED, claripy.BVV(2, 8))


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        *[state.memory.load(base + W_BUFFER + i, 1) for i in range(COPY_LENGTH)],
        *[state.memory.load(base + DESTINATION + i, 1) for i in range(COPY_LENGTH)],
        state.memory.load(base + W_UPDATE_SPRITES_ENABLED, 1),
    )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "TwoOptionMenu_RestoreScreenTiles")
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
    q = location.address
    project.hook(q + 6, RestoreFetch(q + 7), length=1)
    project.hook(q + 7, IncrementDE(q + 8), length=1)
    project.hook(q + 8, StoreHLI(q + 9), length=1)
    project.hook(q + 9, Sm83DecRegister("c", q + 10), length=1)
    project.hook(q + 16, Sm83AddHlRegisterPair("bc", q + 17), length=1)
    project.hook(q + 20, Sm83DecRegister("b", q + 21), length=1)
    project.hook(q + 23, UpdateSpritesEarlyReturn(q + 26), length=3)
    state = project.factory.blank_state(addr=q)
    _setup_assembly(state, values)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN)
    assert not manager.errored and manager.found
    return [
        Endpoint(**assembly_registers(end), memory=_memory(end, 0), constraints=tuple(end.solver.constraints))
        for end in manager.found
    ]


def _setup_native(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    store_native_registers(state, NATIVE_STATE, values)
    for i in range(COPY_LENGTH):
        state.memory.store(NATIVE_MEMORY + W_BUFFER + i, values[f"source_{i}"])
        state.memory.store(NATIVE_MEMORY + DESTINATION + i, values[f"destination_{i}"])
    state.memory.store(NATIVE_MEMORY + W_UPDATE_SPRITES_ENABLED, claripy.BVV(2, 8))


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_two_option_menu_restore_screen_tiles")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    _setup_native(state, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    end = manager.deadended[0]
    return [
        Endpoint(**native_registers(end, NATIVE_STATE), memory=_memory(end, NATIVE_MEMORY), constraints=tuple(end.solver.constraints))
    ]


@pytest.mark.skipif(
    not NATIVE_ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),
    reason="build artifacts missing",
)
def test_restore_screen_tiles_pathwise_equivalence() -> None:
    values = _inputs()
    location = symbol_location(SYMBOLS, "TwoOptionMenu_RestoreScreenTiles")
    assert linked_bytes(ROM, location, 27) == bytes.fromhex(
        "11e9ce0106051a13220d20fac5010e0009c10e060520efcd2924c9"
    )
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "memory"),
    )
