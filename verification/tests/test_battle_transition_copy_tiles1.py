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
from verification.harness.rom import rom_window, symbol_location
from verification.harness.sm83_shims import Sm83StoreAImmediate

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
DONE = 0xEFFF
OFFSET_LOW = 0xCD3D
OFFSET_HIGH = 0xCD3E


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
    offset_low: claripy.ast.BV
    offset_high: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class CopyRegisterPreserveFlags(angr.SimProcedure):
    def __init__(self, source: str, target: str, next_address: int) -> None:
        super().__init__()
        self._source = source
        self._target = target
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self._target, getattr(self.state.regs, self._source))
        self.jump(self._next_address)

class LoadC8(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.c = claripy.BVV(8, 8)
        self.jump(self.state.addr + 2)


class CopySetup(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.b = claripy.BVV(0, 8)
        self.state.regs.c = claripy.BVV(20, 8)
        self.jump(self.state.addr + 6)


class Boundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.successors.add_successor(
            self.state.copy(), DONE, claripy.BoolV(True), "Ijk_Boring"
        )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "BattleTransition_CopyTiles1")
    base = location.address
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
    project.hook(base, CopyRegisterPreserveFlags("c", "a", base + 1), length=1)
    project.hook(base + 1, Sm83StoreAImmediate(OFFSET_LOW, base + 4), length=3)
    project.hook(base + 4, CopyRegisterPreserveFlags("b", "a", base + 5), length=1)
    project.hook(base + 5, Sm83StoreAImmediate(OFFSET_HIGH, base + 8), length=3)
    project.hook(base + 8, LoadC8(), length=2)
    project.hook(base + 10, CopySetup(), length=6)
    project.hook(base + 16, Boundary(), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.memory.store(OFFSET_LOW, values["offset_low"])
    state.memory.store(OFFSET_HIGH, values["offset_high"])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored
    return [
        Endpoint(
            **assembly_registers(end),
            offset_low=end.memory.load(OFFSET_LOW, 1),
            offset_high=end.memory.load(OFFSET_HIGH, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_battle_transition_copy_tiles1")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, values["offset_low"])
    state.memory.store(NATIVE_STATE + 9, values["offset_high"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            offset_low=end.memory.load(NATIVE_STATE + 8, 1),
            offset_high=end.memory.load(NATIVE_STATE + 9, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_battle_transition_copy_tiles1_setup_pathwise_equivalence() -> None:
    values = symbolic_registers("battle_transition_copy_tiles1")
    values["offset_low"] = claripy.BVS("battle_transition_copy_tiles1_offset_low", 8)
    values["offset_high"] = claripy.BVS("battle_transition_copy_tiles1_offset_high", 8)
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "offset_low", "offset_high"),
    )
