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
from verification.harness.sm83_shims import Sm83StoreAHighImmediate

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
DONE = 0xEFFF
H_BASE_TILE_ID = 0xFF8B


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
    base_tile: claripy.ast.BV
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


class SkipPredefRegisters(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(self.state.addr + 3)


class Boundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.successors.add_successor(
            self.state.copy(), DONE, claripy.BoolV(True), "Ijk_Boring"
        )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "CopyTileIDsFromList")
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
    project.hook(location.address, SkipPredefRegisters(), length=3)
    project.hook(
        location.address + 3,
        CopyRegisterPreserveFlags("c", "a", location.address + 4),
        length=1,
    )
    project.hook(
        location.address + 4,
        Sm83StoreAHighImmediate(0x8B, location.address + 6),
        length=2,
    )
    project.hook(
        location.address + 6,
        CopyRegisterPreserveFlags("b", "a", location.address + 7),
        length=1,
    )
    project.hook(location.address + 8, Boundary(), length=3)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored
    return [
        Endpoint(
            **assembly_registers(end),
            base_tile=end.memory.load(H_BASE_TILE_ID, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_copy_tile_ids_from_list")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            base_tile=end.memory.load(NATIVE_STATE + 8, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_copy_tile_ids_from_list_setup_pathwise_equivalence() -> None:
    values = symbolic_registers("copy_tile_ids_from_list")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "base_tile"),
    )
