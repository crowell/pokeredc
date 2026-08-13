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
    Sm83OrRegister,
    Sm83RrRegister,
    Sm83SrlRegister,
)


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
BOUNDARY = 0xEFFF


class XorA(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = 0
        self.state.regs.f = 0x40
        self.jump(self._next_address)


class Boundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(BOUNDARY)


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
    constraints: tuple[claripy.ast.Bool, ...]


def assembly(inputs: dict[str, claripy.ast.BV]) -> Endpoint:
    location = symbol_location(SYMBOLS, "GetRowColAddressBgMap")
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
    address = location.address
    project.hook(address, XorA(address + 1), length=1)
    address += 1
    for _ in range(3):
        project.hook(address, Sm83SrlRegister("h", address + 2), length=2)
        project.hook(address + 2, Sm83RrRegister("a", address + 4), length=2)
        address += 4
    project.hook(address, Sm83OrRegister("l", address + 1), length=1)
    project.hook(address + 3, Sm83OrRegister("h", address + 4), length=1)
    project.hook(address + 5, Boundary(), length=1)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=BOUNDARY)
    assert not manager.errored
    assert len(manager.found) == 1
    end = manager.found[0]
    return Endpoint(
        **assembly_registers(end), constraints=tuple(end.solver.constraints)
    )


def native(inputs: dict[str, claripy.ast.BV]) -> Endpoint:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_get_row_col_address_bg_map")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    end = manager.deadended[0]
    return Endpoint(
        **native_registers(end, NATIVE_STATE),
        constraints=tuple(end.solver.constraints),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native port not built")
def test_symbolic_equivalence() -> None:
    inputs = symbolic_registers("get_row_col_address_bg_map")
    assert_pathwise_equivalent(
        [assembly(inputs)], [native(inputs)], REGISTERS
    )


def test_exact_body() -> None:
    location = symbol_location(SYMBOLS, "GetRowColAddressBgMap")
    assert linked_bytes(ROM, location, 19) == bytes.fromhex(
        "afcb3ccb1fcb3ccb1fcb3ccb1fb56f78b467c9"
    )
