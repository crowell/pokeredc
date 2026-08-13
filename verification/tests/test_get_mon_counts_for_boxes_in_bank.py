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


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
BOUNDARY = 0xEFFF


class Fetch(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals["fetched"]
        self.jump(self._next_address)


class StoreIncrement(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.globals["written"] = self.state.regs.a
        self.state.regs.hl = self.state.regs.hl + 1
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
    fetched: claripy.ast.BV
    written: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["fetched"] = claripy.BVS(f"{prefix}_fetched", 8)
    values["written"] = claripy.BVS(f"{prefix}_written", 8)
    return values


def assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "GetMonCountsForBoxesInBank")
    loaded = angr.Project(
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
    loaded.hook(location.address, Fetch(location.address + 3), length=3)
    loaded.hook(location.address + 3, StoreIncrement(), length=1)
    state = loaded.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.globals["fetched"] = values["fetched"]
    state.globals["written"] = values["written"]
    manager = loaded.factory.simulation_manager(state)
    manager.explore(find=BOUNDARY)
    assert not manager.errored and len(manager.found) == 1
    end = manager.found[0]
    return [
        Endpoint(
            **assembly_registers(end),
            fetched=values["fetched"],
            written=end.globals["written"],
            constraints=tuple(end.solver.constraints),
        )
    ]


def native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    loaded = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = loaded.loader.find_symbol(
        "port_get_mon_counts_for_boxes_in_bank_step"
    )
    assert function is not None
    state = loaded.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, values["fetched"])
    state.memory.store(NATIVE_STATE + 9, values["written"])
    manager = loaded.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            fetched=end.memory.load(NATIVE_STATE + 8, 1),
            written=end.memory.load(NATIVE_STATE + 9, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native port not built")
def test_copy_step_equivalence() -> None:
    values = inputs("get_mon_counts_for_boxes_in_bank")
    assert_pathwise_equivalent(
        assembly(values),
        native(values),
        (*REGISTERS, "fetched", "written"),
    )


def test_exact_body() -> None:
    location = symbol_location(SYMBOLS, "GetMonCountsForBoxesInBank")
    assert linked_bytes(ROM, location, 25) == bytes.fromhex(
        "fa00a022fa62a422fac4a822fa26ad22fa88b122faeab522c9"
    )
