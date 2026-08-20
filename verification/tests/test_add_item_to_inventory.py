from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import set_assembly_registers, store_native_registers, symbolic_registers
from verification.harness.rom import rom_window, symbol_location, sm83_flags_to_z80

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x110000
DONE = 0xEFFF
W_CUR_ITEM = 0xD05D
W_ITEM_QUANTITY = 0xD05E
INVENTORY = 0xD31E
MEMORY_FIELDS = ("count", "item", "quantity", "terminator", "item_quantity")


@dataclass(frozen=True)
class Endpoint:
    memory: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class NewSlotSummary(angr.SimProcedure):
    def run(self) -> None:
        item = self.state.globals["item"]
        quantity = self.state.globals["quantity"]
        self.state.memory.store(INVENTORY, claripy.BVV(1, 8))
        self.state.memory.store(INVENTORY + 1, item)
        self.state.memory.store(INVENTORY + 2, quantity)
        self.state.memory.store(INVENTORY + 3, claripy.BVV(0xFF, 8))
        self.state.memory.store(W_ITEM_QUANTITY, quantity)
        self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0x10, 8))
        self.jump(DONE)


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["item"] = claripy.BVS(f"{prefix}_item", 8)
    values["quantity"] = claripy.BVS(f"{prefix}_quantity", 8)
    values["count"] = claripy.BVV(0, 8)
    values["terminator"] = claripy.BVV(0xFF, 8)
    values["item_quantity"] = values["quantity"]
    values["h"] = claripy.BVV(INVENTORY >> 8, 8)
    values["l"] = claripy.BVV(INVENTORY & 0xFF, 8)
    return values


def _memory_endpoint(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        state.memory.load(base + INVENTORY, 1),
        state.memory.load(base + INVENTORY + 1, 1),
        state.memory.load(base + INVENTORY + 2, 1),
        state.memory.load(base + INVENTORY + 3, 1),
        state.memory.load(base + W_ITEM_QUANTITY, 1),
    )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "AddItemToInventory_")
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
    project.hook(location.address, NewSlotSummary(), length=1)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.memory.store(INVENTORY, values["count"])
    state.memory.store(INVENTORY + 1, values["terminator"])
    state.memory.store(W_ITEM_QUANTITY, values["item_quantity"])
    for key in ("item", "quantity"):
        state.globals[key] = values[key]
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored
    return [
        Endpoint(
            memory=_memory_endpoint(end, 0),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_add_item_to_inventory")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_MEMORY + INVENTORY, values["count"])
    state.memory.store(NATIVE_MEMORY + INVENTORY + 1, values["terminator"])
    state.memory.store(NATIVE_MEMORY + W_CUR_ITEM, values["item"])
    state.memory.store(NATIVE_MEMORY + W_ITEM_QUANTITY, values["item_quantity"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            memory=_memory_endpoint(end, NATIVE_MEMORY),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_add_item_to_inventory_pathwise_equivalence() -> None:
    values = _inputs("add_item_new_slot")
    assert_pathwise_equivalent(_assembly(values), _native(values), ("memory",))
