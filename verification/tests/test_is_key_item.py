from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import symbolic_registers
from verification.harness.rom import rom_window, symbol_location

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x110000
DONE = 0xEFFF
W_CUR_ITEM = 0xCF91
W_IS_KEY_ITEM = 0xD124
KEY_ITEM_FLAGS = 0x6799
HM01 = 0xC4
TM01 = 0xC9


@dataclass(frozen=True)
class Endpoint:
    key_item: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class KeyItemSummary(angr.SimProcedure):
    def run(self) -> None:
        item = self.state.globals["cur_item"]
        table_result: claripy.ast.BV = claripy.BVV(0, 8)
        for item_value in range(1, 0x79):
            table_byte = self.state.globals[f"key_flags_{(item_value - 1) >> 3}"]
            bit = 1 << ((item_value - 1) & 7)
            result = claripy.If(
                (table_byte & bit) != 0,
                claripy.BVV(1, 8),
                claripy.BVV(0, 8),
            )
            table_result = claripy.If(item == item_value, result, table_result)
        key_result = claripy.If(
            item < HM01,
            table_result,
            claripy.If(item < TM01, claripy.BVV(1, 8), claripy.BVV(0, 8)),
        )
        self.state.globals["is_key_item"] = key_result
        self.state.add_constraints(
            claripy.Or(item < 0x79, item >= HM01), item != 0
        )
        self.jump(DONE)


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["cur_item"] = claripy.BVS(f"{prefix}_cur_item", 8)
    values["is_key_item"] = claripy.BVS(f"{prefix}_is_key_item", 8)
    for index in range(15):
        values[f"key_flags_{index}"] = claripy.BVS(f"{prefix}_key_flags_{index}", 8)
    return values


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "IsKeyItem_")
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
    project.hook(location.address, KeyItemSummary(), length=1)
    state = project.factory.blank_state(addr=location.address)
    for key, value in values.items():
        if key in {"cur_item", "is_key_item"} or key.startswith("key_flags_"):
            state.globals[key] = value
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored
    return [
        Endpoint(
            key_item=end.globals["is_key_item"],
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_is_key_item_")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    state.memory.store(NATIVE_MEMORY + W_CUR_ITEM, values["cur_item"])
    state.memory.store(NATIVE_MEMORY + W_IS_KEY_ITEM, values["is_key_item"])
    for index in range(15):
        state.memory.store(
            NATIVE_MEMORY + KEY_ITEM_FLAGS + index,
            values[f"key_flags_{index}"],
        )
    state.add_constraints(
        claripy.Or(values["cur_item"] < 0x79, values["cur_item"] >= HM01),
        values["cur_item"] != 0,
    )
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            key_item=end.memory.load(NATIVE_MEMORY + W_IS_KEY_ITEM, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_is_key_item_pathwise_equivalence() -> None:
    values = _inputs("is_key_item")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        ("key_item",),
    )
