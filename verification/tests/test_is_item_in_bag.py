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
from verification.harness.rom import collect_returns, linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import (
    Sm83CpImmediate,
    Sm83CpRegister,
    Sm83LoadAAtHlIncrement,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xFFFF
W_NUM_BAG_ITEMS = 0xD31D
BAG_SLOTS = 8
EXPECTED_BODY = bytes.fromhex("3e1ccd6d3e78a7c9")


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
    bag: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class DirectCall(angr.SimProcedure):
    def __init__(self, target: int, continuation: int) -> None:
        super().__init__()
        self.target = target
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.sp -= 2
        self.state.memory.store(
            self.state.regs.sp,
            claripy.BVV(self.continuation, 16),
            endness="Iend_LE",
        )
        self.jump(self.target)


class SkipCall(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.jump(self.continuation)


class AndA(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.f = claripy.BVV(0x10, 8) | claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x40, 8),
            claripy.BVV(0, 8),
        )
        self.jump(self.continuation)


def _store_bag(
    state: angr.SimState, values: dict[str, claripy.ast.BV], base: int = 0
) -> None:
    state.memory.store(base + W_NUM_BAG_ITEMS, values["bag_count"])
    for index in range(BAG_SLOTS):
        item = (
            claripy.BVV(0xFF, 8)
            if index == BAG_SLOTS - 1
            else values[f"bag_id_{index}"]
        )
        state.memory.store(base + W_NUM_BAG_ITEMS + 1 + 2 * index, item)
        state.memory.store(
            base + W_NUM_BAG_ITEMS + 2 + 2 * index,
            values[f"bag_quantity_{index}"],
        )


def _bag(state: angr.SimState, base: int = 0) -> claripy.ast.BV:
    return state.memory.load(base + W_NUM_BAG_ITEMS, 1 + 2 * BAG_SLOTS)


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "IsItemInBag")
    callee = symbol_location(SYMBOLS, "GetQuantityOfItemInBag")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY
    project = angr.Project(
        rom_window(ROM, callee.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": location.address,
        },
    )
    base = location.address
    project.hook(base + 2, DirectCall(callee.address, base + 5), length=3)
    project.hook(base + 6, AndA(base + 7), length=1)
    project.hook(callee.address, SkipCall(callee.address + 3), length=3)
    project.hook(
        callee.address + 7,
        Sm83LoadAAtHlIncrement(callee.address + 8),
        length=1,
    )
    project.hook(
        callee.address + 8,
        Sm83CpImmediate(0xFF, callee.address + 10),
        length=2,
    )
    project.hook(
        callee.address + 12,
        Sm83CpRegister("b", callee.address + 13),
        length=1,
    )
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _store_bag(state, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    return [
        Endpoint(
            **assembly_registers(end),
            bag=_bag(end),
            constraints=tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, RETURN)
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_is_item_in_bag")
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    _store_bag(state, values, NATIVE_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            bag=_bag(end, NATIVE_MEMORY),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_is_item_in_bag_pathwise_equivalence() -> None:
    values = symbolic_registers("is_item_in_bag")
    values["bag_count"] = claripy.BVS("bag_count", 8)
    for index in range(BAG_SLOTS):
        values[f"bag_id_{index}"] = claripy.BVS(f"bag_id_{index}", 8)
        values[f"bag_quantity_{index}"] = claripy.BVS(
            f"bag_quantity_{index}", 8
        )
    assert_pathwise_equivalent(
        _assembly(values), _native(values), (*REGISTERS, "bag")
    )
