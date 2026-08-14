from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
    assembly_registers,
    native_registers,
    set_assembly_registers,
    store_native_registers,
    symbolic_registers,
)
from verification.harness.rom import (
    collect_returns,
    linked_bytes,
    rom_window,
    symbol_location,
)
from verification.harness.sm83_shims import (
    Sm83CpImmediate,
    Sm83CpRegister,
    Sm83LoadAAtHlIncrement,
)


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification" / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
GB_STACK = 0xD000
GB_RETURN = 0xFFFF
NATIVE_STATE = 0x100000
W_NUM_BAG_ITEMS = 0xD31D
BAG_SLOTS = 8


class SkipCall(angr.SimProcedure):
    """Replace a ``call`` with a direct jump to its return address so the
    callee's effect is skipped (used for ``GetPredefRegisters`` whose result
    is irrelevant: b passes through from the inputs and hl is overwritten)."""

    def __init__(self, next_address: int, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.jump(self._next_address)


@lru_cache(maxsize=None)
def _bag_bvs() -> tuple[tuple[claripy.ast.BV, ...], tuple[claripy.ast.BV, ...]]:
    """Symbolic wNumBagItems id/quantity bytes, shared between the assembly
    and native endpoints so path constraints refer to the same claripy vars."""
    ids = tuple(claripy.BVS(f"gqob_id{i}", 8) for i in range(BAG_SLOTS))
    qtys = tuple(claripy.BVS(f"gqob_qty{i}", 8) for i in range(BAG_SLOTS))
    return ids, qtys


def _store_bag(state: angr.SimState) -> None:
    """Make the wNumBagItems item table symbolic and force the final slot's
    id to the $ff terminator so the scan always terminates within the table."""
    ids, qtys = _bag_bvs()
    # count byte is never read by the scan
    state.memory.store(W_NUM_BAG_ITEMS, claripy.BVV(BAG_SLOTS, 8))
    for i in range(BAG_SLOTS):
        state.memory.store(W_NUM_BAG_ITEMS + 1 + 2 * i, ids[i])
        state.memory.store(W_NUM_BAG_ITEMS + 1 + 2 * i + 1, qtys[i])
    state.memory.store(
        W_NUM_BAG_ITEMS + 1 + 2 * (BAG_SLOTS - 1), claripy.BVV(0xFF, 8)
    )


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


def _assembly_endpoint(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "GetQuantityOfItemInBag")
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
    state = project.factory.blank_state(addr=location.address)
    base = location.address
    # 0x00: call GetPredefRegisters -> skipped (b passes through, hl overwritten)
    project.hook(base + 0x00, SkipCall(base + 0x03), length=3)
    # 0x07: ld a,[hli] mis-decoded by z80 pcode -> shim
    project.hook(base + 0x07, Sm83LoadAAtHlIncrement(base + 0x08), length=1)
    # 0x08: cp $ff -> shim for SM83 compare flags
    project.hook(base + 0x08, Sm83CpImmediate(0xFF, base + 0x0A), length=2)
    # 0x0C: cp b -> shim for SM83 compare flags
    project.hook(base + 0x0C, Sm83CpRegister("b", base + 0x0D), length=1)
    _store_bag(state)
    set_assembly_registers(state, inputs)
    state.regs.sp = claripy.BVV(GB_STACK, 16)
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    return [
        Endpoint(
            **assembly_registers(end),
            constraints=tuple(end.solver.constraints),
        )
        for end in returned
    ]


def _native_endpoint(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(
        "port_get_quantity_of_item_in_bag"
    )
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, claripy.BVV(0, 64)
    )
    store_native_registers(state, NATIVE_STATE, inputs)
    _store_bag(state)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_get_quantity_of_item_in_bag_symbolic_equivalence() -> None:
    inputs = symbolic_registers("gqob")
    assembly = _assembly_endpoint(inputs)
    native = _native_endpoint(inputs)
    assert_pathwise_equivalent(
        assembly,
        native,
        ("a", "f", "b", "c", "d", "e", "h", "l"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_get_quantity_of_item_in_bag_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "GetQuantityOfItemInBag")
    expected = bytes.fromhex("cd943e211dd3232afeff2806b820f77e47c90600c9")
    assert linked_bytes(ROM, location, len(expected)) == expected
