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
from verification.harness.rom import (
    linked_bytes,
    rom_window,
    sm83_flags_to_z80,
    symbol_location,
)
from verification.harness.sm83_shims import (
    Sm83CpImmediate,
    Sm83IncRegister,
    Sm83LoadAAtHlIncrement,
    Sm83StoreAImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xFFFF
DONE = 0xEFFF

W_NUM_BAG_ITEMS = 0xD31D
W_BAG_ITEMS = 0xD31E
W_WHICH_POKEMON = 0xCF92
W_ITEM_QUANTITY = 0xCF96
BAG_CAPACITY = 20
TABLE_SIZE = 2 + BAG_CAPACITY * 2
OAKS_PARCEL = 0x46
BODY = bytes.fromhex(
    "211ed30100002afeffc8fe462804230c18f4211dd379ea92cf"
    "3e01ea96cfc3bb2b"
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
    memory: claripy.ast.BV
    call: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class LoadPair(angr.SimProcedure):
    def __init__(self, high: str, low: str, value: int, next_address: int) -> None:
        super().__init__()
        self.high = high
        self.low = low
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.high, claripy.BVV(self.value >> 8, 8))
        setattr(self.state.regs, self.low, claripy.BVV(self.value & 0xFF, 8))
        self.jump(self.next_address)


class CopyRegister(angr.SimProcedure):
    def __init__(self, destination: str, source: str, next_address: int) -> None:
        super().__init__()
        self.destination = destination
        self.source = source
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.destination, getattr(self.state.regs, self.source))
        self.jump(self.next_address)


class LoadImmediate(angr.SimProcedure):
    def __init__(self, register: str, value: int, next_address: int) -> None:
        super().__init__()
        self.register = register
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.register, claripy.BVV(self.value, 8))
        self.jump(self.next_address)


class IncHL(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.hl += 1
        self.jump(self.next_address)


class BranchZ(angr.SimProcedure):
    def __init__(self, taken: int, fallthrough: int, returns: bool = False) -> None:
        super().__init__()
        self.taken = taken
        self.fallthrough = fallthrough
        self.returns = returns

    def run(self) -> None:  # type: ignore[override]
        condition = (self.state.regs.f & 0x40) != 0
        yes = self.state.copy()
        no = self.state.copy()
        yes.solver.add(condition)
        no.solver.add(~condition)
        target = self.taken
        if self.returns:
            target = yes.solver.eval(
                yes.memory.load(yes.regs.sp, 2, endness="Iend_LE")
            )
            yes.regs.sp += 2
        yes.regs.ip = claripy.BVV(target, 16)
        no.regs.ip = claripy.BVV(self.fallthrough, 16)
        self.inhibit_autoret = True
        self.successors.add_successor(yes, target, condition, "Ijk_Boring")
        self.successors.add_successor(
            no, self.fallthrough, ~condition, "Ijk_Boring"
        )


class Jump(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__()
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.jump(self.target)


def call_snapshot(
    state: angr.SimState, registers: dict[str, claripy.ast.BV], base: int
) -> claripy.ast.BV:
    values = [registers[register] for register in REGISTERS]
    values.extend(
        (
            state.memory.load(base + W_WHICH_POKEMON, 1),
            state.memory.load(base + W_ITEM_QUANTITY, 1),
        )
    )
    values.extend(
        state.memory.load(base + W_NUM_BAG_ITEMS + offset, 1)
        for offset in range(TABLE_SIZE)
    )
    return claripy.Concat(*values)


class AssemblyRemoveTransition(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        registers = assembly_registers(self.state)
        self.state.globals["call"] = call_snapshot(self.state, registers, 0)
        for register in REGISTERS:
            value = self.state.globals[f"out_{register}"]
            if register == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, register, value)
        for offset in range(TABLE_SIZE):
            self.state.memory.store(
                W_NUM_BAG_ITEMS + offset,
                self.state.globals[f"out_table_{offset}"],
            )
        self.state.memory.store(
            W_WHICH_POKEMON, self.state.globals["out_which"]
        )
        self.state.memory.store(
            W_ITEM_QUANTITY, self.state.globals["out_quantity"]
        )
        self.jump(DONE)


class NativeRemoveTransition(angr.SimProcedure):
    def run(
        self, registers_pointer: claripy.ast.BV, memory: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        registers = {
            register: self.state.memory.load(registers_pointer + index, 1)
            for index, register in enumerate(REGISTERS)
        }
        self.state.globals["call"] = call_snapshot(
            self.state, registers, NATIVE_MEMORY
        )
        for index, register in enumerate(REGISTERS):
            self.state.memory.store(
                registers_pointer + index,
                self.state.globals[f"out_{register}"],
            )
        for offset in range(TABLE_SIZE):
            self.state.memory.store(
                memory + W_NUM_BAG_ITEMS + offset,
                self.state.globals[f"out_table_{offset}"],
            )
        self.state.memory.store(
            memory + W_WHICH_POKEMON, self.state.globals["out_which"]
        )
        self.state.memory.store(
            memory + W_ITEM_QUANTITY, self.state.globals["out_quantity"]
        )


def inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for register in REGISTERS:
        values[f"out_{register}"] = (
            claripy.Concat(
                claripy.BVS(f"{prefix}_out_flags", 4), claripy.BVV(0, 4)
            )
            if register == "f"
            else claripy.BVS(f"{prefix}_out_{register}", 8)
        )
    for offset in range(TABLE_SIZE):
        values[f"out_table_{offset}"] = claripy.BVS(
            f"{prefix}_out_table_{offset}", 8
        )
    values["out_which"] = claripy.BVS(f"{prefix}_out_which", 8)
    values["out_quantity"] = claripy.BVS(f"{prefix}_out_quantity", 8)
    for slot in range(BAG_CAPACITY):
        values[f"quantity_{slot}"] = claripy.BVS(
            f"{prefix}_quantity_{slot}", 8
        )
    values["count"] = claripy.BVS(f"{prefix}_count", 8)
    values["which"] = claripy.BVS(f"{prefix}_which", 8)
    values["quantity"] = claripy.BVS(f"{prefix}_quantity", 8)
    return values


def setup_globals(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    state.globals["call"] = claripy.BVV(0, (len(REGISTERS) + 2 + TABLE_SIZE) * 8)
    for key, value in values.items():
        if key.startswith("out_"):
            state.globals[key] = value


def setup_memory(
    state: angr.SimState,
    values: dict[str, claripy.ast.BV],
    match: int | None,
    base: int,
) -> None:
    for offset in range(TABLE_SIZE):
        state.memory.store(
            base + W_NUM_BAG_ITEMS + offset, claripy.BVV(0, 8)
        )
    state.memory.store(base + W_NUM_BAG_ITEMS, values["count"])
    for slot in range(BAG_CAPACITY):
        item = 0x20 + slot
        if match == slot:
            item = OAKS_PARCEL
        state.memory.store(base + W_BAG_ITEMS + slot * 2, claripy.BVV(item, 8))
        state.memory.store(
            base + W_BAG_ITEMS + slot * 2 + 1, values[f"quantity_{slot}"]
        )
    terminator_slot = BAG_CAPACITY if match is not None else BAG_CAPACITY - 1
    state.memory.store(
        base + W_BAG_ITEMS + terminator_slot * 2, claripy.BVV(0xFF, 8)
    )
    state.memory.store(base + W_WHICH_POKEMON, values["which"])
    state.memory.store(base + W_ITEM_QUANTITY, values["quantity"])


def endpoint(state: angr.SimState, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    registers = (
        native_registers(state, NATIVE_STATE)
        if native
        else assembly_registers(state)
    )
    memory = claripy.Concat(
        state.memory.load(base + W_WHICH_POKEMON, 1),
        state.memory.load(base + W_ITEM_QUANTITY, 1),
        *(
            state.memory.load(base + W_NUM_BAG_ITEMS + offset, 1)
            for offset in range(TABLE_SIZE)
        ),
    )
    return Endpoint(
        **registers,
        memory=memory,
        call=state.globals["call"],
        constraints=tuple(state.solver.constraints),
    )


def assembly(
    values: dict[str, claripy.ast.BV], match: int | None
) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "OaksLabScript_RemoveParcel")
    target = symbol_location(SYMBOLS, "RemoveItemFromInventory")
    assert location.bank == 7 and location.address == 0x500A
    assert linked_bytes(ROM, location, len(BODY)) == BODY
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
    start = location.address
    project.hook(start, LoadPair("h", "l", W_BAG_ITEMS, start + 3), length=3)
    project.hook(start + 3, LoadPair("b", "c", 0, start + 6), length=3)
    project.hook(start + 6, Sm83LoadAAtHlIncrement(start + 7), length=1)
    project.hook(start + 7, Sm83CpImmediate(0xFF, start + 9), length=2)
    project.hook(start + 9, BranchZ(RETURN, start + 10, returns=True), length=1)
    project.hook(start + 10, Sm83CpImmediate(OAKS_PARCEL, start + 12), length=2)
    project.hook(start + 12, BranchZ(start + 18, start + 14), length=2)
    project.hook(start + 14, IncHL(start + 15), length=1)
    project.hook(start + 15, Sm83IncRegister("c", start + 16), length=1)
    project.hook(start + 16, Jump(start + 6), length=2)
    project.hook(start + 18, LoadPair("h", "l", W_NUM_BAG_ITEMS, start + 21), length=3)
    project.hook(start + 21, CopyRegister("a", "c", start + 22), length=1)
    project.hook(start + 22, Sm83StoreAImmediate(W_WHICH_POKEMON, start + 25), length=3)
    project.hook(start + 25, LoadImmediate("a", 1, start + 27), length=2)
    project.hook(start + 27, Sm83StoreAImmediate(W_ITEM_QUANTITY, start + 30), length=3)
    project.hook(target.address, AssemblyRemoveTransition(), length=1)

    state = project.factory.blank_state(addr=start)
    set_assembly_registers(state, values)
    setup_globals(state, values)
    setup_memory(state, values, match, 0)
    state.regs.sp = claripy.BVV(STACK, 16)
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    manager = project.factory.simulation_manager(state)
    manager.explore(find=lambda item: item.addr in (RETURN, DONE), num_find=2)
    assert not manager.errored and len(manager.found) == 1
    return [endpoint(manager.found[0], False)]


def native(
    values: dict[str, claripy.ast.BV], match: int | None
) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_oaks_lab_script_remove_parcel")
    target = project.loader.find_symbol("port_remove_item_from_inventory_wrapper")
    assert function is not None and target is not None
    project.hook(target.rebased_addr, NativeRemoveTransition())
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    setup_globals(state, values)
    setup_memory(state, values, match, NATIVE_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [endpoint(manager.deadended[0], True)]


@pytest.mark.skipif(
    not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),
    reason="build artifacts missing",
)
@pytest.mark.parametrize(
    "match",
    (*range(BAG_CAPACITY), None),
    ids=lambda value: "absent" if value is None else f"slot-{value}",
)
def test_oaks_lab_remove_parcel_pathwise_equivalence(match: int | None) -> None:
    values = inputs(f"oaks_lab_remove_parcel_{match}")
    assert_pathwise_equivalent(
        assembly(values, match),
        native(values, match),
        (*REGISTERS, "memory", "call"),
    )
