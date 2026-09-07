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
    Sm83LoadAHighImmediate,
    Sm83StoreAHighImmediate,
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

H_LOADED_ROM_BANK = 0xFFB8
R_ROMB = 0x2000
W_WHICH_POKEMON = 0xCF92
W_ITEM_QUANTITY = 0xCF96
W_MAX_ITEM_QUANTITY = 0xCF97
W_CURRENT_MENU_ITEM = 0xCC26
W_MAX_MENU_ITEM = 0xCC28
W_BAG_SAVED_MENU_ITEM = 0xCC2C
W_LIST_SCROLL_OFFSET = 0xCC36
W_SAVED_LIST_SCROLL_OFFSET = 0xD07E
W_LIST_COUNT = 0xD12A

GLOBALS = (
    W_WHICH_POKEMON,
    W_ITEM_QUANTITY,
    W_MAX_ITEM_QUANTITY,
    W_LIST_SCROLL_OFFSET,
    W_CURRENT_MENU_ITEM,
    W_BAG_SAVED_MENU_ITEM,
    W_SAVED_LIST_SCROLL_OFFSET,
    W_LIST_COUNT,
    W_MAX_MENU_ITEM,
)
INNER_FIELD_OFFSETS = (8, 9, 10, 14, 15, 16, 17, 19, 20)
OUTPUT_FIELD_OFFSETS = (10, 14, 15, 16, 17, 19, 20)
OUTPUT_GLOBALS = (
    W_MAX_ITEM_QUANTITY,
    W_LIST_SCROLL_OFFSET,
    W_CURRENT_MENU_ITEM,
    W_BAG_SAVED_MENU_ITEM,
    W_SAVED_LIST_SCROLL_OFFSET,
    W_LIST_COUNT,
    W_MAX_MENU_ITEM,
)
INVENTORIES = ((0xD31D, 42, "bag"), (0xD53A, 102, "pc"))
BODY = bytes.fromhex("f0b8f53e03e0b8ea0020cd744ef1e0b8ea0020c9")


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


class PushAF(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.sp -= 2
        self.state.memory.store(self.state.regs.sp, self.state.regs.f)
        self.state.memory.store(self.state.regs.sp + 1, self.state.regs.a)
        self.jump(self.next_address)


class PopAF(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.f = self.state.memory.load(self.state.regs.sp, 1)
        self.state.regs.a = self.state.memory.load(self.state.regs.sp + 1, 1)
        self.state.regs.sp += 2
        self.jump(self.next_address)


class LoadA(angr.SimProcedure):
    def __init__(self, value: int, next_address: int) -> None:
        super().__init__()
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(self.value, 8)
        self.jump(self.next_address)


class Call(angr.SimProcedure):
    def __init__(self, target: int, return_address: int) -> None:
        super().__init__()
        self.target = target
        self.return_address = return_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.sp -= 2
        self.state.memory.store(
            self.state.regs.sp,
            claripy.BVV(self.return_address, 16),
            endness="Iend_LE",
        )
        self.jump(self.target)


class Return(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        target = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp += 2
        self.jump(target)


def semantic_call(
    state: angr.SimState,
    registers: dict[str, claripy.ast.BV],
    fields: list[claripy.ast.BV],
) -> claripy.ast.BV:
    return claripy.Concat(
        *(registers[register] for register in REGISTERS), *fields
    )


class AssemblyInnerTransition(angr.SimProcedure):
    def __init__(self, return_address: int) -> None:
        super().__init__()
        self.return_address = return_address

    def run(self) -> None:  # type: ignore[override]
        registers = assembly_registers(self.state)
        fields = [self.state.memory.load(address, 1) for address in GLOBALS]
        self.state.globals["call"] = semantic_call(
            self.state, registers, fields
        )
        for register in REGISTERS:
            value = self.state.globals[f"out_{register}"]
            if register == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, register, value)
        for address in OUTPUT_GLOBALS:
            self.state.memory.store(address, self.state.globals[f"out_{address:x}"])
        inventory = self.state.globals["inventory"]
        span = self.state.globals["span"]
        for offset in range(span):
            self.state.memory.store(
                inventory + offset, self.state.globals[f"out_mem_{offset}"]
            )
        target = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp += 2
        self.jump(target)


class NativeInnerTransition(angr.SimProcedure):
    def run(
        self, inner: claripy.ast.BV, memory: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        registers = {
            register: self.state.memory.load(inner + index, 1)
            for index, register in enumerate(REGISTERS)
        }
        fields = [
            self.state.memory.load(inner + offset, 1)
            for offset in INNER_FIELD_OFFSETS
        ]
        self.state.globals["call"] = semantic_call(
            self.state, registers, fields
        )
        for index, register in enumerate(REGISTERS):
            self.state.memory.store(
                inner + index, self.state.globals[f"out_{register}"]
            )
        for field_offset, address in zip(
            OUTPUT_FIELD_OFFSETS, OUTPUT_GLOBALS, strict=True
        ):
            self.state.memory.store(
                inner + field_offset, self.state.globals[f"out_{address:x}"]
            )
        inventory = self.state.globals["inventory"]
        span = self.state.globals["span"]
        for offset in range(span):
            self.state.memory.store(
                memory + inventory + offset,
                self.state.globals[f"out_mem_{offset}"],
            )


def inputs(prefix: str, span: int) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["loaded_bank"] = claripy.BVS(f"{prefix}_loaded_bank", 8)
    values["romb"] = claripy.BVS(f"{prefix}_romb", 8)
    for index, address in enumerate(GLOBALS):
        values[f"global_{address:x}"] = claripy.BVS(
            f"{prefix}_global_{index}", 8
        )
    for register in REGISTERS:
        values[f"out_{register}"] = (
            claripy.Concat(
                claripy.BVS(f"{prefix}_out_flags", 4), claripy.BVV(0, 4)
            )
            if register == "f"
            else claripy.BVS(f"{prefix}_out_{register}", 8)
        )
    for address in OUTPUT_GLOBALS:
        values[f"out_{address:x}"] = claripy.BVS(
            f"{prefix}_out_{address:x}", 8
        )
    for offset in range(span):
        values[f"mem_{offset}"] = claripy.BVS(f"{prefix}_mem_{offset}", 8)
        values[f"out_mem_{offset}"] = claripy.BVS(
            f"{prefix}_out_mem_{offset}", 8
        )
    return values


def setup(
    state: angr.SimState,
    values: dict[str, claripy.ast.BV],
    inventory: int,
    span: int,
    base: int,
) -> None:
    state.memory.store(base + H_LOADED_ROM_BANK, values["loaded_bank"])
    state.memory.store(base + R_ROMB, values["romb"])
    for address in GLOBALS:
        state.memory.store(
            base + address, values[f"global_{address:x}"]
        )
    for offset in range(span):
        state.memory.store(base + inventory + offset, values[f"mem_{offset}"])
    state.globals["inventory"] = inventory
    state.globals["span"] = span
    state.globals["call"] = claripy.BVV(0, (len(REGISTERS) + len(GLOBALS)) * 8)
    for key, value in values.items():
        if key.startswith("out_"):
            state.globals[key] = value


def endpoint(
    state: angr.SimState, native: bool, inventory: int, span: int
) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    registers = (
        native_registers(state, NATIVE_STATE)
        if native
        else assembly_registers(state)
    )
    memory = claripy.Concat(
        state.memory.load(base + H_LOADED_ROM_BANK, 1),
        state.memory.load(base + R_ROMB, 1),
        *(state.memory.load(base + address, 1) for address in GLOBALS),
        *(
            state.memory.load(base + inventory + offset, 1)
            for offset in range(span)
        ),
    )
    return Endpoint(
        **registers,
        memory=memory,
        call=state.globals["call"],
        constraints=tuple(state.solver.constraints),
    )


def assembly(
    values: dict[str, claripy.ast.BV], inventory: int, span: int
) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "RemoveItemFromInventory")
    inner = symbol_location(SYMBOLS, "RemoveItemFromInventory_")
    assert linked_bytes(ROM, location, len(BODY)) == BODY
    project = angr.Project(
        rom_window(ROM, inner.bank),
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
    project.hook(start, Sm83LoadAHighImmediate(0xB8, start + 2), length=2)
    project.hook(start + 2, PushAF(start + 3), length=1)
    project.hook(start + 3, LoadA(3, start + 5), length=2)
    project.hook(start + 5, Sm83StoreAHighImmediate(0xB8, start + 7), length=2)
    project.hook(start + 7, Sm83StoreAImmediate(R_ROMB, start + 10), length=3)
    project.hook(start + 10, Call(inner.address, start + 13), length=3)
    project.hook(inner.address, AssemblyInnerTransition(start + 13), length=1)
    project.hook(start + 13, PopAF(start + 14), length=1)
    project.hook(start + 14, Sm83StoreAHighImmediate(0xB8, start + 16), length=2)
    project.hook(start + 16, Sm83StoreAImmediate(R_ROMB, start + 19), length=3)
    project.hook(start + 19, Return(), length=1)

    state = project.factory.blank_state(addr=start)
    set_assembly_registers(state, values)
    state.regs.h = claripy.BVV(inventory >> 8, 8)
    state.regs.l = claripy.BVV(inventory & 0xFF, 8)
    setup(state, values, inventory, span, 0)
    state.regs.sp = claripy.BVV(STACK, 16)
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN, num_find=1)
    assert not manager.errored and len(manager.found) == 1
    return [endpoint(manager.found[0], False, inventory, span)]


def native(
    values: dict[str, claripy.ast.BV], inventory: int, span: int
) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_remove_item_from_inventory_wrapper")
    inner = project.loader.find_symbol("port_remove_item_from_inventory")
    assert function is not None and inner is not None
    project.hook(inner.rebased_addr, NativeInnerTransition())
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 6, claripy.BVV(inventory >> 8, 8))
    state.memory.store(NATIVE_STATE + 7, claripy.BVV(inventory & 0xFF, 8))
    setup(state, values, inventory, span, NATIVE_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [endpoint(manager.deadended[0], True, inventory, span)]


@pytest.mark.skipif(
    not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),
    reason="build artifacts missing",
)
@pytest.mark.parametrize("inventory,span,name", INVENTORIES, ids=lambda item: str(item))
def test_remove_item_from_inventory_wrapper_pathwise_equivalence(
    inventory: int, span: int, name: str
) -> None:
    values = inputs(f"remove_inventory_wrapper_{name}", span)
    assert_pathwise_equivalent(
        assembly(values, inventory, span),
        native(values, inventory, span),
        (*REGISTERS, "memory", "call"),
    )
