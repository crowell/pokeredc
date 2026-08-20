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

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x110000
DONE = 0xEFFF
LIST_ADDRESS = 0xC500

ADDRESSES = {
    "auto_bg": 0xFFBA,
    "joy7": 0xFFB7,
    "joy_pressed": 0xFFB3,
    "loaded_bank": 0xFFB8,
    "battle_type": 0xD05A,
    "status_flags5": 0xD730,
    "menu_item_swap": 0xCC35,
    "list_count": 0xD12A,
    "list_pointer_low": 0xCF8B,
    "list_pointer_high": 0xCF8C,
    "text_box_id": 0xD125,
    "watch_oob": 0xCC37,
    "max_menu_item": 0xCC28,
    "top_menu_y": 0xCC24,
    "top_menu_x": 0xCC25,
    "watched_keys": 0xCC29,
    "current_item": 0xCC26,
    "scroll_offset": 0xCC36,
    "list_menu_id": 0xCF94,
    "which_pokemon": 0xCF92,
    "cur_item": 0xCF91,
    "max_item_quantity": 0xCF97,
    "name_list_index": 0xD0B5,
    "predef_bank": 0xD0B7,
    "cursor_low": 0xCC30,
    "cursor_high": 0xCC31,
    "exit_method": 0xD12E,
    "chosen_item": 0xD12D,
    "rom_bank": 0x2000,
}
FIELDS = tuple(ADDRESSES) + ("list_entries_count",)


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
    constraints: tuple[claripy.ast.Bool, ...]




class Boundary(angr.SimProcedure):
    def __init__(self, continuation: int):
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:
        self.jump(self.continuation)
class SetupBoundary(angr.SimProcedure):
    def __init__(self, loop: int):
        super().__init__()
        self.loop = loop

    def run(self) -> None:
        memory = self.state.memory
        battle = self.state.globals["battle_type"]
        list_count = self.state.globals["list_entries_count"]
        saved_bank = self.state.globals["loaded_bank"]
        self.state.globals["saved_bank"] = saved_bank
        memory.store(ADDRESSES["auto_bg"], claripy.BVV(0, 8))
        memory.store(ADDRESSES["joy7"], claripy.BVV(1, 8))
        bank = claripy.If(battle == 0, claripy.BVV(1, 8), claripy.BVV(0, 8))
        memory.store(ADDRESSES["loaded_bank"], bank)
        memory.store(ADDRESSES["rom_bank"], bank)
        memory.store(
            ADDRESSES["status_flags5"],
            memory.load(ADDRESSES["status_flags5"], 1) | 0x40,
        )
        memory.store(ADDRESSES["menu_item_swap"], claripy.BVV(0, 8))
        memory.store(ADDRESSES["list_count"], list_count)
        memory.store(ADDRESSES["text_box_id"], claripy.BVV(0x0D, 8))
        memory.store(ADDRESSES["watch_oob"], claripy.BVV(1, 8))
        memory.store(
            ADDRESSES["max_menu_item"],
            claripy.If(list_count < 2, claripy.BVV(1, 8), claripy.BVV(2, 8)),
        )
        memory.store(ADDRESSES["top_menu_y"], claripy.BVV(4, 8))
        memory.store(ADDRESSES["top_menu_x"], claripy.BVV(5, 8))
        memory.store(ADDRESSES["watched_keys"], claripy.BVV(7, 8))
        self.jump(self.loop)


class LoopStart(angr.SimProcedure):
    def __init__(self, continuation: int):
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:
        self.state.memory.store(ADDRESSES["auto_bg"], claripy.BVV(0, 8))
        self.jump(self.continuation)


class StoreAuto(angr.SimProcedure):
    def __init__(self, continuation: int):
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:
        self.state.memory.store(ADDRESSES["auto_bg"], self.state.regs.a)
        self.jump(self.continuation)


class LoadBattle(angr.SimProcedure):
    def __init__(self, continuation: int):
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:
        self.state.regs.a = self.state.globals["battle_type"]
        self.jump(self.continuation)


class MenuInput(angr.SimProcedure):
    def __init__(self, continuation: int):
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:
        self.state.regs.a = claripy.BVV(2, 8)  # PAD_B
        self.jump(self.continuation)


class RestoreInput(angr.SimProcedure):
    def run(self) -> None:
        self.state.regs.a = claripy.BVV(2, 8)
        self.jump(self.addr + 1)


class CheckOther(angr.SimProcedure):
    def run(self) -> None:
        self.jump(self.addr + 0x9D)


class CancelBoundary(angr.SimProcedure):
    def run(self) -> None:
        saved_bank = self.state.globals["saved_bank"]
        self.state.memory.store(ADDRESSES["exit_method"], claripy.BVV(2, 8))
        self.state.memory.store(ADDRESSES["loaded_bank"], saved_bank)
        self.state.memory.store(ADDRESSES["rom_bank"], saved_bank)
        self.jump(DONE)


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for field in FIELDS:
        values[field] = claripy.BVS(f"{prefix}_{field}", 8)
    values["battle_type"] = claripy.BVV(0, 8)
    values["joy_pressed"] = claripy.BVV(2, 8)
    values["list_pointer_low"] = claripy.BVV(LIST_ADDRESS & 0xFF, 8)
    values["list_pointer_high"] = claripy.BVV(LIST_ADDRESS >> 8, 8)
    return values


def _store_assembly_memory(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    for field, address in ADDRESSES.items():
        state.memory.store(address, values[field])
    state.memory.store(LIST_ADDRESS, values["list_entries_count"])
    for field in FIELDS:
        state.globals[field] = values[field]


def _setup_native_memory(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    for field, address in ADDRESSES.items():
        state.memory.store(NATIVE_MEMORY + address, values[field])
    state.memory.store(NATIVE_MEMORY + LIST_ADDRESS, values["list_entries_count"])


def _memory_endpoint(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        *(state.memory.load(base + ADDRESSES[field], 1) for field in FIELDS if field != "list_entries_count"),
        state.memory.load(base + LIST_ADDRESS, 1),
    )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "DisplayListMenuID")
    loop = symbol_location(SYMBOLS, "DisplayListMenuIDLoop")
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
    q = loop.address
    project.hook(location.address, SetupBoundary(q), length=1)
    project.hook(q, LoopStart(q + 3), length=1)
    project.hook(q + 3, Boundary(q + 6), length=3)
    project.hook(q + 8, StoreAuto(q + 10), length=2)
    project.hook(q + 10, Boundary(q + 13), length=3)
    project.hook(q + 13, LoadBattle(q + 16), length=3)
    project.hook(q + 16, Boundary(q + 0x2E), length=1)
    project.hook(q + 0x2E, Boundary(q + 0x31), length=3)
    project.hook(q + 0x31, MenuInput(q + 0x34), length=3)
    project.hook(q + 0x35, Boundary(q + 0x38), length=3)
    project.hook(q + 0x38, RestoreInput(), length=1)
    project.hook(q + 0x3B, Boundary(q + 0xDA), length=3)
    project.hook(q + 0xDC, CancelBoundary(), length=3)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    _store_assembly_memory(state, values)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored
    return [
        Endpoint(
            **assembly_registers(end),
            memory=_memory_endpoint(end, 0),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_display_list_menu_id")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup_native_memory(state, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=_memory_endpoint(end, NATIVE_MEMORY),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_display_list_menu_id_cancel_pathwise_equivalence() -> None:
    values = _inputs("display_cancel")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        ("memory",),
    )
