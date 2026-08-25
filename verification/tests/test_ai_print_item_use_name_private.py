from __future__ import annotations

from dataclasses import dataclass
from functools import cache
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
    collect_returns,
    linked_bytes,
    rom_window,
    sm83_flags_to_z80,
    symbol_location,
)


ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xE000
RETURN = 0xFFFF
W_AI_ITEM = 0xCF05
W_NAMED_OBJECT_INDEX = 0xD11E
W_TEXT_BOX_ID = 0xD125
NAME_BUFFER = 0xCD6D
EXPECTED = bytes.fromhex("fa05cfea1ed1cdcf2f214468c3493c")
GLOBALS = (
    "index",
    "type",
    "predef",
    "named",
    "loaded",
    "rom",
    "swap",
    "swap_plus",
    "unused_low",
    "unused_high",
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
    globals: claripy.ast.BV
    memory: claripy.ast.BV
    item_call: claripy.ast.BV
    print_call: claripy.ast.BV
    trace: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _assembly_register_bytes(state: angr.SimState) -> claripy.ast.BV:
    registers = assembly_registers(state)
    return claripy.Concat(*(registers[name] for name in REGISTERS))


def _assembly_full_state(state: angr.SimState) -> claripy.ast.BV:
    return claripy.Concat(
        _assembly_register_bytes(state),
        *(state.globals[name] for name in GLOBALS),
        *(state.globals[f"saved_{name}"] for name in REGISTERS),
        state.globals["saved_bank"],
    )


class LoadAIItem(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(W_AI_ITEM, 1)
        self.jump(self._continuation)


class StoreNamed(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(W_NAMED_OBJECT_INDEX, self.state.regs.a)
        self.state.globals["named"] = self.state.regs.a
        self.jump(self._continuation)


class AssemblyGetItemName(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["item_call"] = _assembly_full_state(self.state)
        self.state.globals["trace"] = self.state.globals["trace"] * 16 + 1
        for offset, name in enumerate(REGISTERS):
            value = self.state.globals[f"item_out_{offset}"]
            if name == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, name, value)
        for offset, name in enumerate(GLOBALS, 8):
            self.state.globals[name] = self.state.globals[f"item_out_{offset}"]
        for offset, name in enumerate(REGISTERS, 18):
            self.state.globals[f"saved_{name}"] = self.state.globals[
                f"item_out_{offset}"
            ]
        self.state.globals["saved_bank"] = self.state.globals["item_out_26"]
        for offset in range(20):
            self.state.memory.store(
                NAME_BUFFER + offset, self.state.globals[f"item_buffer_{offset}"]
            )
        self.jump(self._continuation)


class NativeGetItemName(angr.SimProcedure):
    def run(
        self, address: claripy.ast.BV, memory: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        assert not memory.symbolic and self.state.solver.eval(memory) == NATIVE_MEMORY
        self.state.globals["item_call"] = self.state.memory.load(address, 27)
        self.state.globals["trace"] = self.state.globals["trace"] * 16 + 1
        for offset in range(27):
            self.state.memory.store(address + offset, self.state.globals[f"item_out_{offset}"])
        for offset in range(20):
            self.state.memory.store(
                memory + NAME_BUFFER + offset,
                self.state.globals[f"item_buffer_{offset}"],
            )


class AssemblyPrintText(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.globals["print_call"] = _assembly_register_bytes(self.state)
        self.state.globals["trace"] = self.state.globals["trace"] * 16 + 2
        self.state.memory.store(W_TEXT_BOX_ID, claripy.BVV(1, 8))
        self.state.regs.b = 0xC4
        self.state.regs.c = 0xB9
        self.jump(RETURN)


class NativePrintText(angr.SimProcedure):
    def run(
        self, address: claripy.ast.BV, memory: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        assert not memory.symbolic and self.state.solver.eval(memory) == NATIVE_MEMORY
        self.state.globals["print_call"] = self.state.memory.load(address, 8)
        self.state.globals["trace"] = self.state.globals["trace"] * 16 + 2
        self.state.memory.store(address + 2, claripy.BVV(0xC4B9, 16))
        self.state.memory.store(memory + W_TEXT_BOX_ID, claripy.BVV(1, 8))


def _inputs() -> dict[str, claripy.ast.BV]:
    values = symbolic_registers("ai_print_item_use_name")
    for name in GLOBALS:
        values[name] = claripy.BVS(f"ai_print_item_use_name_{name}", 8)
    saved = symbolic_registers("ai_print_item_use_name_saved")
    for name in REGISTERS:
        values[f"saved_{name}"] = saved[name]
    values["saved_bank"] = claripy.BVS("ai_print_item_use_name_saved_bank", 8)
    for offset in range(27):
        values[f"item_out_{offset}"] = claripy.BVS(
            f"ai_print_item_use_name_item_out_{offset}", 8
        )
    values["item_out_1"] = claripy.Concat(
        claripy.BVS("ai_print_item_use_name_item_out_flags", 4),
        claripy.BVV(0, 4),
    )
    for prefix in ("initial_name", "item_buffer"):
        for offset in range(20):
            values[f"{prefix}_{offset}"] = claripy.BVS(
                f"ai_print_item_use_name_{prefix}_{offset}", 8
            )
    for name in ("ai_item", "named_memory", "text_box"):
        values[name] = claripy.BVS(f"ai_print_item_use_name_{name}", 8)
    return values


def _setup(
    state: angr.SimState, values: dict[str, claripy.ast.BV], native: bool
) -> None:
    memory_base = NATIVE_MEMORY if native else 0
    for name in GLOBALS:
        state.globals[name] = values[name]
    for name in REGISTERS:
        state.globals[f"saved_{name}"] = values[f"saved_{name}"]
    state.globals["saved_bank"] = values["saved_bank"]
    for offset in range(27):
        state.globals[f"item_out_{offset}"] = values[f"item_out_{offset}"]
    for offset in range(20):
        state.globals[f"item_buffer_{offset}"] = values[f"item_buffer_{offset}"]
        state.memory.store(
            memory_base + NAME_BUFFER + offset, values[f"initial_name_{offset}"]
        )
    state.memory.store(memory_base + W_AI_ITEM, values["ai_item"])
    state.memory.store(memory_base + W_NAMED_OBJECT_INDEX, values["named_memory"])
    state.memory.store(memory_base + W_TEXT_BOX_ID, values["text_box"])
    state.globals["item_call"] = claripy.BVV(0, 216)
    state.globals["print_call"] = claripy.BVV(0, 64)
    state.globals["trace"] = claripy.BVV(0, 16)


def _endpoint(state: angr.SimState, native: bool) -> Endpoint:
    memory_base = NATIVE_MEMORY if native else 0
    registers = (
        native_registers(state, NATIVE_STATE)
        if native
        else assembly_registers(state)
    )
    global_state = (
        state.memory.load(NATIVE_STATE + 8, 19)
        if native
        else _assembly_full_state(state)[151:0]
    )
    return Endpoint(
        **registers,
        globals=global_state,
        memory=claripy.Concat(
            state.memory.load(memory_base + W_AI_ITEM, 1),
            state.memory.load(memory_base + W_NAMED_OBJECT_INDEX, 1),
            state.memory.load(memory_base + W_TEXT_BOX_ID, 1),
            state.memory.load(memory_base + NAME_BUFFER, 20),
        ),
        item_call=state.globals["item_call"],
        print_call=state.globals["print_call"],
        trace=state.globals["trace"],
        constraints=tuple(state.solver.constraints),
    )


@cache
def _assembly_project() -> tuple[angr.Project, int]:
    location = symbol_location(SYMS, "AIPrintItemUse_")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
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
    base = location.address
    project.hook(base, LoadAIItem(base + 3), length=3)
    project.hook(base + 3, StoreNamed(base + 6), length=3)
    project.hook(base + 6, AssemblyGetItemName(base + 9), length=3)
    project.hook(base + 12, AssemblyPrintText(), length=3)
    return project, base


@cache
def _native_project() -> tuple[angr.Project, int]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_ai_print_item_use_")
    get_item = project.loader.find_symbol("port_get_item_name")
    print_text = project.loader.find_symbol("port_print_text")
    assert function is not None and get_item is not None and print_text is not None
    project.hook(get_item.rebased_addr, NativeGetItemName())
    project.hook(print_text.rebased_addr, NativePrintText())
    return project, function.rebased_addr


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, base = _assembly_project()
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _setup(state, values, False)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    return [_endpoint(end, False) for end in collect_returns(project, state, RETURN)]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, function = _native_project()
    state = project.factory.call_state(function, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    for offset, name in enumerate(GLOBALS, 8):
        state.memory.store(NATIVE_STATE + offset, values[name])
    for offset, name in enumerate(REGISTERS, 18):
        state.memory.store(NATIVE_STATE + offset, values[f"saved_{name}"])
    state.memory.store(NATIVE_STATE + 26, values["saved_bank"])
    _setup(state, values, True)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [_endpoint(manager.deadended[0], True)]


@pytest.mark.skipif(
    not ELF.exists() or not ROM.exists() or not SYMS.exists(), reason="build"
)
def test_ai_print_item_use_name_pathwise_equivalence() -> None:
    values = _inputs()
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "globals", "memory", "item_call", "print_call", "trace"),
    )
