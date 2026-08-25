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
W_AI_COUNT = 0xCCDF
W_AI_ITEM = 0xCF05
W_NAMED_OBJECT_INDEX = 0xD11E
W_TEXT_BOX_ID = 0xD125
NAME_BUFFER = 0xCD6D
EXPECTED = bytes.fromhex("ea05cfcd3568c39566")
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
    state: claripy.ast.BV
    memory: claripy.ast.BV
    child_call: claripy.ast.BV
    decrement_call: claripy.ast.BV
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


def _memory_snapshot(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        state.memory.load(base + W_AI_ITEM, 1),
        state.memory.load(base + W_AI_COUNT, 1),
        state.memory.load(base + W_NAMED_OBJECT_INDEX, 1),
        state.memory.load(base + W_TEXT_BOX_ID, 1),
        state.memory.load(base + NAME_BUFFER, 20),
    )


class StoreAIItem(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(W_AI_ITEM, self.state.regs.a)
        self.jump(self._continuation)


class AssemblyChild(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["child_call"] = claripy.Concat(
            _assembly_full_state(self.state), _memory_snapshot(self.state, 0)
        )
        self.state.globals["trace"] = self.state.globals["trace"] * 16 + 1
        _write_assembly_state(self.state, "child_out")
        _write_child_memory(self.state, 0)
        self.jump(self._continuation)


class NativeChild(angr.SimProcedure):
    def run(
        self, address: claripy.ast.BV, memory: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        assert not memory.symbolic and self.state.solver.eval(memory) == NATIVE_MEMORY
        self.state.globals["child_call"] = claripy.Concat(
            self.state.memory.load(address, 27),
            _memory_snapshot(self.state, NATIVE_MEMORY),
        )
        self.state.globals["trace"] = self.state.globals["trace"] * 16 + 1
        for offset in range(27):
            self.state.memory.store(
                address + offset, self.state.globals[f"child_out_{offset}"]
            )
        _write_child_memory(self.state, NATIVE_MEMORY)


class AssemblyDecrement(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.globals["decrement_call"] = claripy.Concat(
            _assembly_register_bytes(self.state),
            self.state.memory.load(W_AI_COUNT, 1),
        )
        self.state.globals["trace"] = self.state.globals["trace"] * 16 + 2
        for offset, name in enumerate(REGISTERS):
            value = self.state.globals[f"decrement_out_{offset}"]
            if name == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, name, value)
        self.state.memory.store(
            W_AI_COUNT, self.state.globals["decrement_out_8"]
        )
        self.jump(RETURN)


class NativeDecrement(angr.SimProcedure):
    def run(self, address: claripy.ast.BV) -> None:  # type: ignore[override]
        self.state.globals["decrement_call"] = self.state.memory.load(address, 9)
        self.state.globals["trace"] = self.state.globals["trace"] * 16 + 2
        for offset in range(9):
            self.state.memory.store(
                address + offset, self.state.globals[f"decrement_out_{offset}"]
            )


def _write_assembly_state(state: angr.SimState, prefix: str) -> None:
    for offset, name in enumerate(REGISTERS):
        value = state.globals[f"{prefix}_{offset}"]
        if name == "f":
            value = sm83_flags_to_z80(value)
        setattr(state.regs, name, value)
    for offset, name in enumerate(GLOBALS, 8):
        state.globals[name] = state.globals[f"{prefix}_{offset}"]
    for offset, name in enumerate(REGISTERS, 18):
        state.globals[f"saved_{name}"] = state.globals[f"{prefix}_{offset}"]
    state.globals["saved_bank"] = state.globals[f"{prefix}_26"]


def _write_child_memory(state: angr.SimState, base: int) -> None:
    state.memory.store(
        base + W_NAMED_OBJECT_INDEX, state.globals["child_named"]
    )
    state.memory.store(base + W_TEXT_BOX_ID, state.globals["child_text_box"])
    for offset in range(20):
        state.memory.store(
            base + NAME_BUFFER + offset,
            state.globals[f"child_buffer_{offset}"],
        )


def _inputs() -> dict[str, claripy.ast.BV]:
    values = symbolic_registers("ai_print_item_use")
    for name in GLOBALS:
        values[name] = claripy.BVS(f"ai_print_item_use_{name}", 8)
    saved = symbolic_registers("ai_print_item_use_saved")
    for name in REGISTERS:
        values[f"saved_{name}"] = saved[name]
    values["saved_bank"] = claripy.BVS("ai_print_item_use_saved_bank", 8)
    for prefix, size in (("child_out", 27), ("decrement_out", 9)):
        for offset in range(size):
            values[f"{prefix}_{offset}"] = claripy.BVS(
                f"ai_print_item_use_{prefix}_{offset}", 8
            )
        values[f"{prefix}_1"] = claripy.Concat(
            claripy.BVS(f"ai_print_item_use_{prefix}_flags", 4),
            claripy.BVV(0, 4),
        )
    for name in ("ai_item", "ai_count", "named", "text_box"):
        values[name] = claripy.BVS(f"ai_print_item_use_memory_{name}", 8)
    values["child_named"] = claripy.BVS("ai_print_item_use_child_named", 8)
    values["child_text_box"] = claripy.BVS(
        "ai_print_item_use_child_text_box", 8
    )
    for prefix in ("initial_buffer", "child_buffer"):
        for offset in range(20):
            values[f"{prefix}_{offset}"] = claripy.BVS(
                f"ai_print_item_use_{prefix}_{offset}", 8
            )
    return values


def _setup(
    state: angr.SimState, values: dict[str, claripy.ast.BV], native: bool
) -> None:
    base = NATIVE_MEMORY if native else 0
    for name in GLOBALS:
        state.globals[name] = values[name]
    for name in REGISTERS:
        state.globals[f"saved_{name}"] = values[f"saved_{name}"]
    state.globals["saved_bank"] = values["saved_bank"]
    for prefix, size in (("child_out", 27), ("decrement_out", 9)):
        for offset in range(size):
            state.globals[f"{prefix}_{offset}"] = values[f"{prefix}_{offset}"]
    state.globals["child_named"] = values["child_named"]
    state.globals["child_text_box"] = values["child_text_box"]
    for offset in range(20):
        state.globals[f"child_buffer_{offset}"] = values[
            f"child_buffer_{offset}"
        ]
        state.memory.store(
            base + NAME_BUFFER + offset, values[f"initial_buffer_{offset}"]
        )
    state.memory.store(base + W_AI_ITEM, values["ai_item"])
    state.memory.store(base + W_AI_COUNT, values["ai_count"])
    state.memory.store(base + W_NAMED_OBJECT_INDEX, values["named"])
    state.memory.store(base + W_TEXT_BOX_ID, values["text_box"])
    state.globals["child_call"] = claripy.BVV(0, 408)
    state.globals["decrement_call"] = claripy.BVV(0, 72)
    state.globals["trace"] = claripy.BVV(0, 16)


def _endpoint(state: angr.SimState, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    full_state = (
        state.memory.load(NATIVE_STATE, 27)
        if native
        else _assembly_full_state(state)
    )
    return Endpoint(
        state=full_state,
        memory=_memory_snapshot(state, base),
        child_call=state.globals["child_call"],
        decrement_call=state.globals["decrement_call"],
        trace=state.globals["trace"],
        constraints=tuple(state.solver.constraints),
    )


@cache
def _assembly_project() -> tuple[angr.Project, int]:
    location = symbol_location(SYMS, "AIPrintItemUse")
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
    project.hook(base, StoreAIItem(base + 3), length=3)
    project.hook(base + 3, AssemblyChild(base + 6), length=3)
    project.hook(base + 6, AssemblyDecrement(), length=3)
    return project, base


@cache
def _native_project() -> tuple[angr.Project, int]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_ai_print_item_use")
    child = project.loader.find_symbol("port_ai_print_item_use_")
    decrement = project.loader.find_symbol("port_decrement_ai_count")
    assert function is not None and child is not None and decrement is not None
    project.hook(child.rebased_addr, NativeChild())
    project.hook(decrement.rebased_addr, NativeDecrement())
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
def test_ai_print_item_use_pathwise_equivalence() -> None:
    location = symbol_location(SYMS, "AIPrintItemUse")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    values = _inputs()
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        ("state", "memory", "child_call", "decrement_call", "trace"),
    )
