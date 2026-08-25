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
from verification.harness.sm83_shims import Sm83CpImmediate


ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD800
RETURN = 0xFFFF
BUFFER = 0xCD6D
EXPECTED = bytes.fromhex(
    "e5c5fa1ed1fec43012eab5d03e04eab6d03e01eab7d0cd6b371803cdf32f"
    "116dcdc1e1c9"
)
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
    buffer: claripy.ast.BV
    get_call: claripy.ast.BV
    machine_call: claripy.ast.BV
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


class LoadGlobal(angr.SimProcedure):
    def __init__(self, name: str, continuation: int) -> None:
        super().__init__()
        self._name = name
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals[self._name]
        self.jump(self._continuation)


class StoreGlobal(angr.SimProcedure):
    def __init__(self, name: str, continuation: int) -> None:
        super().__init__()
        self._name = name
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.globals[self._name] = self.state.regs.a
        self.jump(self._continuation)


class AssemblyGetName(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["get_call"] = _assembly_full_state(self.state)
        self.state.globals["trace"] = claripy.BVV(1, 8)
        for offset, name in enumerate(REGISTERS):
            value = self.state.globals[f"get_out_{offset}"]
            if name == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, name, value)
        for offset, name in enumerate(GLOBALS, 8):
            self.state.globals[name] = self.state.globals[f"get_out_{offset}"]
        for offset, name in enumerate(REGISTERS, 18):
            self.state.globals[f"saved_{name}"] = self.state.globals[
                f"get_out_{offset}"
            ]
        self.state.globals["saved_bank"] = self.state.globals["get_out_26"]
        for offset in range(20):
            self.state.memory.store(
                BUFFER + offset, self.state.globals[f"get_buffer_{offset}"]
            )
        self.jump(self._continuation)


class NativeGetName(angr.SimProcedure):
    def run(
        self, address: claripy.ast.BV, memory: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        assert not memory.symbolic and self.state.solver.eval(memory) == NATIVE_MEMORY
        self.state.globals["get_call"] = self.state.memory.load(address, 27)
        self.state.globals["trace"] = claripy.BVV(1, 8)
        for offset in range(27):
            self.state.memory.store(address + offset, self.state.globals[f"get_out_{offset}"])
        for offset in range(20):
            self.state.memory.store(
                memory + BUFFER + offset, self.state.globals[f"get_buffer_{offset}"]
            )


class AssemblyGetMachineName(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["machine_call"] = claripy.Concat(
            _assembly_register_bytes(self.state), self.state.globals["named"]
        )
        self.state.globals["trace"] = claripy.BVV(2, 8)
        for offset, name in enumerate(REGISTERS):
            value = self.state.globals[f"machine_out_{offset}"]
            if name == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, name, value)
        self.state.globals["named"] = self.state.globals["machine_out_8"]
        for offset in range(20):
            self.state.memory.store(
                BUFFER + offset, self.state.globals[f"machine_buffer_{offset}"]
            )
        self.jump(self._continuation)


class NativeGetMachineName(angr.SimProcedure):
    def run(
        self, address: claripy.ast.BV, memory: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        assert not memory.symbolic and self.state.solver.eval(memory) == NATIVE_MEMORY
        self.state.globals["machine_call"] = self.state.memory.load(address, 9)
        self.state.globals["trace"] = claripy.BVV(2, 8)
        for offset in range(9):
            self.state.memory.store(
                address + offset, self.state.globals[f"machine_out_{offset}"]
            )
        for offset in range(20):
            self.state.memory.store(
                memory + BUFFER + offset,
                self.state.globals[f"machine_buffer_{offset}"],
            )


def _inputs() -> dict[str, claripy.ast.BV]:
    values = symbolic_registers("get_item_name")
    for name in GLOBALS:
        values[name] = claripy.BVS(f"get_item_name_{name}", 8)
    saved = symbolic_registers("get_item_name_saved")
    for name in REGISTERS:
        values[f"saved_{name}"] = saved[name]
    values["saved_bank"] = claripy.BVS("get_item_name_saved_bank", 8)
    for offset in range(27):
        values[f"get_out_{offset}"] = claripy.BVS(
            f"get_item_name_get_out_{offset}", 8
        )
    values["get_out_1"] = claripy.Concat(
        claripy.BVS("get_item_name_get_out_flags", 4), claripy.BVV(0, 4)
    )
    for offset in range(9):
        values[f"machine_out_{offset}"] = claripy.BVS(
            f"get_item_name_machine_out_{offset}", 8
        )
    values["machine_out_1"] = claripy.Concat(
        claripy.BVS("get_item_name_machine_out_flags", 4), claripy.BVV(0, 4)
    )
    for prefix in ("initial", "get_buffer", "machine_buffer"):
        for offset in range(20):
            values[f"{prefix}_{offset}"] = claripy.BVS(
                f"get_item_name_{prefix}_{offset}", 8
            )
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
    for prefix, count in (("get_out", 27), ("machine_out", 9)):
        for offset in range(count):
            state.globals[f"{prefix}_{offset}"] = values[f"{prefix}_{offset}"]
    for prefix in ("get_buffer", "machine_buffer"):
        for offset in range(20):
            state.globals[f"{prefix}_{offset}"] = values[f"{prefix}_{offset}"]
    for offset in range(20):
        state.memory.store(
            memory_base + BUFFER + offset, values[f"initial_{offset}"]
        )
    state.globals["get_call"] = claripy.BVV(0, 216)
    state.globals["machine_call"] = claripy.BVV(0, 72)
    state.globals["trace"] = claripy.BVV(0, 8)


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
        buffer=state.memory.load(memory_base + BUFFER, 20),
        get_call=state.globals["get_call"],
        machine_call=state.globals["machine_call"],
        trace=state.globals["trace"],
        constraints=tuple(state.solver.constraints),
    )


@cache
def _assembly_project() -> tuple[angr.Project, int]:
    location = symbol_location(SYMS, "GetItemName")
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
    project.hook(base + 2, LoadGlobal("named", base + 5), length=3)
    project.hook(base + 5, Sm83CpImmediate(0xC4, base + 7), length=2)
    project.hook(base + 9, StoreGlobal("index", base + 12), length=3)
    project.hook(base + 14, StoreGlobal("type", base + 17), length=3)
    project.hook(base + 19, StoreGlobal("predef", base + 22), length=3)
    project.hook(base + 22, AssemblyGetName(base + 25), length=3)
    project.hook(base + 27, AssemblyGetMachineName(base + 30), length=3)
    return project, base


@cache
def _native_project() -> tuple[angr.Project, int]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_get_item_name")
    get_name = project.loader.find_symbol("port_get_name")
    get_machine = project.loader.find_symbol("port_get_machine_name")
    assert function is not None and get_name is not None and get_machine is not None
    project.hook(get_name.rebased_addr, NativeGetName())
    project.hook(get_machine.rebased_addr, NativeGetMachineName())
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
    assert not manager.errored
    return [_endpoint(end, True) for end in manager.deadended]


@pytest.mark.skipif(
    not ELF.exists() or not ROM.exists() or not SYMS.exists(), reason="build"
)
def test_get_item_name_pathwise_equivalence() -> None:
    values = _inputs()
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (
            *REGISTERS,
            "globals",
            "buffer",
            "get_call",
            "machine_call",
            "trace",
        ),
    )
