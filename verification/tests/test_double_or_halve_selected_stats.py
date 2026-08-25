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
NATIVE_STATS = 0x110000
STACK = 0xE000
RETURN = 0xFFFF
EXPECTED = bytes.fromhex("218056060ecdd63521a756060ec3d635")
GLOBALS = ("whose_turn", "player_mask", "enemy_mask", "stat_high", "stat_low")


@dataclass(frozen=True)
class Endpoint:
    state: claripy.ast.BV
    stats: claripy.ast.BV
    double_call: claripy.ast.BV
    halve_call: claripy.ast.BV
    trace: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _register_bytes(state: angr.SimState) -> claripy.ast.BV:
    registers = assembly_registers(state)
    return claripy.Concat(*(registers[name] for name in REGISTERS))


def _assembly_state(state: angr.SimState) -> claripy.ast.BV:
    return claripy.Concat(
        _register_bytes(state), *(state.globals[name] for name in GLOBALS)
    )


def _semantic_state(state: angr.SimState) -> claripy.ast.BV:
    registers = assembly_registers(state)
    return claripy.Concat(
        registers["a"],
        registers["f"],
        state.globals["semantic_b"],
        registers["c"],
        registers["d"],
        registers["e"],
        state.globals["semantic_h"],
        state.globals["semantic_l"],
        *(state.globals[name] for name in GLOBALS),
    )


def _write_assembly_output(state: angr.SimState, prefix: str) -> None:
    for offset, name in enumerate(REGISTERS):
        value = state.globals[f"{prefix}_{offset}"]
        if name == "f":
            value = sm83_flags_to_z80(value)
        setattr(state.regs, name, value)
    for offset, name in enumerate(GLOBALS, 8):
        state.globals[name] = state.globals[f"{prefix}_{offset}"]


class AssemblyDouble(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["double_call"] = claripy.Concat(
            self.state.globals["initial_state"], self.state.globals["stats"]
        )
        self.state.globals["trace"] = self.state.globals["trace"] * 16 + 1
        _write_assembly_output(self.state, "double_out")
        self.state.globals["semantic_b"] = self.state.globals["double_out_2"]
        self.state.globals["semantic_h"] = self.state.globals["double_out_6"]
        self.state.globals["semantic_l"] = self.state.globals["double_out_7"]
        self.state.globals["stats"] = self.state.globals["double_stats_out"]
        self.jump(self.continuation)


class AssemblyHalve(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.globals["halve_call"] = claripy.Concat(
            _semantic_state(self.state), self.state.globals["stats"]
        )
        self.state.globals["trace"] = self.state.globals["trace"] * 16 + 2
        _write_assembly_output(self.state, "halve_out")
        self.state.globals["stats"] = self.state.globals["halve_stats_out"]
        self.jump(RETURN)


class NativeCallee(angr.SimProcedure):
    def __init__(self, prefix: str, trace_value: int) -> None:
        super().__init__()
        self.prefix = prefix
        self.trace_value = trace_value

    def run(
        self, address: claripy.ast.BV, stats: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        assert not stats.symbolic and self.state.solver.eval(stats) == NATIVE_STATS
        self.state.globals[f"{self.prefix}_call"] = claripy.Concat(
            self.state.memory.load(address, 13), self.state.memory.load(stats, 8)
        )
        self.state.globals["trace"] = (
            self.state.globals["trace"] * 16 + self.trace_value
        )
        for offset in range(13):
            self.state.memory.store(
                address + offset, self.state.globals[f"{self.prefix}_out_{offset}"]
            )
        self.state.memory.store(
            stats, self.state.globals[f"{self.prefix}_stats_out"]
        )


def _inputs() -> dict[str, claripy.ast.BV]:
    values = symbolic_registers("double_or_halve")
    for name in GLOBALS:
        values[name] = claripy.BVS(f"double_or_halve_{name}", 8)
    values["stats"] = claripy.BVS("double_or_halve_stats", 64)
    for prefix in ("double", "halve"):
        for offset in range(13):
            values[f"{prefix}_out_{offset}"] = claripy.BVS(
                f"double_or_halve_{prefix}_out_{offset}", 8
            )
        values[f"{prefix}_out_1"] = claripy.Concat(
            claripy.BVS(f"double_or_halve_{prefix}_flags", 4),
            claripy.BVV(0, 4),
        )
        values[f"{prefix}_stats_out"] = claripy.BVS(
            f"double_or_halve_{prefix}_stats_out", 64
        )
    return values


def _setup(
    state: angr.SimState, values: dict[str, claripy.ast.BV], native: bool
) -> None:
    for name in GLOBALS:
        state.globals[name] = values[name]
    for prefix in ("double", "halve"):
        for offset in range(13):
            state.globals[f"{prefix}_out_{offset}"] = values[
                f"{prefix}_out_{offset}"
            ]
        state.globals[f"{prefix}_stats_out"] = values[f"{prefix}_stats_out"]
    state.globals["double_call"] = claripy.BVV(0, 168)
    state.globals["halve_call"] = claripy.BVV(0, 168)
    state.globals["trace"] = claripy.BVV(0, 16)
    if native:
        state.memory.store(NATIVE_STATS, values["stats"])
    else:
        state.globals["stats"] = values["stats"]
        state.globals["initial_state"] = _assembly_state(state)
        state.globals["semantic_b"] = values["b"]
        state.globals["semantic_h"] = values["h"]
        state.globals["semantic_l"] = values["l"]


def _endpoint(state: angr.SimState, native: bool) -> Endpoint:
    return Endpoint(
        state=(
            state.memory.load(NATIVE_STATE, 13)
            if native
            else _assembly_state(state)
        ),
        stats=(
            state.memory.load(NATIVE_STATS, 8)
            if native
            else state.globals["stats"]
        ),
        double_call=state.globals["double_call"],
        halve_call=state.globals["halve_call"],
        trace=state.globals["trace"],
        constraints=tuple(state.solver.constraints),
    )


@cache
def _assembly_project() -> tuple[angr.Project, int]:
    location = symbol_location(SYMS, "DoubleOrHalveSelectedStats")
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
    project.hook(base + 5, AssemblyDouble(base + 8), length=3)
    project.hook(base + 13, AssemblyHalve(), length=3)
    return project, base


@cache
def _native_project() -> tuple[angr.Project, int]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_double_or_halve_selected_stats")
    double = project.loader.find_symbol("port_double_selected_stats")
    halve = project.loader.find_symbol("port_halve_selected_stats")
    assert function is not None and double is not None and halve is not None
    project.hook(double.rebased_addr, NativeCallee("double", 1))
    project.hook(halve.rebased_addr, NativeCallee("halve", 2))
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
    state = project.factory.call_state(function, NATIVE_STATE, NATIVE_STATS)
    store_native_registers(state, NATIVE_STATE, values)
    for offset, name in enumerate(GLOBALS, 8):
        state.memory.store(NATIVE_STATE + offset, values[name])
    _setup(state, values, True)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [_endpoint(manager.deadended[0], True)]


@pytest.mark.skipif(
    not ELF.exists() or not ROM.exists() or not SYMS.exists(), reason="build"
)
def test_double_or_halve_selected_stats_pathwise_equivalence() -> None:
    location = symbol_location(SYMS, "DoubleOrHalveSelectedStats")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    values = _inputs()
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        ("state", "stats", "double_call", "halve_call", "trace"),
    )
