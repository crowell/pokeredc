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
    collect_returns,
    linked_bytes,
    rom_window,
    sm83_flags_to_z80,
    symbol_location,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xFFFF
MARKER = 0x1234
EXPECTED_ENTRY = bytes.fromhex("fa61d347fa62d34f")


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
    state_memory: claripy.ast.BV
    call_registers: claripy.ast.BV
    marker: claripy.ast.BV
    result: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class LoadField(angr.SimProcedure):
    def __init__(self, field: str, continuation: int) -> None:
        super().__init__()
        self.field = field
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals[self.field]
        self.jump(self.continuation)


class CheckCoordsSummary(angr.SimProcedure):
    """Arbitrary transition supplied by the independently proven CheckCoords."""

    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        call = assembly_registers(self.state)
        self.state.globals["call_registers"] = claripy.Concat(
            *(call[register] for register in REGISTERS)
        )
        for register in REGISTERS:
            value = self.state.globals[f"callee_{register}"]
            if register == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, register, value)
        self.state.globals["coord_index"] = self.state.globals["callee_coord_index"]
        self.state.memory.store(MARKER, self.state.globals["callee_marker"])
        self.state.globals["result"] = self.state.globals["callee_result"]
        self.jump(self.continuation)


class NativeCheckCoordsSummary(angr.SimProcedure):
    """Native-ABI form of the same independently proven transition."""

    def run(
        self, check: claripy.ast.BV, memory: claripy.ast.BV
    ) -> claripy.ast.BV:  # type: ignore[override]
        self.state.globals["call_registers"] = self.state.memory.load(check, 8)
        for offset, register in enumerate(REGISTERS):
            self.state.memory.store(
                check + offset, self.state.globals[f"callee_{register}"]
            )
        self.state.memory.store(check + 8, self.state.globals["callee_coord_index"])
        self.state.memory.store(
            memory + MARKER, self.state.globals["callee_marker"]
        )
        return self.state.globals["callee_result"]


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for field in ("coord_index", "fetched_y", "fetched_x", "player_y", "player_x"):
        values[field] = claripy.BVS(f"{prefix}_{field}", 8)
    values["marker"] = claripy.BVS(f"{prefix}_marker", 8)
    for register in REGISTERS:
        values[f"callee_{register}"] = (
            claripy.Concat(
                claripy.BVS(f"{prefix}_callee_flags", 4), claripy.BVV(0, 4)
            )
            if register == "f"
            else claripy.BVS(f"{prefix}_callee_{register}", 8)
        )
    values["callee_coord_index"] = claripy.BVS(
        f"{prefix}_callee_coord_index", 8
    )
    values["callee_marker"] = claripy.BVS(f"{prefix}_callee_marker", 8)
    values["callee_result"] = claripy.BVS(f"{prefix}_callee_result", 8)
    return values


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "ArePlayerCoordsInArray")
    assert linked_bytes(ROM, location, len(EXPECTED_ENTRY)) == EXPECTED_ENTRY
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
    project.hook(base, LoadField("player_y", base + 3), length=3)
    project.hook(base + 4, LoadField("player_x", base + 7), length=3)
    project.hook(base + 8, CheckCoordsSummary(RETURN), length=0)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    for field in ("coord_index", "player_y", "player_x"):
        state.globals[field] = values[field]
    state.globals["result"] = claripy.BVV(0, 8)
    state.globals["call_registers"] = claripy.BVV(0, 64)
    for register in REGISTERS:
        state.globals[f"callee_{register}"] = values[f"callee_{register}"]
    for field in ("callee_coord_index", "callee_marker", "callee_result"):
        state.globals[field] = values[field]
    state.memory.store(MARKER, values["marker"])
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    return [
        Endpoint(
            **assembly_registers(end),
            state_memory=claripy.Concat(
                end.globals["coord_index"],
                end.globals["player_y"],
                end.globals["player_x"],
            ),
            call_registers=end.globals["call_registers"],
            marker=end.memory.load(MARKER, 1),
            result=end.globals["result"],
            constraints=tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, RETURN)
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_are_player_coords_in_array")
    check_coords = project.loader.find_symbol("port_check_coords")
    assert function is not None and check_coords is not None
    project.hook(check_coords.rebased_addr, NativeCheckCoordsSummary())
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    for offset, field in enumerate(
        ("coord_index", "fetched_y", "fetched_x", "player_y", "player_x"), 8
    ):
        state.memory.store(NATIVE_STATE + offset, values[field])
    state.memory.store(NATIVE_MEMORY + MARKER, values["marker"])
    state.globals["call_registers"] = claripy.BVV(0, 64)
    for register in REGISTERS:
        state.globals[f"callee_{register}"] = values[f"callee_{register}"]
    for field in ("callee_coord_index", "callee_marker", "callee_result"):
        state.globals[field] = values[field]
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            state_memory=claripy.Concat(
                end.memory.load(NATIVE_STATE + 8, 1),
                end.memory.load(NATIVE_STATE + 11, 2),
            ),
            call_registers=end.globals["call_registers"],
            marker=end.memory.load(NATIVE_MEMORY + MARKER, 1),
            result=end.regs.rax[7:0],
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_are_player_coords_pathwise_equivalence() -> None:
    values = _inputs("are_player_coords")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "state_memory", "call_registers", "marker", "result"),
    )
