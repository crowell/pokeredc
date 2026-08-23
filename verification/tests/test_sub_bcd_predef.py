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

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
MARKER = 0x1234
DONE = 0xEFFF
EXPECTED = bytes.fromhex(
    "cd943ea7411a9e27121b2b0d20f730093e001312130520fb37c9"
)
PREDEF_FIELDS = tuple(f"predef{index}" for index in range(6))
SUB_FIELDS = ("fetched_left", "fetched_right", "written")
FIELDS = (*PREDEF_FIELDS, *SUB_FIELDS)


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
    state: claripy.ast.BV
    calls: claripy.ast.BV
    marker: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class CallSummary(angr.SimProcedure):
    def __init__(self, kind: str, target: int):
        super().__init__()
        self.kind = kind
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        registers = assembly_registers(self.state)
        fields = PREDEF_FIELDS if self.kind == "predef" else SUB_FIELDS
        parts = [
            *(registers[register] for register in REGISTERS),
            *(self.state.globals[field] for field in fields),
        ]
        if self.kind == "sub":
            parts.append(self.state.globals["marker"])
        self.state.globals["call_" + self.kind] = claripy.Concat(*parts)
        for register in REGISTERS:
            value = self.state.globals[f"{self.kind}_out_{register}"]
            if register == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, register, value)
        if self.kind == "sub":
            for field in SUB_FIELDS:
                self.state.globals[field] = self.state.globals[
                    "sub_out_" + field
                ]
            self.state.globals["marker"] = self.state.globals[
                "sub_out_marker"
            ]
        self.jump(self.target)


class NativeCallSummary(angr.SimProcedure):
    def __init__(self, kind: str):
        super().__init__()
        self.kind = kind

    def run(
        self, callee_state: claripy.ast.BV, memory: claripy.ast.BV | None = None
    ) -> None:  # type: ignore[override]
        size = 14 if self.kind == "predef" else 11
        parts = [self.state.memory.load(callee_state, size)]
        if self.kind == "sub":
            if memory is None:
                memory = self.state.regs.rsi
            parts.append(self.state.memory.load(memory + MARKER, 1))
        self.state.globals["call_" + self.kind] = claripy.Concat(*parts)
        output = [
            *(self.state.globals[f"{self.kind}_out_{register}"]
              for register in REGISTERS)
        ]
        if self.kind == "sub":
            output.extend(
                self.state.globals["sub_out_" + field]
                for field in SUB_FIELDS
            )
        self.state.memory.store(callee_state, claripy.Concat(*output))
        if self.kind == "sub":
            assert memory is not None
            self.state.memory.store(
                memory + MARKER, self.state.globals["sub_out_marker"]
            )


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for field in FIELDS:
        values[field] = claripy.BVS(f"{prefix}_{field}", 8)
    for kind in ("predef", "sub"):
        for register in REGISTERS:
            values[f"{kind}_out_{register}"] = (
                claripy.Concat(
                    claripy.BVS(f"{prefix}_{kind}_out_flags", 4),
                    claripy.BVV(0, 4),
                )
                if register == "f"
                else claripy.BVS(f"{prefix}_{kind}_out_{register}", 8)
            )
    for field in SUB_FIELDS:
        values["sub_out_" + field] = claripy.BVS(
            f"{prefix}_sub_out_{field}", 8
        )
    values["marker"] = claripy.BVS(f"{prefix}_marker", 8)
    values["sub_out_marker"] = claripy.BVS(f"{prefix}_sub_out_marker", 8)
    return values


def _setup(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    for field in FIELDS:
        state.globals[field] = values[field]
    for kind in ("predef", "sub"):
        for register in REGISTERS:
            state.globals[f"{kind}_out_{register}"] = values[
                f"{kind}_out_{register}"
            ]
    for field in SUB_FIELDS:
        state.globals["sub_out_" + field] = values["sub_out_" + field]
    state.globals["marker"] = values["marker"]
    state.globals["sub_out_marker"] = values["sub_out_marker"]
    state.globals["call_predef"] = claripy.BVV(0, 112)
    state.globals["call_sub"] = claripy.BVV(0, 96)


def _calls(state: angr.SimState) -> claripy.ast.BV:
    return claripy.Concat(
        state.globals["call_predef"], state.globals["call_sub"]
    )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "SubBCDPredef")
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
    project.hook(base, CallSummary("predef", base + 3), length=3)
    project.hook(base + 3, CallSummary("sub", DONE), length=23)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _setup(state, values)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE)
    assert not manager.errored
    return [
        Endpoint(
            **assembly_registers(end),
            state=claripy.Concat(*(end.globals[field] for field in FIELDS)),
            calls=_calls(end),
            marker=end.globals["marker"],
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_sub_bcd_predef")
    predef = project.loader.find_symbol("port_get_predef_registers")
    subtract = project.loader.find_symbol("port_sub_bcd")
    assert function is not None and predef is not None and subtract is not None
    project.hook(predef.rebased_addr, NativeCallSummary("predef"))
    project.hook(subtract.rebased_addr, NativeCallSummary("sub"))
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    for offset, field in enumerate(FIELDS, 8):
        state.memory.store(NATIVE_STATE + offset, values[field])
    _setup(state, values)
    state.memory.store(NATIVE_MEMORY + MARKER, values["marker"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            state=end.memory.load(NATIVE_STATE + 8, len(FIELDS)),
            calls=_calls(end),
            marker=end.memory.load(NATIVE_MEMORY + MARKER, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_sub_bcd_predef_pathwise_equivalence() -> None:
    values = _inputs("sub_bcd_predef")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "state", "calls", "marker"),
    )
