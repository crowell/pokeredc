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
    "cd943ee53e78223ccde05a3c77e111140019e53e7b223e7fcde05a3677e1111"
    "400190520ed3e7c223e76cde05a367dc9"
)
PREDEF_FIELDS = tuple(f"predef{index}" for index in range(6))
BORDER_FIELDS = (
    "saved_h", "saved_l", "written0", "written1",
    "write0_h", "write0_l", "write1_h", "write1_l",
)
FIELDS = (*PREDEF_FIELDS, *BORDER_FIELDS)


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
        fields = PREDEF_FIELDS if self.kind == "predef" else BORDER_FIELDS
        parts = [
            *(registers[register] for register in REGISTERS),
            *(self.state.globals[field] for field in fields),
        ]
        if self.kind == "border":
            parts.append(self.state.globals["marker"])
        self.state.globals["call_" + self.kind] = claripy.Concat(*parts)
        for register in REGISTERS:
            value = self.state.globals[f"{self.kind}_out_{register}"]
            if register == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, register, value)
        if self.kind == "border":
            for field in BORDER_FIELDS:
                self.state.globals[field] = self.state.globals[
                    "border_out_" + field
                ]
            self.state.globals["marker"] = self.state.globals[
                "border_out_marker"
            ]
        self.jump(self.target)


class NativeCallSummary(angr.SimProcedure):
    def __init__(self, kind: str):
        super().__init__()
        self.kind = kind

    def run(
        self, callee_state: claripy.ast.BV,
        memory: claripy.ast.BV | None = None,
    ) -> None:  # type: ignore[override]
        size = 14 if self.kind == "predef" else 16
        parts = [self.state.memory.load(callee_state, size)]
        if self.kind == "border":
            if memory is None:
                memory = self.state.regs.rsi
            parts.append(self.state.memory.load(memory + MARKER, 1))
        self.state.globals["call_" + self.kind] = claripy.Concat(*parts)
        output = [
            *(self.state.globals[f"{self.kind}_out_{register}"]
              for register in REGISTERS)
        ]
        if self.kind == "border":
            output.extend(
                self.state.globals["border_out_" + field]
                for field in BORDER_FIELDS
            )
        self.state.memory.store(callee_state, claripy.Concat(*output))
        if self.kind == "border":
            assert memory is not None
            self.state.memory.store(
                memory + MARKER, self.state.globals["border_out_marker"]
            )


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for field in FIELDS:
        values[field] = claripy.BVS(f"{prefix}_{field}", 8)
    for kind in ("predef", "border"):
        for register in REGISTERS:
            values[f"{kind}_out_{register}"] = (
                claripy.Concat(
                    claripy.BVS(f"{prefix}_{kind}_out_flags", 4),
                    claripy.BVV(0, 4),
                )
                if register == "f"
                else claripy.BVS(f"{prefix}_{kind}_out_{register}", 8)
            )
    for field in BORDER_FIELDS:
        values["border_out_" + field] = claripy.BVS(
            f"{prefix}_border_out_{field}", 8
        )
    values["marker"] = claripy.BVS(f"{prefix}_marker", 8)
    values["border_out_marker"] = claripy.BVS(
        f"{prefix}_border_out_marker", 8
    )
    return values


def _setup(
    state: angr.SimState, values: dict[str, claripy.ast.BV]
) -> None:
    for field in FIELDS:
        state.globals[field] = values[field]
    for kind in ("predef", "border"):
        for register in REGISTERS:
            state.globals[f"{kind}_out_{register}"] = values[
                f"{kind}_out_{register}"
            ]
    for field in BORDER_FIELDS:
        state.globals["border_out_" + field] = values[
            "border_out_" + field
        ]
    state.globals["marker"] = values["marker"]
    state.globals["border_out_marker"] = values["border_out_marker"]
    state.globals["call_predef"] = claripy.BVV(0, 112)
    state.globals["call_border"] = claripy.BVV(0, 136)


def _calls(state: angr.SimState) -> claripy.ast.BV:
    return claripy.Concat(
        state.globals["call_predef"], state.globals["call_border"]
    )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "Diploma_TextBoxBorder")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0, "entry_point": location.address,
        },
    )
    base = location.address
    project.hook(base, CallSummary("predef", base + 3), length=3)
    project.hook(base + 3, CallSummary("border", DONE), length=45)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _setup(state, values)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE)
    assert not manager.errored
    return [
        Endpoint(
            **assembly_registers(end),
            state=claripy.Concat(
                *(end.globals[field] for field in FIELDS)
            ),
            calls=_calls(end), marker=end.globals["marker"],
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(
        "port_diploma_text_box_border_private"
    )
    predef = project.loader.find_symbol("port_get_predef_registers")
    border = project.loader.find_symbol("port_cable_club_text_box_border")
    assert function is not None and predef is not None and border is not None
    project.hook(predef.rebased_addr, NativeCallSummary("predef"))
    project.hook(border.rebased_addr, NativeCallSummary("border"))
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
def test_diploma_text_box_border_private_pathwise_equivalence() -> None:
    values = _inputs("diploma_text_box_border")
    assert_pathwise_equivalent(
        _assembly(values), _native(values),
        (*REGISTERS, "state", "calls", "marker"),
    )
