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
    Sm83AddRegister,
    Sm83CpImmediate,
    Sm83IncRegister,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF
MARKER = 0x1234
FIELDS = ("byte_count", "byte_value", "fetched_value", "fetched_repetitions")
EXPECTED_BODY = bytes.fromhex(
    "afead2cc1afeff2816e08b131a06004ffad2cc81ead2ccf08bcde0361318e53eff77fad2cc3cc9"
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
    state_memory: claripy.ast.BV
    call_registers: claripy.ast.BV
    marker: claripy.ast.BV
    sentinel: claripy.ast.BV
    result: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class ZeroA(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x40, 8)
        self.jump(self.continuation)


class LoadField(angr.SimProcedure):
    def __init__(self, field: str, continuation: int) -> None:
        super().__init__()
        self.field = field
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals[self.field]
        self.jump(self.continuation)


class StoreField(angr.SimProcedure):
    def __init__(self, field: str, continuation: int) -> None:
        super().__init__()
        self.field = field
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.globals[self.field] = self.state.regs.a
        self.jump(self.continuation)


class Boundary(angr.SimProcedure):
    def __init__(self, result: int) -> None:
        super().__init__()
        self.result = result

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["result"] = claripy.BVV(self.result, 8)
        self.jump(DONE)


class FillMemorySummary(angr.SimProcedure):
    """Arbitrary transition supplied by the independently proven FillMemory."""

    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        call = assembly_registers(self.state)
        self.state.globals["call_registers"] = claripy.Concat(
            *(call[register] for register in REGISTERS)
        )
        for register in REGISTERS:
            value = self.state.globals[f"fill_{register}"]
            if register == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, register, value)
        self.state.memory.store(MARKER, self.state.globals["fill_marker"])
        self.jump(self.continuation)


class NativeFillMemorySummary(angr.SimProcedure):
    """Native-ABI form of the same independently proven transition."""

    def run(
        self, fill: claripy.ast.BV, memory: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        self.state.globals["call_registers"] = self.state.memory.load(fill, 8)
        for offset, register in enumerate(REGISTERS):
            self.state.memory.store(
                fill + offset, self.state.globals[f"fill_{register}"]
            )
        self.state.memory.store(memory + MARKER, self.state.globals["fill_marker"])


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["saved_d"] = claripy.BVS(f"{prefix}_saved_d", 8)
    values["saved_e"] = claripy.BVS(f"{prefix}_saved_e", 8)
    values["written"] = claripy.BVS(f"{prefix}_written", 8)
    for field in FIELDS:
        values[field] = claripy.BVS(f"{prefix}_{field}", 8)
    values["marker"] = claripy.BVS(f"{prefix}_marker", 8)
    values["sentinel_before"] = claripy.BVS(f"{prefix}_sentinel_before", 8)
    for register in REGISTERS:
        values[f"fill_{register}"] = (
            claripy.Concat(
                claripy.BVS(f"{prefix}_fill_flags", 4), claripy.BVV(0, 4)
            )
            if register == "f"
            else claripy.BVS(f"{prefix}_fill_{register}", 8)
        )
    values["fill_marker"] = claripy.BVS(f"{prefix}_fill_marker", 8)
    return values


def _project() -> tuple[int, angr.Project]:
    location = symbol_location(SYMBOLS, "DecodeRLEList")
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
    return location.address, project


def _setup_assembly(
    state: angr.SimState, values: dict[str, claripy.ast.BV]
) -> None:
    set_assembly_registers(state, values)
    for field in FIELDS:
        state.globals[field] = values[field]
    for register in REGISTERS:
        state.globals[f"fill_{register}"] = values[f"fill_{register}"]
    state.globals["fill_marker"] = values["fill_marker"]
    state.globals["call_registers"] = claripy.BVV(0, 64)
    state.globals["result"] = claripy.BVV(0, 8)
    state.memory.store(MARKER, values["marker"])


def _assembly_endpoint(end: angr.SimState, sentinel: claripy.ast.BV) -> Endpoint:
    return Endpoint(
        **assembly_registers(end),
        state_memory=claripy.Concat(*(end.globals[field] for field in FIELDS)),
        call_registers=end.globals["call_registers"],
        marker=end.memory.load(MARKER, 1),
        sentinel=sentinel,
        result=end.globals["result"],
        constraints=tuple(end.solver.constraints),
    )


def _assembly_begin(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    base, project = _project()
    project.hook(base, ZeroA(base + 1), length=1)
    project.hook(base + 1, StoreField("byte_count", base + 4), length=3)
    project.hook(base + 4, Boundary(2), length=0)
    state = project.factory.blank_state(addr=base)
    _setup_assembly(state, values)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE)
    return [
        _assembly_endpoint(end, values["sentinel_before"])
        for end in manager.found
    ]


def _assembly_step(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    base, project = _project()
    project.hook(base + 4, LoadField("fetched_value", base + 5), length=1)
    project.hook(base + 5, Sm83CpImmediate(0xFF, base + 7), length=2)
    project.hook(base + 9, StoreField("byte_value", base + 11), length=2)
    project.hook(
        base + 12, LoadField("fetched_repetitions", base + 13), length=1
    )
    project.hook(base + 16, LoadField("byte_count", base + 19), length=3)
    project.hook(base + 19, Sm83AddRegister("c", base + 20), length=1)
    project.hook(base + 20, StoreField("byte_count", base + 23), length=3)
    project.hook(base + 23, LoadField("byte_value", base + 25), length=2)
    project.hook(base + 25, FillMemorySummary(base + 28), length=3)
    project.hook(base + 29, Boundary(1), length=2)
    project.hook(base + 31, Boundary(0), length=0)
    state = project.factory.blank_state(addr=base + 4)
    _setup_assembly(state, values)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=10)
    return [
        _assembly_endpoint(end, values["sentinel_before"])
        for end in manager.found
    ]


def _assembly_finish(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    base, project = _project()
    project.hook(base + 34, LoadField("byte_count", base + 37), length=3)
    project.hook(base + 37, Sm83IncRegister("a", base + 38), length=1)
    project.hook(base + 38, Boundary(3), length=1)
    state = project.factory.blank_state(addr=base + 31)
    _setup_assembly(state, values)
    address = claripy.Concat(values["h"], values["l"])
    state.memory.store(address, values["sentinel_before"])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE)
    return [
        _assembly_endpoint(end, end.memory.load(address, 1))
        for end in manager.found
    ]


def _setup_native(
    state: angr.SimState, values: dict[str, claripy.ast.BV]
) -> None:
    store_native_registers(state, NATIVE_STATE, values)
    for offset, field in enumerate(("saved_d", "saved_e", "written"), 8):
        state.memory.store(NATIVE_STATE + offset, values[field])
    for offset, field in enumerate(FIELDS, 11):
        state.memory.store(NATIVE_STATE + offset, values[field])
    for register in REGISTERS:
        state.globals[f"fill_{register}"] = values[f"fill_{register}"]
    state.globals["fill_marker"] = values["fill_marker"]
    state.globals["call_registers"] = claripy.BVV(0, 64)
    state.memory.store(NATIVE_MEMORY + MARKER, values["marker"])


def _native_endpoint(
    end: angr.SimState, result: claripy.ast.BV, sentinel: claripy.ast.BV
) -> Endpoint:
    return Endpoint(
        **native_registers(end, NATIVE_STATE),
        state_memory=end.memory.load(NATIVE_STATE + 11, len(FIELDS)),
        call_registers=end.globals["call_registers"],
        marker=end.memory.load(NATIVE_MEMORY + MARKER, 1),
        sentinel=sentinel,
        result=result,
        constraints=tuple(end.solver.constraints),
    )


def _native(
    values: dict[str, claripy.ast.BV], symbol: str, result: int | None
) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(symbol)
    fill_memory = project.loader.find_symbol("port_fill_memory")
    assert function is not None and fill_memory is not None
    if symbol.endswith("_step"):
        project.hook(fill_memory.rebased_addr, NativeFillMemorySummary())
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    _setup_native(state, values)
    address = claripy.Concat(values["h"], values["l"])
    native_address = claripy.ZeroExt(48, address) + NATIVE_MEMORY
    state.memory.store(native_address, values["sentinel_before"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        _native_endpoint(
            end,
            end.regs.rax[7:0] if result is None else claripy.BVV(result, 8),
            end.memory.load(native_address, 1),
        )
        for end in manager.deadended
    ]


OBSERVABLES = (
    *REGISTERS,
    "state_memory",
    "call_registers",
    "marker",
    "sentinel",
    "result",
)


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_decode_rle_list_pathwise_equivalence() -> None:
    location = symbol_location(SYMBOLS, "DecodeRLEList")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY

    begin_values = _inputs("decode_rle_list_begin")
    assert_pathwise_equivalent(
        _assembly_begin(begin_values),
        _native(begin_values, "port_decode_rle_list_begin", 2),
        OBSERVABLES,
    )

    step_values = _inputs("decode_rle_list_step")
    assert_pathwise_equivalent(
        _assembly_step(step_values),
        _native(step_values, "port_decode_rle_list_step", None),
        OBSERVABLES,
    )

    finish_values = _inputs("decode_rle_list_finish")
    finish_values["a"] = claripy.BVV(0xFF, 8)
    finish_values["f"] = claripy.BVV(0xC0, 8)
    assert_pathwise_equivalent(
        _assembly_finish(finish_values),
        _native(finish_values, "port_decode_rle_list_finish", 3),
        OBSERVABLES,
    )
