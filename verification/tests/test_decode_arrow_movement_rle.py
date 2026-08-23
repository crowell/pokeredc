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
    Sm83CpImmediate,
    Sm83CpRegister,
    Sm83DecRegister,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF
MARKER = 0x1234
OUTPUT = 0xCCD3
EXPECTED_BODY = bytes.fromhex(
    "2afeffc8b820122ab9200f2a565f21d3cccd0c353dea38cdc923232318e2"
)
FETCHED_FIELDS = (
    "fetched_y",
    "fetched_x",
    "fetched_pointer_low",
    "fetched_pointer_high",
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
    result: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class FetchHli(angr.SimProcedure):
    def __init__(self, field: str, continuation: int) -> None:
        super().__init__()
        self.field = field
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals[self.field]
        self.state.regs.hl = self.state.regs.hl + 1
        self.jump(self.continuation)


class FetchD(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.d = self.state.globals["fetched_pointer_high"]
        self.jump(self.continuation)


class SetHl(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.hl = claripy.BVV(OUTPUT, 16)
        self.jump(self.continuation)


class StoreIndex(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["simulated_index"] = self.state.regs.a
        self.jump(self.continuation)


class Boundary(angr.SimProcedure):
    def __init__(self, result: int) -> None:
        super().__init__()
        self.result = result

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["result"] = claripy.BVV(self.result, 8)
        self.jump(DONE)


class ReturnIfZero(angr.SimProcedure):
    def __init__(self, fallthrough: int) -> None:
        super().__init__()
        self.fallthrough = fallthrough

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        condition = (self.state.regs.f & 0x40) != 0
        taken = self.state.copy()
        taken.globals["result"] = claripy.BVV(0, 8)
        self.successors.add_successor(taken, DONE, condition, "Ijk_Boring")
        self.successors.add_successor(
            self.state.copy(),
            self.fallthrough,
            claripy.Not(condition),
            "Ijk_Boring",
        )


class DecodeRleSummary(angr.SimProcedure):
    """Arbitrary transition supplied by the proven DecodeRLEList."""

    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        call = assembly_registers(self.state)
        self.state.globals["call_registers"] = claripy.Concat(
            *(call[register] for register in REGISTERS)
        )
        for register in REGISTERS:
            value = self.state.globals[f"decoder_{register}"]
            if register == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, register, value)
        self.state.globals["byte_count"] = self.state.globals[
            "decoder_byte_count"
        ]
        self.state.globals["byte_value"] = self.state.globals[
            "decoder_byte_value"
        ]
        self.state.memory.store(MARKER, self.state.globals["decoder_marker"])
        self.jump(self.continuation)


class NativeDecodeRleSummary(angr.SimProcedure):
    """Native-ABI form of the same independently proven transition."""

    def run(
        self, rle: claripy.ast.BV, memory: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        self.state.globals["call_registers"] = self.state.memory.load(rle, 8)
        for offset, register in enumerate(REGISTERS):
            self.state.memory.store(
                rle + offset, self.state.globals[f"decoder_{register}"]
            )
        self.state.memory.store(
            rle + 11, self.state.globals["decoder_byte_count"]
        )
        self.state.memory.store(
            rle + 12, self.state.globals["decoder_byte_value"]
        )
        self.state.memory.store(
            memory + MARKER, self.state.globals["decoder_marker"]
        )


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["byte_count"] = claripy.BVS(f"{prefix}_byte_count", 8)
    values["byte_value"] = claripy.BVS(f"{prefix}_byte_value", 8)
    values["simulated_index"] = claripy.BVS(f"{prefix}_simulated_index", 8)
    for field in FETCHED_FIELDS:
        values[field] = claripy.BVS(f"{prefix}_{field}", 8)
    values["marker"] = claripy.BVS(f"{prefix}_marker", 8)
    for register in REGISTERS:
        values[f"decoder_{register}"] = (
            claripy.Concat(
                claripy.BVS(f"{prefix}_decoder_flags", 4), claripy.BVV(0, 4)
            )
            if register == "f"
            else claripy.BVS(f"{prefix}_decoder_{register}", 8)
        )
    values["decoder_byte_count"] = claripy.BVS(
        f"{prefix}_decoder_byte_count", 8
    )
    values["decoder_byte_value"] = claripy.BVS(
        f"{prefix}_decoder_byte_value", 8
    )
    values["decoder_marker"] = claripy.BVS(f"{prefix}_decoder_marker", 8)
    return values


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "DecodeArrowMovementRLE")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY
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
    project.hook(base, FetchHli("fetched_y", base + 1), length=1)
    project.hook(base + 1, Sm83CpImmediate(0xFF, base + 3), length=2)
    project.hook(base + 3, ReturnIfZero(base + 4), length=1)
    project.hook(base + 4, Sm83CpRegister("b", base + 5), length=1)
    project.hook(base + 7, FetchHli("fetched_x", base + 8), length=1)
    project.hook(base + 8, Sm83CpRegister("c", base + 9), length=1)
    project.hook(
        base + 11, FetchHli("fetched_pointer_low", base + 12), length=1
    )
    project.hook(base + 12, FetchD(base + 13), length=1)
    project.hook(base + 14, SetHl(base + 17), length=3)
    project.hook(base + 17, DecodeRleSummary(base + 20), length=3)
    project.hook(base + 20, Sm83DecRegister("a", base + 21), length=1)
    project.hook(base + 21, StoreIndex(base + 24), length=3)
    project.hook(base + 24, Boundary(2), length=1)
    project.hook(base + 28, Boundary(1), length=2)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.globals["byte_count"] = values["byte_count"]
    state.globals["byte_value"] = values["byte_value"]
    state.globals["simulated_index"] = values["simulated_index"]
    for field in FETCHED_FIELDS:
        state.globals[field] = values[field]
    for register in REGISTERS:
        state.globals[f"decoder_{register}"] = values[f"decoder_{register}"]
    for field in ("decoder_byte_count", "decoder_byte_value", "decoder_marker"):
        state.globals[field] = values[field]
    state.globals["call_registers"] = claripy.BVV(0, 64)
    state.globals["result"] = claripy.BVV(0, 8)
    state.memory.store(MARKER, values["marker"])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=10)
    return [
        Endpoint(
            **assembly_registers(end),
            state_memory=claripy.Concat(
                end.globals["byte_count"],
                end.globals["byte_value"],
                end.globals["simulated_index"],
            ),
            call_registers=end.globals["call_registers"],
            marker=end.memory.load(MARKER, 1),
            result=end.globals["result"],
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_decode_arrow_movement_rle_step")
    decoder = project.loader.find_symbol("port_decode_rle_list")
    assert function is not None and decoder is not None
    project.hook(decoder.rebased_addr, NativeDecodeRleSummary())
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 11, values["byte_count"])
    state.memory.store(NATIVE_STATE + 12, values["byte_value"])
    state.memory.store(NATIVE_STATE + 15, values["simulated_index"])
    for offset, field in enumerate(FETCHED_FIELDS, 16):
        state.memory.store(NATIVE_STATE + offset, values[field])
    for register in REGISTERS:
        state.globals[f"decoder_{register}"] = values[f"decoder_{register}"]
    for field in ("decoder_byte_count", "decoder_byte_value", "decoder_marker"):
        state.globals[field] = values[field]
    state.globals["call_registers"] = claripy.BVV(0, 64)
    state.memory.store(NATIVE_MEMORY + MARKER, values["marker"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            state_memory=claripy.Concat(
                end.memory.load(NATIVE_STATE + 11, 2),
                end.memory.load(NATIVE_STATE + 15, 1),
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
def test_decode_arrow_movement_rle_pathwise_equivalence() -> None:
    values = _inputs("decode_arrow_movement_rle")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "state_memory", "call_registers", "marker", "result"),
    )
