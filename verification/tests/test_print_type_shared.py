from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
    assembly_registers,
    native_registers,
    set_assembly_registers,
    store_native_registers,
    symbolic_registers,
)
from verification.harness.rom import linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair, Sm83AddRegister

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
DONE = 0xEFFF
TYPE_NAMES = 0x7DAE


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
    fetched_low: claripy.ast.BV
    fetched_high: claripy.ast.BV
    saved_h: claripy.ast.BV
    saved_l: claripy.ast.BV
    dispatched: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class LoadHL(angr.SimProcedure):
    def __init__(self, value: int, next_address: int) -> None:
        super().__init__()
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = claripy.BVV(self.value >> 8, 8)
        self.state.regs.l = claripy.BVV(self.value & 0xff, 8)
        self.jump(self.next_address)


class CopyAToE(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.e = self.state.regs.a
        self.jump(self.state.addr + 1)


class LoadDImmediate(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.d = claripy.BVV(0, 8)
        self.jump(self.state.addr + 2)


class LoadTableLow(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals["fetched_low"]
        self.state.regs.hl = self.state.regs.hl + 1
        self.jump(self.state.addr + 1)


class LoadTableHigh(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.d = self.state.globals["fetched_high"]
        self.jump(self.state.addr + 1)


class RestoreHL(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = self.state.globals["saved_h"]
        self.state.regs.l = self.state.globals["saved_l"]
        self.jump(self.state.addr + 1)


class Boundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(DONE)


def _assembly(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    loc = symbol_location(SYMBOLS, "PrintType_")
    base = loc.address
    project = angr.Project(
        rom_window(ROM, loc.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": base,
        },
    )
    project.hook(base, Sm83AddRegister("a", base + 1), length=1)
    project.hook(base + 1, LoadHL(TYPE_NAMES, base + 4), length=3)
    project.hook(base + 4, CopyAToE(), length=1)
    project.hook(base + 5, LoadDImmediate(), length=2)
    project.hook(base + 7, Sm83AddHlRegisterPair("de", base + 8), length=1)
    project.hook(base + 8, LoadTableLow(), length=1)
    project.hook(base + 9, CopyAToE(), length=1)
    project.hook(base + 10, LoadTableHigh(), length=1)
    project.hook(base + 11, RestoreHL(), length=1)
    project.hook(base + 12, Boundary(), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, inputs)
    for key in ("fetched_low", "fetched_high", "saved_h", "saved_l"):
        state.globals[key] = inputs[key]
    state.globals["dispatched"] = claripy.BVV(0, 8)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert len(manager.found) == 1
    end = manager.found[0]
    return [
        Endpoint(
            **assembly_registers(end),
            fetched_low=end.globals["fetched_low"],
            fetched_high=end.globals["fetched_high"],
            saved_h=end.globals["saved_h"],
            saved_l=end.globals["saved_l"],
            dispatched=claripy.BVV(1, 8),
            constraints=tuple(end.solver.constraints),
        )
    ]


def _native(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_print_type_")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["fetched_low"])
    state.memory.store(NATIVE_STATE + 9, inputs["fetched_high"])
    state.memory.store(NATIVE_STATE + 10, inputs["saved_h"])
    state.memory.store(NATIVE_STATE + 11, inputs["saved_l"])
    state.memory.store(NATIVE_STATE + 12, claripy.BVV(0, 8))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    end = manager.deadended[0]
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            fetched_low=end.memory.load(NATIVE_STATE + 8, 1),
            fetched_high=end.memory.load(NATIVE_STATE + 9, 1),
            saved_h=end.memory.load(NATIVE_STATE + 10, 1),
            saved_l=end.memory.load(NATIVE_STATE + 11, 1),
            dispatched=end.memory.load(NATIVE_STATE + 12, 1),
            constraints=tuple(end.solver.constraints),
        )
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_print_type_shared_pathwise_equivalence() -> None:
    inputs = symbolic_registers("pts")
    for key in ("fetched_low", "fetched_high", "saved_h", "saved_l"):
        inputs[key] = claripy.BVS(f"pts_{key}", 8)
    assert_pathwise_equivalent(
        _assembly(inputs),
        _native(inputs),
        ("a", "f", "b", "c", "d", "e", "h", "l", "fetched_low", "fetched_high", "saved_h", "saved_l", "dispatched"),
    )


def test_print_type_shared_exact_body() -> None:
    loc = symbol_location(SYMBOLS, "PrintType_")
    assert linked_bytes(ROM, loc, 15) == bytes.fromhex("8721ae7d5f1600192a5f56e1c35519")
