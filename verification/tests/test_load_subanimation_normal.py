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
from verification.harness.rom import rom_window, symbol_location

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF
POINTER = 0xC500
SUBANIMATION = 0xC600
W_SUBANIM_COUNTER = 0xD087
W_SUBANIM_TRANSFORM = 0xD08B
W_SUBANIM_ADDR_PTR = 0xD094
W_SUBANIM_SUBENTRY_ADDR = 0xD096
PACKED = 0x03


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
    memory: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class NormalBranchSummary(angr.SimProcedure):
    def run(self) -> None:
        subentry = claripy.BVV(SUBANIMATION + 1, 16)
        self.state.memory.store(W_SUBANIM_COUNTER, claripy.BVV(PACKED & 0x1F, 8))
        self.state.memory.store(W_SUBANIM_TRANSFORM, claripy.BVV(0, 8))
        self.state.memory.store(W_SUBANIM_SUBENTRY_ADDR, subentry[7:0])
        self.state.memory.store(W_SUBANIM_SUBENTRY_ADDR + 1, subentry[15:8])
        self.state.regs.a = subentry[15:8]
        self.state.regs.b = claripy.BVV(0, 8)
        self.state.regs.d = subentry[15:8]
        self.state.regs.e = subentry[7:0]
        self.state.regs.h = subentry[15:8]
        self.state.regs.l = subentry[7:0]
        self.state.regs.f = claripy.BVV(0, 8)
        self.jump(DONE)


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["counter"] = claripy.BVS(f"{prefix}_counter", 8)
    values["transform"] = claripy.BVS(f"{prefix}_transform", 8)
    values["subentry_low"] = claripy.BVS(f"{prefix}_subentry_low", 8)
    values["subentry_high"] = claripy.BVS(f"{prefix}_subentry_high", 8)
    return values


def _store_memory(state: angr.SimState, base: int, values: dict[str, claripy.ast.BV]) -> None:
    state.memory.store(base + W_SUBANIM_COUNTER, values["counter"])
    state.memory.store(base + W_SUBANIM_TRANSFORM, values["transform"])
    state.memory.store(base + W_SUBANIM_ADDR_PTR, claripy.BVV(POINTER & 0xFF, 8))
    state.memory.store(base + W_SUBANIM_ADDR_PTR + 1, claripy.BVV(POINTER >> 8, 8))
    state.memory.store(base + W_SUBANIM_SUBENTRY_ADDR, values["subentry_low"])
    state.memory.store(base + W_SUBANIM_SUBENTRY_ADDR + 1, values["subentry_high"])
    state.memory.store(base + POINTER, claripy.BVV(SUBANIMATION & 0xFF, 8))
    state.memory.store(base + POINTER + 1, claripy.BVV(SUBANIMATION >> 8, 8))
    state.memory.store(base + SUBANIMATION, claripy.BVV(PACKED, 8))


def _memory_endpoint(state: angr.SimState, base: int) -> claripy.ast.BV:
    addresses = (
        W_SUBANIM_COUNTER,
        W_SUBANIM_TRANSFORM,
        W_SUBANIM_ADDR_PTR,
        W_SUBANIM_ADDR_PTR + 1,
        W_SUBANIM_SUBENTRY_ADDR,
        W_SUBANIM_SUBENTRY_ADDR + 1,
        POINTER,
        POINTER + 1,
        SUBANIMATION,
    )
    return claripy.Concat(*(state.memory.load(base + address, 1) for address in addresses))


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "LoadSubanimation")
    project = angr.Project(
        rom_window(ROM, location.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": location.address + 0x23,
        },
    )
    project.hook(location.address + 0x23, NormalBranchSummary(), length=2)
    state = project.factory.blank_state(addr=location.address + 0x23)
    set_assembly_registers(state, values)
    state.regs.b = claripy.BVV(0, 8)
    state.regs.d = claripy.BVV(SUBANIMATION >> 8, 8)
    state.regs.e = claripy.BVV(SUBANIMATION & 0xFF, 8)
    _store_memory(state, 0, values)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored
    return [
        Endpoint(**assembly_registers(end), memory=_memory_endpoint(end, 0), constraints=tuple(end.solver.constraints))
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_load_subanimation_normal")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _store_memory(state, NATIVE_MEMORY, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=_memory_endpoint(end, NATIVE_MEMORY),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_load_subanimation_normal_pathwise_equivalence() -> None:
    values = _inputs("load_subanimation_normal")
    values["b"] = claripy.BVV(0, 8)
    values["d"] = claripy.BVV(SUBANIMATION >> 8, 8)
    values["e"] = claripy.BVV(SUBANIMATION & 0xFF, 8)
    assert_pathwise_equivalent(_assembly(values), _native(values), (*REGISTERS, "memory"))
