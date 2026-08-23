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
from verification.harness.sm83_shims import (
    Sm83AddHlRegisterPair,
    Sm83CpImmediate,
    Sm83CpRegister,
    Sm83IncRegister,
    Sm83Scf,
)


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x400000
ARRAY = 0xC100
FOUND = 0xEFFE
NOT_FOUND = 0xEFFF


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
    result: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class AndA(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x50, 8),
            claripy.BVV(0x10, 8),
        )
        self.jump(self._next_address)


class Boundary(angr.SimProcedure):
    def __init__(self, address: int) -> None:
        super().__init__()
        self._address = address

    def run(self) -> None:  # type: ignore[override]
        self.jump(self._address)


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "IsInArray")
    base = location.address
    project = angr.Project(
        rom_window(ROM, location.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": base,
        },
    )
    project.hook(base + 4, Sm83CpImmediate(0xFF, base + 6), length=2)
    project.hook(base + 8, Sm83CpRegister("c", base + 9), length=1)
    project.hook(base + 11, Sm83IncRegister("b", base + 12), length=1)
    project.hook(base + 12, Sm83AddHlRegisterPair("de", base + 13), length=1)
    project.hook(base + 15, AndA(base + 16), length=1)
    project.hook(base + 16, Boundary(NOT_FOUND), length=1)
    project.hook(base + 17, Sm83Scf(base + 18), length=1)
    project.hook(base + 18, Boundary(FOUND), length=1)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.memory.store(ARRAY, values["array"])
    manager = project.factory.simulation_manager(state)
    manager.stashes["found"] = []
    while manager.active:
        manager.move(
            from_stash="active",
            to_stash="found",
            filter_func=lambda end: end.addr in {FOUND, NOT_FOUND},
        )
        if manager.active:
            manager.step()
    assert not manager.errored
    return [
        Endpoint(
            **assembly_registers(end),
            result=claripy.BVV(1 if end.addr == FOUND else 2, 8),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_is_in_array")
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_MEMORY + ARRAY, values["array"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            result=end.regs.rax[7:0],
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run red")
def test_is_in_array_pathwise_equivalence() -> None:
    values = symbolic_registers("is_in_array")
    values["d"] = claripy.BVV(0, 8)
    values["e"] = claripy.BVV(1, 8)
    values["h"] = claripy.BVV(ARRAY >> 8, 8)
    values["l"] = claripy.BVV(ARRAY & 0xFF, 8)
    values["array"] = claripy.Concat(
        claripy.BVS("is_in_array_entry_0", 8),
        claripy.BVS("is_in_array_entry_1", 8),
        claripy.BVS("is_in_array_entry_2", 8),
        claripy.BVV(0xFF, 8),
    )
    assert_pathwise_equivalent(
        _assembly(values), _native(values), (*REGISTERS, "result")
    )
