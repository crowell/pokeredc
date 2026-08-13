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
from verification.harness.rom import collect_returns, linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import Sm83DecRegister, Sm83SubRegister


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
STACK = 0xD000
RETURN = 0xFFFF
KEYS = (
    "map_pal_offset",
    "fetched0",
    "fetched1",
    "fetched2",
    "background_palette",
    "object_palette0",
    "object_palette1",
)


class ReadGlobal(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals["map_pal_offset"]
        self.jump(self.next_address)


class Fetch(angr.SimProcedure):
    def __init__(self, index: int, next_address: int) -> None:
        super().__init__()
        self.index = index
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals[f"fetched{self.index}"]
        self.state.regs.hl = self.state.regs.hl + 1
        self.jump(self.next_address)


class StorePalette(angr.SimProcedure):
    def __init__(self, key: str, next_address: int) -> None:
        super().__init__()
        self.key = key
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.globals[self.key] = self.state.regs.a
        self.jump(self.next_address)


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


def inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for key in KEYS:
        values[key] = claripy.BVS(f"{prefix}_{key}", 8)
    return values


def assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "LoadGBPal")
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
    q = location.address
    project.hook(q, ReadGlobal(q + 3), length=3)
    project.hook(q + 8, Sm83SubRegister("b", q + 9), length=1)
    project.hook(q + 12, Sm83DecRegister("h", q + 13), length=1)
    project.hook(q + 13, Fetch(0, q + 14), length=1)
    project.hook(q + 14, StorePalette("background_palette", q + 16), length=2)
    project.hook(q + 16, Fetch(1, q + 17), length=1)
    project.hook(q + 17, StorePalette("object_palette0", q + 19), length=2)
    project.hook(q + 19, Fetch(2, q + 20), length=1)
    project.hook(q + 20, StorePalette("object_palette1", q + 22), length=2)

    state = project.factory.blank_state(addr=q)
    set_assembly_registers(state, values)
    for key in KEYS:
        state.globals[key] = values[key]
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    return [
        Endpoint(
            **assembly_registers(end),
            memory=claripy.Concat(*(end.globals[key] for key in KEYS)),
            constraints=tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, RETURN)
    ]


def native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_load_gb_pal")
    assert function
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(
        NATIVE_STATE + 8, claripy.Concat(*(values[key] for key in KEYS))
    )
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=end.memory.load(NATIVE_STATE + 8, len(KEYS)),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native")
def test_equivalence() -> None:
    values = inputs("load_gb_pal")
    assert_pathwise_equivalent(
        assembly(values), native(values), (*REGISTERS, "memory")
    )


def test_exact_body() -> None:
    location = symbol_location(SYMBOLS, "LoadGBPal")
    assert linked_bytes(ROM, location, 23) == bytes.fromhex(
        "fa5dd3472116217d906f3001252ae0472ae0482ae049c9"
    )
    assert symbol_location(SYMBOLS, "wMapPalOffset").address == 0xD35D
    assert symbol_location(SYMBOLS, "FadePal4").address == 0x2116
