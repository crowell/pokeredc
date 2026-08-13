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
    symbol_location,
)
from verification.harness.sm83_shims import (
    Sm83AddRegister,
    Sm83AndImmediate,
    Sm83CpImmediate,
    Sm83CpRegister,
    Sm83DecRegister,
    Sm83IncRegister,
    Sm83SlaRegister,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
STACK = 0xD000
RETURN = 0xFFFF
KEYS = ("direction", "dividing_line", "first_set", "second_set", "y", "x")


class Fetch(angr.SimProcedure):
    def __init__(self, next_address: int, key: str, increment: bool = False) -> None:
        super().__init__()
        self.next_address = next_address
        self.key = key
        self.increment = increment

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals[self.key]
        if self.increment:
            self.state.regs.hl = self.state.regs.hl + 1
        self.jump(self.next_address)


class FetchSet(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        # Every record starts at an address congruent to 1 mod 4.  After the
        # two HLI reads, set 0 is at residue 3 and set 1 at residue 0.
        self.state.regs.a = claripy.If(
            (self.state.regs.hl & 3) == 3,
            self.state.globals["first_set"],
            self.state.globals["second_set"],
        )
        self.jump(self.next_address)


class IncHl(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.hl = self.state.regs.hl + 1
        self.jump(self.next_address)


@dataclass(frozen=True)
class E:
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


def assembly(values: dict[str, claripy.ast.BV]) -> list[E]:
    location = symbol_location(SYMBOLS, "GetSplitMapSpriteSetID")
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
    for offset, immediate in ((0, 0xF8), (20, 1), (44, 43), (50, 62), (56, 55)):
        project.hook(
            q + offset,
            Sm83CpImmediate(immediate, q + offset + 2),
            length=2,
        )
    project.hook(q + 7, Sm83AndImmediate(0x0F, q + 9), length=2)
    project.hook(q + 9, Sm83DecRegister("a", q + 10), length=1)
    project.hook(q + 10, Sm83SlaRegister("a", q + 12), length=2)
    project.hook(q + 12, Sm83SlaRegister("a", q + 14), length=2)
    project.hook(q + 14, Sm83AddRegister("l", q + 15), length=1)
    project.hook(q + 18, Sm83IncRegister("h", q + 19), length=1)
    project.hook(q + 19, Fetch(q + 20, "direction", True), length=1)
    project.hook(q + 22, Fetch(q + 23, "dividing_line", True), length=1)
    project.hook(q + 26, Fetch(q + 29, "y"), length=3)
    project.hook(q + 31, Fetch(q + 34, "x"), length=3)
    project.hook(q + 34, Sm83CpRegister("b", q + 35), length=1)
    project.hook(q + 37, IncHl(q + 38), length=1)
    project.hook(q + 38, FetchSet(q + 39), length=1)
    for offset in (43, 49, 55):
        project.hook(q + offset, Fetch(q + offset + 1, "x"), length=1)
    project.hook(q + 64, Fetch(q + 67, "y"), length=3)
    project.hook(q + 67, Sm83CpRegister("b", q + 68), length=1)

    state = project.factory.blank_state(addr=q)
    set_assembly_registers(state, values)
    for key in KEYS:
        state.globals[key] = values[key]
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    ends = collect_returns(project, state, RETURN)
    memory = claripy.Concat(*(values[key] for key in KEYS))
    return [
        E(
            **assembly_registers(end),
            memory=memory,
            constraints=tuple(end.solver.constraints),
        )
        for end in ends
    ]


def native(values: dict[str, claripy.ast.BV]) -> list[E]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_get_split_map_sprite_set_id")
    assert function
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(
        NATIVE_STATE + 8,
        claripy.Concat(*(values[key] for key in KEYS)),
    )
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        E(
            **native_registers(end, NATIVE_STATE),
            memory=end.memory.load(NATIVE_STATE + 8, len(KEYS)),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native")
def test_equivalence() -> None:
    values = inputs("split_sprite_set")
    assert_pathwise_equivalent(
        assembly(values), native(values), (*REGISTERS, "memory")
    )


def test_exact_body() -> None:
    location = symbol_location(SYMBOLS, "GetSplitMapSpriteSetID")
    assert linked_bytes(ROM, location, 74) == bytes.fromhex(
        "fef8282421897ae60f3dcb27cb27856f3001242afe012a472805fa61d31803"
        "fa62d3b83801237ec92162d37efe2b3e01d87efe3e3e0ad07efe3706083002"
        "060dfa61d3b83e0ad83e01c9"
    )
