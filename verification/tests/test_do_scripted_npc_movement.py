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
from verification.harness.rom import linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import (
    Sm83AddImmediate,
    Sm83AddRegister,
    Sm83BitAtHl,
    Sm83BitRegister,
    Sm83CpImmediate,
    Sm83DecAtHl,
    Sm83SetAtHl,
    Sm83StoreAImmediate,
)


ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification" / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xd000
RETURN = 0xffff
S1 = 0xc100
S2 = 0xc200
STATUS4 = 0xd72e
STATUS5 = 0xd730
DIRECTIONS = 0xcc97
INDEX = 0xcd37
COUNTER = 0xcf18
OFFSET = 0xffda
SLOT = 0xffe9
FRAME = 0xffea
BODY = bytes.fromhex(
    "fa30d7cb7fc8212ed7cb7ecbfecaa6522197ccfa37cd856f3001247efe402009"
    "cdb2520e043efe182afe002009cdb2520e003e02181dfe802009cdb7520e083e"
    "fe1810fec02009cdb7520e0c3e021803feffc9477e8077f0dac6096f7977cdc3"
    "522118cf35c03e08ea18cf2137cd34c9"
)


@dataclass(frozen=True)
class Scenario:
    name: str
    status5: int
    status4: int
    direction: int
    counter: int


SCENARIOS = (
    Scenario("disabled", 0, 0, 0, 2),
    Scenario("initialize", 0x80, 0, 0, 2),
    Scenario("down_step", 0x80, 0x80, 0, 2),
    Scenario("down_counter_rollover", 0x80, 0x80, 0, 1),
    Scenario("unrecognized_direction", 0x80, 0x80, 1, 2),
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
    state: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class LoadAbsolute(angr.SimProcedure):
    def __init__(self, address: int, next_address: int) -> None:
        super().__init__()
        self.address = address
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self.address, 1)
        self.jump(self.next_address)


class LoadHigh(angr.SimProcedure):
    def __init__(self, address: int, next_address: int) -> None:
        super().__init__()
        self.address = address
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self.address, 1)
        self.jump(self.next_address)


class LoadAtHL(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self.state.regs.hl, 1)
        self.jump(self.next_address)


class StoreAtHL(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(self.state.regs.hl, self.state.regs.a)
        self.jump(self.next_address)


class IncAtHL(angr.SimProcedure):
    """SM83's INC [HL], including its carry-preserving flags."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        previous = self.state.memory.load(self.state.regs.hl, 1)
        result = previous + 1
        self.state.memory.store(self.state.regs.hl, result)
        self.state.regs.f = (self.state.regs.f & 1) | claripy.If(
            result == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)
        ) | claripy.If(
            (previous & 0x0f) == 0x0f,
            claripy.BVV(0x10, 8),
            claripy.BVV(0, 8),
        )
        self.jump(self.next_address)


class Pair(angr.SimProcedure):
    def __init__(self, value: int, next_address: int) -> None:
        super().__init__()
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = claripy.BVV(self.value >> 8, 8)
        self.state.regs.l = claripy.BVV(self.value & 0xff, 8)
        self.jump(self.next_address)


class BranchZ(angr.SimProcedure):
    def __init__(self, when_set: int, when_clear: int) -> None:
        super().__init__()
        self.when_set = when_set
        self.when_clear = when_clear

    def run(self) -> None:  # type: ignore[override]
        condition = (self.state.regs.f & 0x40) != 0
        yes = self.state.copy()
        no = self.state.copy()
        yes.solver.add(condition)
        no.solver.add(~condition)
        yes.regs.ip = claripy.BVV(self.when_set, 16)
        no.regs.ip = claripy.BVV(self.when_clear, 16)
        self.inhibit_autoret = True
        self.successors.add_successor(yes, self.when_set, condition, "Ijk_Boring")
        self.successors.add_successor(no, self.when_clear, ~condition, "Ijk_Boring")


class BranchCarry(angr.SimProcedure):
    def __init__(self, when_set: int, when_clear: int) -> None:
        super().__init__()
        self.when_set = when_set
        self.when_clear = when_clear

    def run(self) -> None:  # type: ignore[override]
        condition = (self.state.regs.f & 1) != 0
        yes = self.state.copy()
        no = self.state.copy()
        yes.solver.add(condition)
        no.solver.add(~condition)
        yes.regs.ip = claripy.BVV(self.when_set, 16)
        no.regs.ip = claripy.BVV(self.when_clear, 16)
        self.inhibit_autoret = True
        self.successors.add_successor(yes, self.when_set, condition, "Ijk_Boring")
        self.successors.add_successor(no, self.when_clear, ~condition, "Ijk_Boring")


class PointerYBoundary(angr.SimProcedure):
    """Complete GetSpriteScreenYPointer tail through its proven common helper."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        offset = self.state.memory.load(OFFSET, 1)
        self.state.regs.a = offset + 4
        self.state.regs.b = claripy.BVV(4, 8)
        self.state.regs.h = claripy.BVV(0xc1, 8)
        self.state.regs.l = self.state.regs.a
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)
        ) | claripy.If(
            (offset & 0x0f) + 4 > 0x0f,
            claripy.BVV(0x10, 8),
            claripy.BVV(0, 8),
        ) | claripy.ZeroExt(7, claripy.ZeroExt(1, offset + 4)[8])
        self.jump(self.next_address)


class AnimDownBoundary(angr.SimProcedure):
    """Complete valid-facing/down, non-rollover animation transition."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.b = claripy.BVV(0, 8)
        self.state.regs.h = claripy.BVV(0xc1, 8)
        self.state.regs.l = claripy.BVV(7, 8)
        self.state.memory.store(S1 + 7, claripy.BVV(1, 8))
        self.state.regs.l = claripy.BVV(2, 8)
        self.state.memory.store(S1 + 2, claripy.BVV(0, 8))
        self.state.regs.f = claripy.BVV(0x40, 8)
        self.jump(self.next_address)


class InitBoundary(angr.SimProcedure):
    """Complete initializer tail in the down/non-rollover composition domain."""

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.memory.store(INDEX, self.state.regs.a)
        self.state.regs.a = claripy.BVV(8, 8)
        self.state.memory.store(COUNTER, self.state.regs.a)
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.b = claripy.BVV(0, 8)
        self.state.regs.h = claripy.BVV(0xc1, 8)
        self.state.regs.l = claripy.BVV(2, 8)
        self.state.memory.store(S1 + 7, claripy.BVV(1, 8))
        self.state.memory.store(S1 + 2, claripy.BVV(0, 8))
        self.state.regs.f = claripy.BVV(0x40, 8)
        self.jump(RETURN)


def setup(
    state: angr.SimState,
    base: int,
    scenario: Scenario,
    coordinate: claripy.ast.BV,
) -> None:
    for address in (*range(S1, S1 + 16), *range(S2, S2 + 16)):
        state.memory.store(base + address, claripy.BVV(0, 8))
    for address, value in (
        (OFFSET, 0),
        (S1 + 4, coordinate),
        (S1 + 9, 0),
        (S2 + 14, 1),
        (SLOT, 0),
        (FRAME, 0),
        (STATUS4, scenario.status4),
        (STATUS5, scenario.status5),
        (DIRECTIONS, scenario.direction),
        (INDEX, 0),
        (COUNTER, scenario.counter),
    ):
        state.memory.store(
            base + address,
            value if isinstance(value, claripy.ast.BV) else claripy.BVV(value, 8),
        )


def endpoint(state: angr.SimState, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    registers = (
        native_registers(state, NATIVE_STATE)
        if native
        else assembly_registers(state)
    )
    watched = (
        *range(S1, S1 + 16),
        *range(S2, S2 + 16),
        STATUS4,
        STATUS5,
        DIRECTIONS,
        INDEX,
        COUNTER,
        OFFSET,
        SLOT,
        FRAME,
    )
    return Endpoint(
        **registers,
        state=claripy.Concat(*(state.memory.load(base + address, 1) for address in watched)),
        constraints=tuple(state.solver.constraints),
    )


def assembly(
    inputs: dict[str, claripy.ast.BV], scenario: Scenario
) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "DoScriptedNPCMovement")
    initializer = symbol_location(SYMBOLS, "InitScriptedNPCMovement")
    assert linked_bytes(ROM, location, len(BODY)) == BODY
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
    start = location.address
    project.hook(start, LoadAbsolute(STATUS5, start + 3), length=3)
    project.hook(start + 3, Sm83BitRegister(7, "a", start + 5), length=2)
    project.hook(start + 5, BranchZ(RETURN, start + 6), length=1)
    project.hook(start + 6, Pair(STATUS4, start + 9), length=3)
    project.hook(start + 9, Sm83BitAtHl(7, start + 11), length=2)
    project.hook(start + 11, Sm83SetAtHl(7, start + 13), length=2)
    project.hook(start + 13, BranchZ(initializer.address, start + 16), length=3)
    project.hook(initializer.address, InitBoundary(), length=1)
    project.hook(start + 16, Pair(DIRECTIONS, start + 19), length=3)
    project.hook(start + 19, LoadAbsolute(INDEX, start + 22), length=3)
    project.hook(start + 22, Sm83AddRegister("l", start + 23), length=1)
    project.hook(start + 24, BranchCarry(start + 26, start + 27), length=2)
    project.hook(start + 27, LoadAtHL(start + 28), length=1)
    for offset, immediate, when_equal, when_unequal in (
        (28, 0x40, start + 32, start + 41),
        (41, 0x00, start + 45, start + 54),
        (54, 0x80, start + 58, start + 67),
        (67, 0xc0, start + 71, start + 80),
    ):
        project.hook(
            start + offset,
            Sm83CpImmediate(immediate, start + offset + 2),
            length=2,
        )
        project.hook(
            start + offset + 2,
            BranchZ(when_equal, when_unequal),
            length=2,
        )
    project.hook(start + 45, PointerYBoundary(start + 48), length=3)
    project.hook(start + 80, Sm83CpImmediate(0xff, start + 82), length=2)
    project.hook(start + 82, BranchZ(RETURN, RETURN), length=1)
    project.hook(start + 84, LoadAtHL(start + 85), length=1)
    project.hook(start + 85, Sm83AddRegister("b", start + 86), length=1)
    project.hook(start + 86, StoreAtHL(start + 87), length=1)
    project.hook(start + 87, LoadHigh(OFFSET, start + 89), length=2)
    project.hook(start + 89, Sm83AddImmediate(9, start + 91), length=2)
    project.hook(start + 93, StoreAtHL(start + 94), length=1)
    project.hook(start + 94, AnimDownBoundary(start + 97), length=3)
    project.hook(start + 97, Pair(COUNTER, start + 100), length=3)
    project.hook(start + 100, Sm83DecAtHl(start + 101), length=1)
    project.hook(start + 101, BranchZ(start + 102, RETURN), length=1)
    project.hook(start + 104, Sm83StoreAImmediate(COUNTER, start + 107), length=3)
    project.hook(start + 107, Pair(INDEX, start + 110), length=3)
    project.hook(start + 110, IncAtHL(start + 111), length=1)

    state = project.factory.blank_state(addr=start)
    set_assembly_registers(state, inputs)
    setup(state, 0, scenario, inputs["coordinate"])
    state.regs.sp = claripy.BVV(STACK, 16)
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN, num_find=4)
    assert not manager.errored and manager.found
    return [endpoint(found, False) for found in manager.found]


def native(inputs: dict[str, claripy.ast.BV], scenario: Scenario) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_do_scripted_npc_movement")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, inputs)
    setup(state, NATIVE_MEMORY, scenario, inputs["coordinate"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and manager.deadended
    return [endpoint(deadended, True) for deadended in manager.deadended]


@pytest.mark.skipif(
    not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),
    reason="build artifacts missing",
)
@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda scenario: scenario.name)
def test_do_scripted_npc_movement_pathwise_equivalence(scenario: Scenario) -> None:
    inputs = symbolic_registers(f"scripted_npc_{scenario.name}")
    inputs["coordinate"] = claripy.BVS(
        f"scripted_npc_{scenario.name}_coordinate", 8
    )
    assert_pathwise_equivalent(
        assembly(inputs, scenario),
        native(inputs, scenario),
        (*REGISTERS, "state"),
    )
