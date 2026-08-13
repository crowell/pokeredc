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
    Sm83AddImmediate,
    Sm83AddRegister,
    Sm83BitRegister,
)


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
STACK = 0xD000
RETURN = 0xFFFF
STATUS = 0xD72D
DIRECTION = 0xD52A
OFFSET = 0xFFDA
TILE = 0xFF93


def direction_value(direction: claripy.ast.BV) -> claripy.ast.BV:
    return claripy.If(
        direction & 8 != 0,
        claripy.BVV(0, 8),
        claripy.If(
            direction & 4 != 0,
            claripy.BVV(4, 8),
            claripy.If(
                direction & 2 != 0,
                claripy.BVV(12, 8),
                claripy.BVV(8, 8),
            ),
        ),
    )


def addresses(inputs: dict[str, claripy.ast.BV]) -> tuple[claripy.ast.BV, ...]:
    status = inputs["memory0"]
    direction = inputs["memory1"]
    offset = inputs["memory2"]
    initial_hl = claripy.Concat(inputs["h"], inputs["l"])
    enabled = status & 0x20 == 0
    offset_after_res = claripy.If(
        claripy.And(enabled, initial_hl == OFFSET), offset & 0x7F, offset
    )
    direction_after_res = claripy.If(
        claripy.And(enabled, initial_hl == DIRECTION),
        direction & 0x7F,
        direction,
    )
    facing = direction_value(direction_after_res)
    shell_facing = claripy.Concat(inputs["h"], offset_after_res + 9)
    final_offset = claripy.If(
        claripy.And(enabled, shell_facing == OFFSET), facing, offset_after_res
    )
    animation = claripy.Concat(claripy.BVV(0xC1, 8), final_offset + 8)
    update_facing = animation + 1
    image = claripy.Concat(update_facing[15:8], final_offset + 2)
    return (
        claripy.BVV(STATUS, 16),
        claripy.BVV(DIRECTION, 16),
        claripy.BVV(OFFSET, 16),
        claripy.BVV(TILE, 16),
        initial_hl,
        shell_facing,
        animation,
        update_facing,
        image,
    )


def alias_constraints(
    inputs: dict[str, claripy.ast.BV],
) -> tuple[claripy.ast.Bool, ...]:
    mapped = addresses(inputs)
    return tuple(
        claripy.Or(
            mapped[left] != mapped[right],
            inputs[f"memory{left}"] == inputs[f"memory{right}"],
        )
        for left in range(9)
        for right in range(left)
    )


def read_memory(state: angr.SimState, target: claripy.ast.BV | int) -> claripy.ast.BV:
    mapped = state.globals["addresses"]
    memory = state.globals["memory"]
    value = memory[0]
    for index in range(1, 9):
        value = claripy.If(mapped[index] == target, memory[index], value)
    return value


def write_memory(
    state: angr.SimState, target: claripy.ast.BV | int, value: claripy.ast.BV | int
) -> None:
    mapped = state.globals["addresses"]
    memory = state.globals["memory"]
    if isinstance(value, int):
        value = claripy.BVV(value, 8)
    state.globals["memory"] = [
        claripy.If(mapped[index] == target, value, memory[index])
        for index in range(9)
    ]


class ReadFixed(angr.SimProcedure):
    def __init__(self, target: int, next_address: int) -> None:
        super().__init__()
        self.target = target
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = read_memory(self.state, self.target)
        self.jump(self.next_address)


class ReadAtHl(angr.SimProcedure):
    def __init__(self, next_address: int, increment: bool = False) -> None:
        super().__init__()
        self.next_address = next_address
        self.increment = increment

    def run(self) -> None:  # type: ignore[override]
        target = self.state.regs.hl
        self.state.regs.a = read_memory(self.state, target)
        if self.increment:
            self.state.regs.hl = target + 1
        self.jump(self.next_address)


class ResAtHl(angr.SimProcedure):
    def __init__(self, bit: int, next_address: int) -> None:
        super().__init__()
        self.bit = bit
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        target = self.state.regs.hl
        write_memory(self.state, target, read_memory(self.state, target) & ~(1 << self.bit))
        self.jump(self.next_address)


class StoreAtHl(angr.SimProcedure):
    def __init__(self, source: str | None, next_address: int, value: int = 0) -> None:
        super().__init__()
        self.source = source
        self.next_address = next_address
        self.value = value

    def run(self) -> None:  # type: ignore[override]
        value = (
            self.value
            if self.source is None
            else getattr(self.state.regs, self.source)
        )
        write_memory(self.state, self.state.regs.hl, value)
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


def symbolic_inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    inputs = symbolic_registers(prefix)
    for index in range(9):
        inputs[f"memory{index}"] = claripy.BVS(f"{prefix}_memory{index}", 8)
    return inputs


def assembly(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "MakeNPCFacePlayer")
    not_yet = symbol_location(SYMBOLS, "NotYetMoving")
    update = symbol_location(SYMBOLS, "UpdateSpriteImage")
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
    project.hook(q, ReadFixed(STATUS, q + 3), length=3)
    project.hook(q + 3, Sm83BitRegister(5, "a", q + 5), length=2)
    project.hook(q + 7, ResAtHl(7, q + 9), length=2)
    project.hook(q + 9, ReadFixed(DIRECTION, q + 12), length=3)
    project.hook(q + 12, Sm83BitRegister(3, "a", q + 14), length=2)
    project.hook(q + 20, Sm83BitRegister(2, "a", q + 22), length=2)
    project.hook(q + 28, Sm83BitRegister(1, "a", q + 30), length=2)
    project.hook(q + 38, ReadFixed(OFFSET, q + 40), length=2)
    project.hook(q + 40, Sm83AddImmediate(9, q + 42), length=2)
    project.hook(q + 43, StoreAtHl("c", q + 44), length=1)

    q = not_yet.address
    project.hook(q + 2, ReadFixed(OFFSET, q + 4), length=2)
    project.hook(q + 4, Sm83AddImmediate(8, q + 6), length=2)
    project.hook(q + 7, StoreAtHl(None, q + 9), length=2)

    q = update.address
    project.hook(q + 2, ReadFixed(OFFSET, q + 4), length=2)
    project.hook(q + 4, Sm83AddImmediate(8, q + 6), length=2)
    project.hook(q + 7, ReadAtHl(q + 8, increment=True), length=1)
    project.hook(q + 9, ReadAtHl(q + 10), length=1)
    project.hook(q + 10, Sm83AddRegister("b", q + 11), length=1)
    project.hook(q + 12, ReadFixed(TILE, q + 14), length=2)
    project.hook(q + 14, Sm83AddRegister("b", q + 15), length=1)
    project.hook(q + 16, ReadFixed(OFFSET, q + 18), length=2)
    project.hook(q + 18, Sm83AddImmediate(2, q + 20), length=2)
    project.hook(q + 21, StoreAtHl("b", q + 22), length=1)

    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    state.globals["addresses"] = addresses(inputs)
    state.globals["memory"] = [inputs[f"memory{index}"] for index in range(9)]
    state.solver.add(*alias_constraints(inputs))
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    constraints = alias_constraints(inputs)
    return [
        Endpoint(
            **assembly_registers(end),
            memory=claripy.Concat(*end.globals["memory"]),
            constraints=constraints + tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, RETURN)
    ]


def native(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_make_npc_face_player")
    assert function
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(
        NATIVE_STATE + 8,
        claripy.Concat(*(inputs[f"memory{index}"] for index in range(9))),
    )
    state.solver.add(*alias_constraints(inputs))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    constraints = alias_constraints(inputs)
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=end.memory.load(NATIVE_STATE + 8, 9),
            constraints=constraints + tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native")
def test_equivalence() -> None:
    inputs = symbolic_inputs("make_npc_face")
    assert_pathwise_equivalent(
        assembly(inputs), native(inputs), (*REGISTERS, "memory")
    )


def test_exact_bodies() -> None:
    make_npc = symbol_location(SYMBOLS, "MakeNPCFacePlayer")
    not_yet = symbol_location(SYMBOLS, "NotYetMoving")
    update = symbol_location(SYMBOLS, "UpdateSpriteImage")
    assert linked_bytes(ROM, make_npc, 46) == bytes.fromhex(
        "fa2dd7cb6f20edcbbefa2ad5cb5f28040e001812cb5728040e04180a"
        "cb4f28040e0c18020e08f0dac6096f7118c6"
    )
    assert linked_bytes(ROM, not_yet, 12) == bytes.fromhex(
        "26c1f0dac6086f3600c35751"
    )
    assert linked_bytes(ROM, update, 23) == bytes.fromhex(
        "26c1f0dac6086f2a477e8047f0938047f0dac6026f70c9"
    )
