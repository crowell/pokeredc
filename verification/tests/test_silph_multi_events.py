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
    Sm83CpImmediate,
    Sm83LoadAHighImmediate,
    Sm83SetAtHl,
)


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
GB_STACK = 0xD000
GB_RETURN = 0xFFFF

CASES = (
    (
        "SilphCo2F_UnlockedDoorEventScript",
        "port_silph_co_2f_unlocked_door_event",
        0xD826,
        ((11, 5), (14, 6)),
        ((7, 1),),
        "2126d8f0e0a7c8fe012003cbeec9cbf6c9",
    ),
    (
        "SilphCo3F_UnlockedDoorEventScript",
        "port_silph_co_3f_unlocked_door_event",
        0xD828,
        ((11, 0), (14, 1)),
        ((7, 1),),
        "2128d8f0e0a7c8fe012003cbc6c9cbcec9",
    ),
    (
        "SilphCo4FUnlockedDoorEventScript",
        "port_silph_co_4f_unlocked_door_event",
        0xD82A,
        ((11, 0), (14, 1)),
        ((7, 1),),
        "212ad8f0e0a7c8fe012003cbc6c9cbcec9",
    ),
    (
        "SilphCo5F_SetUnlockedSilphCoDoorsScript",
        "port_silph_co_5f_set_unlocked_doors",
        0xD82C,
        ((11, 0), (18, 1), (21, 2)),
        ((7, 1), (14, 2)),
        "212cd8f0e0a7c8fe012003cbc6c9fe022003cbcec9cbd6c9",
    ),
    (
        "SilphCo7F_UnlockedDoorEventScript",
        "port_silph_co_7f_unlocked_door_event",
        0xD830,
        ((11, 4), (18, 5), (21, 6)),
        ((7, 1), (14, 2)),
        "2130d8f0e0a7c8fe012003cbe6c9fe022003cbeec9cbf6c9",
    ),
    (
        "SilphCo9F_SetUnlockedSilphCoDoorsScript",
        "port_silph_co_9f_set_unlocked_doors",
        0xD834,
        ((11, 0), (18, 1), (25, 2), (31, 3)),
        ((7, 1), (14, 2), (21, 3), (28, 4)),
        "2134d8f0e0a7c8fe012003cbc6c9fe022003cbcec9fe032003cbd6c9fe04c0cbdec9",
    ),
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
    memory: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class AndA(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.f = 0x10 | claripy.If(
            self.state.regs.a == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)
        )
        self.jump(self._next_address)


def inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["source"] = claripy.BVS(f"{prefix}_source", 8)
    values["event_byte"] = claripy.BVS(f"{prefix}_event_byte", 8)
    return values


def assembly(
    symbol: str,
    event_address: int,
    sets: tuple[tuple[int, int], ...],
    comparisons: tuple[tuple[int, int], ...],
    values: dict[str, claripy.ast.BV],
) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, symbol)
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
    project.hook(base + 3, Sm83LoadAHighImmediate(0xE0, base + 5), length=2)
    project.hook(base + 5, AndA(base + 6), length=1)
    for offset, immediate in comparisons:
        project.hook(
            base + offset,
            Sm83CpImmediate(immediate, base + offset + 2),
            length=2,
        )
    for offset, bit in sets:
        project.hook(
            base + offset, Sm83SetAtHl(bit, base + offset + 2), length=2
        )
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.memory.store(0xFFE0, values["source"])
    state.memory.store(event_address, values["event_byte"])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    return [
        Endpoint(
            **assembly_registers(end),
            memory=claripy.Concat(
                end.memory.load(0xFFE0, 1), end.memory.load(event_address, 1)
            ),
            constraints=tuple(end.solver.constraints),
        )
        for end in returned
    ]


def native(symbol: str, values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(
        NATIVE_STATE + 8,
        claripy.Concat(values["source"], values["event_byte"]),
    )
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=end.memory.load(NATIVE_STATE + 8, 2),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native port not built")
@pytest.mark.parametrize(
    "symbol,c_symbol,event_address,sets,comparisons,_body", CASES
)
def test_equivalence(
    symbol: str,
    c_symbol: str,
    event_address: int,
    sets: tuple[tuple[int, int], ...],
    comparisons: tuple[tuple[int, int], ...],
    _body: str,
) -> None:
    values = inputs(symbol.lower())
    assert_pathwise_equivalent(
        assembly(symbol, event_address, sets, comparisons, values),
        native(c_symbol, values),
        (*REGISTERS, "memory"),
    )


@pytest.mark.parametrize(
    "symbol,_c_symbol,_event_address,_sets,_comparisons,body", CASES
)
def test_exact_body(
    symbol: str,
    _c_symbol: str,
    _event_address: int,
    _sets: tuple[tuple[int, int], ...],
    _comparisons: tuple[tuple[int, int], ...],
    body: str,
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    expected = bytes.fromhex(body)
    assert linked_bytes(ROM, location, len(expected)) == expected
