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
    Sm83BitRegister,
    Sm83LoadAHighImmediate,
    Sm83LoadAImmediate,
    Sm83SetAtHl,
)


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
GB_STACK = 0xD000
GB_RETURN = 0xFFFF

SILPH_CASES = (
    (
        "SilphCo6F_UnlockedDoorEventScript",
        "port_silph_co_6f_unlocked_door_event",
        0xD82E,
        7,
        "f0e0a7c8212ed8cbfec9",
    ),
    (
        "SilphCo8F_UnlockedDoorEventScript",
        "port_silph_co_8f_unlocked_door_event",
        0xD832,
        0,
        "f0e0a7c82132d8cbc6c9",
    ),
    (
        "SilphCo10F_SetUnlockedSilphCoDoorsScript",
        "port_silph_co_10f_set_unlocked_doors",
        0xD836,
        0,
        "f0e0a7c82136d8cbc6c9",
    ),
    (
        "SilphCo11FSetUnlockedDoorEventScript",
        "port_silph_co_11f_set_unlocked_door_event",
        0xD838,
        0,
        "f0e0a7c82138d8cbc6c9",
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


def project(symbol: str) -> tuple[angr.Project, int]:
    location = symbol_location(SYMBOLS, symbol)
    loaded = angr.Project(
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
    return loaded, location.address


def endpoints(
    loaded: angr.Project,
    state: angr.SimState,
    source_address: int,
    event_address: int,
) -> list[Endpoint]:
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(loaded, state, GB_RETURN)
    return [
        Endpoint(
            **assembly_registers(end),
            memory=claripy.Concat(
                end.memory.load(source_address, 1),
                end.memory.load(event_address, 1),
            ),
            constraints=tuple(end.solver.constraints),
        )
        for end in returned
    ]


def assembly_silph(
    symbol: str,
    event_address: int,
    bit: int,
    values: dict[str, claripy.ast.BV],
) -> list[Endpoint]:
    loaded, base = project(symbol)
    loaded.hook(base, Sm83LoadAHighImmediate(0xE0, base + 2), length=2)
    loaded.hook(base + 2, AndA(base + 3), length=1)
    loaded.hook(base + 7, Sm83SetAtHl(bit, base + 9), length=2)
    state = loaded.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.memory.store(0xFFE0, values["source"])
    state.memory.store(event_address, values["event_byte"])
    return endpoints(loaded, state, 0xFFE0, event_address)


def assembly_captain(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    loaded, base = project("SSAnneCaptainsRoomEventScript")
    loaded.hook(base, Sm83LoadAImmediate(0xD803, base + 3), length=3)
    loaded.hook(base + 3, Sm83BitRegister(1, "a", base + 5), length=2)
    loaded.hook(base + 9, Sm83SetAtHl(5, base + 11), length=2)
    state = loaded.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.memory.store(0xD803, values["source"])
    state.memory.store(0xD72D, values["event_byte"])
    return endpoints(loaded, state, 0xD803, 0xD72D)


def native(symbol: str, values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    loaded = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = loaded.loader.find_symbol(symbol)
    assert function is not None
    state = loaded.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(
        NATIVE_STATE + 8,
        claripy.Concat(values["source"], values["event_byte"]),
    )
    manager = loaded.factory.simulation_manager(state)
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
@pytest.mark.parametrize("symbol,c_symbol,event_address,bit,_body", SILPH_CASES)
def test_silph_event_equivalence(
    symbol: str, c_symbol: str, event_address: int, bit: int, _body: str
) -> None:
    values = inputs(symbol.lower())
    assert_pathwise_equivalent(
        assembly_silph(symbol, event_address, bit, values),
        native(c_symbol, values),
        (*REGISTERS, "memory"),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native port not built")
def test_captains_room_event_equivalence() -> None:
    values = inputs("ss_anne_captains_room_event")
    assert_pathwise_equivalent(
        assembly_captain(values),
        native("port_ss_anne_captains_room_event", values),
        (*REGISTERS, "memory"),
    )


@pytest.mark.parametrize("symbol,_c_symbol,_event_address,_bit,body", SILPH_CASES)
def test_silph_exact_body(
    symbol: str, _c_symbol: str, _event_address: int, _bit: int, body: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    expected = bytes.fromhex(body)
    assert linked_bytes(ROM, location, len(expected)) == expected


def test_captains_room_exact_body() -> None:
    location = symbol_location(SYMBOLS, "SSAnneCaptainsRoomEventScript")
    assert linked_bytes(ROM, location, 12) == bytes.fromhex(
        "fa03d8cb4fc0212dd7cbeec9"
    )
