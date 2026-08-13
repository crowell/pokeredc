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
    Sm83LoadAImmediate,
    Sm83StoreAImmediate,
)


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
GB_STACK = 0xD000
GB_RETURN = 0xFFFF
TEXT_POINTER = 0xD36C
PARCEL_EVENT_BYTE = 0xD74E


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
    values["source"] = claripy.BVS(f"{prefix}_source", 8)
    values["pointer_low"] = claripy.BVS(f"{prefix}_pointer_low", 8)
    values["pointer_high"] = claripy.BVS(f"{prefix}_pointer_high", 8)
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
) -> list[Endpoint]:
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(loaded, state, GB_RETURN)
    return [
        Endpoint(
            **assembly_registers(end),
            memory=claripy.Concat(
                end.memory.load(source_address, 1),
                end.memory.load(TEXT_POINTER, 2),
            ),
            constraints=tuple(end.solver.constraints),
        )
        for end in returned
    ]


def assembly_oaks(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    loaded, base = project("OaksLabLoadTextPointers2Script")
    loaded.hook(
        base + 4, Sm83StoreAImmediate(TEXT_POINTER, base + 7), length=3
    )
    loaded.hook(
        base + 8, Sm83StoreAImmediate(TEXT_POINTER + 1, base + 11), length=3
    )
    state = loaded.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.memory.store(0xC100, values["source"])
    state.memory.store(
        TEXT_POINTER,
        claripy.Concat(values["pointer_low"], values["pointer_high"]),
    )
    return endpoints(loaded, state, 0xC100)


def assembly_viridian(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    loaded, base = project("ViridianMartCheckParcelDeliveredScript")
    loaded.hook(
        base, Sm83LoadAImmediate(PARCEL_EVENT_BYTE, base + 3), length=3
    )
    loaded.hook(base + 3, Sm83BitRegister(0, "a", base + 5), length=2)
    loaded.hook(
        base + 16, Sm83StoreAImmediate(TEXT_POINTER, base + 19), length=3
    )
    loaded.hook(
        base + 20, Sm83StoreAImmediate(TEXT_POINTER + 1, base + 23), length=3
    )
    state = loaded.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.memory.store(PARCEL_EVENT_BYTE, values["source"])
    state.memory.store(
        TEXT_POINTER,
        claripy.Concat(values["pointer_low"], values["pointer_high"]),
    )
    return endpoints(loaded, state, PARCEL_EVENT_BYTE)


def native(symbol: str, values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    loaded = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = loaded.loader.find_symbol(symbol)
    assert function is not None
    state = loaded.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(
        NATIVE_STATE + 8,
        claripy.Concat(
            values["source"], values["pointer_low"], values["pointer_high"]
        ),
    )
    manager = loaded.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=end.memory.load(NATIVE_STATE + 8, 3),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native port not built")
@pytest.mark.parametrize(
    "assembly_function,c_symbol",
    [
        (assembly_oaks, "port_oaks_lab_load_text_pointers2"),
        (assembly_viridian, "port_viridian_mart_check_parcel_delivered"),
    ],
)
def test_equivalence(assembly_function, c_symbol: str) -> None:
    values = inputs(c_symbol)
    assert_pathwise_equivalent(
        assembly_function(values),
        native(c_symbol, values),
        (*REGISTERS, "memory"),
    )


def test_exact_bodies_and_addresses() -> None:
    oak = symbol_location(SYMBOLS, "OaksLabLoadTextPointers2Script")
    mart = symbol_location(SYMBOLS, "ViridianMartCheckParcelDeliveredScript")
    assert symbol_location(SYMBOLS, "OaksLab_TextPointers2").address == 0x50B8
    assert symbol_location(SYMBOLS, "ViridianMart_TextPointers").address == 0x54E0
    assert symbol_location(SYMBOLS, "ViridianMart_TextPointers2").address == 0x54EA
    assert symbol_location(SYMBOLS, "wCurMapTextPtr").address == TEXT_POINTER
    assert linked_bytes(ROM, oak, 12) == bytes.fromhex(
        "21b8507dea6cd37cea6dd3c9"
    )
    assert linked_bytes(ROM, mart, 24) == bytes.fromhex(
        "fa4ed7cb47200521e054180321ea547dea6cd37cea6dd3c9"
    )
