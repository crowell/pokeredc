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
    Sm83AddHlRegisterPair,
    Sm83CpImmediate,
    Sm83CpRegister,
    Sm83IncRegister,
    Sm83Scf,
    Sm83StoreAImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xFFFF
W_STRING_BUFFER = 0xCF4B
W_NAMING_SCREEN_LETTER = 0xCEED
DAKUTENS = 0x6885
HANDAKUTENS = 0x68D6
TABLE_END = 0x68EB
EXPECTED_BODY = bytes.fromhex("d5cdeb682b7ee1110200cdab3dd0237eeaedcec9")


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
    naming_letter: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class AndA(angr.SimProcedure):
    """Audited SM83 ``AND A``: A unchanged, H set, N/C clear."""

    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.f = claripy.BVV(0x10, 8) | claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x40, 8),
            claripy.BVV(0, 8),
        )
        self.jump(self.continuation)


def _tables() -> tuple[int, int]:
    dakutens = symbol_location(SYMBOLS, "Dakutens")
    assert dakutens.bank == 1 and dakutens.address == DAKUTENS
    data = ROM.read_bytes()
    assert data[DAKUTENS + 80] == 0xFF
    assert data[DAKUTENS + 81 : DAKUTENS + 83] == bytes((0xCA, 0x44))
    assert data[TABLE_END - 1] == 0xFF
    return (DAKUTENS, DAKUTENS + 81)


def _assembly(values: dict[str, claripy.ast.BV], table: int) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "DakutensAndHandakutens")
    calc = symbol_location(SYMBOLS, "CalcStringLength").address
    array = symbol_location(SYMBOLS, "IsInArray").address
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY
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
    project.hook(
        base + 16,
        Sm83StoreAImmediate(W_NAMING_SCREEN_LETTER, base + 19),
        length=3,
    )
    project.hook(calc + 6, Sm83CpImmediate(0x50, calc + 8), length=2)
    project.hook(calc + 10, Sm83IncRegister("c", calc + 11), length=1)
    project.hook(array + 4, Sm83CpImmediate(0xFF, array + 6), length=2)
    project.hook(array + 8, Sm83CpRegister("c", array + 9), length=1)
    project.hook(array + 11, Sm83IncRegister("b", array + 12), length=1)
    project.hook(array + 12, Sm83AddHlRegisterPair("de", array + 13), length=1)
    project.hook(array + 15, AndA(array + 16), length=1)
    project.hook(array + 17, Sm83Scf(array + 18), length=1)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.add_constraints(values["d"] == table >> 8)
    state.add_constraints(values["e"] == table & 0xFF)
    state.add_constraints(values["char0"] != 0x50, values["char1"] != 0x50)
    state.memory.store(W_STRING_BUFFER, values["char0"])
    state.memory.store(W_STRING_BUFFER + 1, values["char1"])
    state.memory.store(W_STRING_BUFFER + 2, claripy.BVV(0x50, 8))
    state.memory.store(W_NAMING_SCREEN_LETTER, values["letter"])
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    return [
        Endpoint(
            **assembly_registers(end),
            naming_letter=end.memory.load(W_NAMING_SCREEN_LETTER, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, RETURN)
    ]


def _native(values: dict[str, claripy.ast.BV], table: int) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_dakutens_and_handakutens")
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    state.add_constraints(values["d"] == table >> 8)
    state.add_constraints(values["e"] == table & 0xFF)
    state.add_constraints(values["char0"] != 0x50, values["char1"] != 0x50)
    state.memory.store(NATIVE_MEMORY + W_STRING_BUFFER, values["char0"])
    state.memory.store(NATIVE_MEMORY + W_STRING_BUFFER + 1, values["char1"])
    state.memory.store(
        NATIVE_MEMORY + W_STRING_BUFFER + 2, claripy.BVV(0x50, 8)
    )
    state.memory.store(NATIVE_MEMORY + W_NAMING_SCREEN_LETTER, values["letter"])
    data = ROM.read_bytes()
    for address in range(DAKUTENS, TABLE_END):
        state.memory.store(
            NATIVE_MEMORY + address, claripy.BVV(data[address], 8)
        )
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            naming_letter=end.memory.load(
                NATIVE_MEMORY + W_NAMING_SCREEN_LETTER, 1
            ),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("table", (DAKUTENS, HANDAKUTENS), ids=("dakutens", "handakutens"))
def test_dakutens_and_handakutens_pathwise_equivalence(table: int) -> None:
    assert _tables() == (DAKUTENS, HANDAKUTENS)
    values = symbolic_registers("dakutens_and_handakutens")
    values["char0"] = claripy.BVS("dakutens_char0", 8)
    values["char1"] = claripy.BVS("dakutens_char1", 8)
    values["letter"] = claripy.BVS("dakutens_letter", 8)
    assert_pathwise_equivalent(
        _assembly(values, table),
        _native(values, table),
        (*REGISTERS, "naming_letter"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_dakutens_and_handakutens_exact_body() -> None:
    location = symbol_location(SYMBOLS, "DakutensAndHandakutens")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY
