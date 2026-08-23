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
from verification.harness.rom import linked_bytes, rom_window, sm83_flags_to_z80, symbol_location

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
DONE = 0xEFFF
EXPECTED = bytes.fromhex("ea1ed1060121187cc3d635")
FIELDS = ("status_flags5", "pokedex_num", "loaded_rom_bank", "mapper_bank")


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
    call_registers: claripy.ast.BV
    call_pokedex_num: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class StorePokedexNum(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["pokedex_num"] = self.state.regs.a
        self.jump(self.next_address)


class BankswitchSummary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        saved_bank = self.state.globals["loaded_rom_bank"]
        saved_f = assembly_registers(self.state)["f"]
        callback = assembly_registers(self.state)
        callback["a"] = callback["b"]
        callback["b"] = claripy.BVV(0x35, 8)
        callback["c"] = claripy.BVV(0xE4, 8)
        self.state.globals["call_registers"] = claripy.Concat(
            *(callback[register] for register in REGISTERS)
        )
        self.state.globals["call_pokedex_num"] = self.state.globals["pokedex_num"]
        for register in REGISTERS:
            value = self.state.globals[f"callee_{register}"]
            if register == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, register, value)
        self.state.globals["status_flags5"] = self.state.globals["callee_status_flags5"]
        self.state.regs.a = saved_bank
        self.state.regs.b = saved_bank
        self.state.regs.c = saved_f
        self.state.globals["loaded_rom_bank"] = saved_bank
        self.state.globals["mapper_bank"] = saved_bank
        self.jump(DONE)


class NativeCalleeSummary(angr.SimProcedure):
    def run(self, state: claripy.ast.BV) -> None:  # type: ignore[override]
        self.state.globals["call_registers"] = self.state.memory.load(state, 8)
        self.state.globals["call_pokedex_num"] = self.state.memory.load(state + 9, 1)
        for offset, register in enumerate(REGISTERS):
            self.state.memory.store(
                state + offset, self.state.globals[f"callee_{register}"]
            )
        self.state.memory.store(state + 8, self.state.globals["callee_status_flags5"])


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for field in FIELDS:
        values[field] = claripy.BVS(f"{prefix}_{field}", 8)
    values["callee_status_flags5"] = claripy.BVS(f"{prefix}_callee_status_flags5", 8)
    for register in REGISTERS:
        values[f"callee_{register}"] = (
            claripy.Concat(claripy.BVS(f"{prefix}_callee_flags", 4), claripy.BVV(0, 4))
            if register == "f" else claripy.BVS(f"{prefix}_callee_{register}", 8)
        )
    return values


def _setup_globals(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    for field in FIELDS:
        state.globals[field] = values[field]
    state.globals["callee_status_flags5"] = values["callee_status_flags5"]
    for register in REGISTERS:
        state.globals[f"callee_{register}"] = values[f"callee_{register}"]
    state.globals["call_registers"] = claripy.BVV(0, 64)
    state.globals["call_pokedex_num"] = claripy.BVV(0, 8)


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "DisplayPokedex")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0, "entry_point": location.address},
    )
    base = location.address
    project.hook(base, StorePokedexNum(base + 3), length=3)
    project.hook(base + 8, BankswitchSummary(), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _setup_globals(state, values)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE)
    assert not manager.errored
    return [
        Endpoint(
            **assembly_registers(end),
            state=claripy.Concat(*(end.globals[field] for field in FIELDS)),
            call_registers=end.globals["call_registers"],
            call_pokedex_num=end.globals["call_pokedex_num"],
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_display_pokedex")
    callee = project.loader.find_symbol("port_display_pokedex_private")
    assert function is not None and callee is not None
    project.hook(callee.rebased_addr, NativeCalleeSummary())
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    for offset, field in enumerate(FIELDS, 8):
        state.memory.store(NATIVE_STATE + offset, values[field])
    _setup_globals(state, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            state=end.memory.load(NATIVE_STATE + 8, len(FIELDS)),
            call_registers=end.globals["call_registers"],
            call_pokedex_num=end.globals["call_pokedex_num"],
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_display_pokedex_pathwise_equivalence() -> None:
    values = _inputs("display_pokedex")
    assert_pathwise_equivalent(
        _assembly(values), _native(values),
        (*REGISTERS, "state", "call_registers", "call_pokedex_num"),
    )
