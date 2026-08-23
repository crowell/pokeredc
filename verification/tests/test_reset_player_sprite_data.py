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
from verification.harness.sm83_shims import Sm83StoreAImmediate

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF
MARKER = 0x1234
DATA1 = 0xC100
DATA2 = 0xC200
EXPECTED = bytes.fromhex(
    "2100c1cdc4282100c2cdc4283e01ea00c1ea0ec22104c1363c23233640c9"
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
    data1: claripy.ast.BV
    data2: claripy.ast.BV
    calls: claripy.ast.BV
    marker: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class ClearSummary(angr.SimProcedure):
    def __init__(self, call_index: int, next_address: int):
        super().__init__()
        self.call_index = call_index
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        call = assembly_registers(self.state)
        self.state.globals[f"call{self.call_index}"] = claripy.Concat(
            *(call[register] for register in REGISTERS)
        )
        for register in REGISTERS:
            value = self.state.globals[f"callee{self.call_index}_{register}"]
            if register == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, register, value)
        base = DATA1 if self.call_index == 1 else DATA2
        for offset in range(16):
            self.state.memory.store(
                base + offset,
                self.state.globals[f"callee{self.call_index}_memory{offset}"],
            )
        self.jump(self.next_address)


class NativeClearSummary(angr.SimProcedure):
    def run(
        self, state: claripy.ast.BV, memory: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        call_index = self.state.globals["call_index"]
        self.state.globals[f"call{call_index}"] = self.state.memory.load(state, 8)
        for offset, register in enumerate(REGISTERS):
            self.state.memory.store(
                state + offset,
                self.state.globals[f"callee{call_index}_{register}"],
            )
        base = DATA1 if call_index == 1 else DATA2
        for offset in range(16):
            self.state.memory.store(
                memory + base + offset,
                self.state.globals[f"callee{call_index}_memory{offset}"],
            )
        self.state.globals["call_index"] = call_index + 1


class StoreAtHl(angr.SimProcedure):
    def __init__(self, value: int, next_address: int):
        super().__init__()
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(self.state.regs.hl, claripy.BVV(self.value, 8))
        self.jump(self.next_address)


class Finish(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(DONE)


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["marker"] = claripy.BVS(f"{prefix}_marker", 8)
    for call_index in (1, 2):
        for register in REGISTERS:
            values[f"callee{call_index}_{register}"] = (
                claripy.Concat(
                    claripy.BVS(f"{prefix}_callee{call_index}_flags", 4),
                    claripy.BVV(0, 4),
                )
                if register == "f"
                else claripy.BVS(f"{prefix}_callee{call_index}_{register}", 8)
            )
        for offset in range(16):
            values[f"callee{call_index}_memory{offset}"] = claripy.BVS(
                f"{prefix}_callee{call_index}_memory{offset}", 8
            )
    for base_name in ("data1", "data2"):
        for offset in range(16):
            values[f"{base_name}_{offset}"] = claripy.BVS(
                f"{prefix}_{base_name}_{offset}", 8
            )
    return values


def _setup_globals(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    for call_index in (1, 2):
        for register in REGISTERS:
            state.globals[f"callee{call_index}_{register}"] = values[
                f"callee{call_index}_{register}"
            ]
        for offset in range(16):
            state.globals[f"callee{call_index}_memory{offset}"] = values[
                f"callee{call_index}_memory{offset}"
            ]
        state.globals[f"call{call_index}"] = claripy.BVV(0, 64)


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "ResetPlayerSpriteData")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0, "entry_point": location.address},
    )
    base = location.address
    project.hook(base + 3, ClearSummary(1, base + 6), length=3)
    project.hook(base + 9, ClearSummary(2, base + 12), length=3)
    project.hook(base + 14, Sm83StoreAImmediate(DATA1, base + 17), length=3)
    project.hook(base + 17, Sm83StoreAImmediate(DATA2 + 14, base + 20), length=3)
    project.hook(base + 23, StoreAtHl(0x3C, base + 25), length=2)
    project.hook(base + 27, StoreAtHl(0x40, base + 29), length=2)
    project.hook(base + 29, Finish(), length=1)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _setup_globals(state, values)
    for offset in range(16):
        state.memory.store(DATA1 + offset, values[f"data1_{offset}"])
        state.memory.store(DATA2 + offset, values[f"data2_{offset}"])
    state.memory.store(MARKER, values["marker"])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE)
    assert not manager.errored
    return [
        Endpoint(
            **assembly_registers(end),
            data1=end.memory.load(DATA1, 16),
            data2=end.memory.load(DATA2, 16),
            calls=claripy.Concat(end.globals["call1"], end.globals["call2"]),
            marker=end.memory.load(MARKER, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_reset_player_sprite_data")
    clear = project.loader.find_symbol("port_reset_player_sprite_data_clear_sprite_data")
    assert function is not None and clear is not None
    project.hook(clear.rebased_addr, NativeClearSummary())
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup_globals(state, values)
    state.globals["call_index"] = 1
    for offset in range(16):
        state.memory.store(NATIVE_MEMORY + DATA1 + offset, values[f"data1_{offset}"])
        state.memory.store(NATIVE_MEMORY + DATA2 + offset, values[f"data2_{offset}"])
    state.memory.store(NATIVE_MEMORY + MARKER, values["marker"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            data1=end.memory.load(NATIVE_MEMORY + DATA1, 16),
            data2=end.memory.load(NATIVE_MEMORY + DATA2, 16),
            calls=claripy.Concat(end.globals["call1"], end.globals["call2"]),
            marker=end.memory.load(NATIVE_MEMORY + MARKER, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_reset_player_sprite_data_pathwise_equivalence() -> None:
    values = _inputs("reset_player_sprite_data")
    assert_pathwise_equivalent(
        _assembly(values), _native(values),
        (*REGISTERS, "data1", "data2", "calls", "marker"),
    )
