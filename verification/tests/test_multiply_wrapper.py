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
    linked_bytes,
    rom_window,
    sm83_flags_to_z80,
    symbol_location,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
DONE = 0xEFFF
EXPECTED = bytes.fromhex("e5c521417d060dcdd635c1e1c9")
FIELDS = (
    "product0",
    "product1",
    "product2",
    "product3",
    "multiplier",
    "buffer0",
    "buffer1",
    "buffer2",
    "buffer3",
    "loaded_rom_bank",
    "mapper_bank",
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
    call_registers: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class SavePair(angr.SimProcedure):
    def __init__(self, pair: str, next_address: int):
        super().__init__()
        self.pair = pair
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        for register in self.pair:
            self.state.globals[f"saved_{register}"] = getattr(
                self.state.regs, register
            )
        self.jump(self.next_address)


class RestorePair(angr.SimProcedure):
    def __init__(self, pair: str, next_address: int):
        super().__init__()
        self.pair = pair
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        for register in self.pair:
            setattr(
                self.state.regs,
                register,
                self.state.globals[f"saved_{register}"],
            )
        self.jump(self.next_address)


class BankswitchMultiplySummary(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        saved_bank = self.state.globals["loaded_rom_bank"]
        callback = assembly_registers(self.state)
        callback["a"] = callback["b"]
        callback["b"] = claripy.BVV(0x35, 8)
        callback["c"] = claripy.BVV(0xE4, 8)
        self.state.globals["call_registers"] = claripy.Concat(
            *(callback[register] for register in REGISTERS)
        )
        for register in REGISTERS:
            value = self.state.globals[f"callee_{register}"]
            if register == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, register, value)
        for field in FIELDS[:9]:
            self.state.globals[field] = self.state.globals[f"callee_{field}"]
        self.state.regs.a = saved_bank
        self.state.globals["loaded_rom_bank"] = saved_bank
        self.state.globals["mapper_bank"] = saved_bank
        self.jump(self.next_address)


class NativeMultiplySummary(angr.SimProcedure):
    def run(self, state: claripy.ast.BV) -> None:  # type: ignore[override]
        self.state.globals["call_registers"] = self.state.memory.load(state, 8)
        for offset, register in enumerate(REGISTERS):
            self.state.memory.store(
                state + offset, self.state.globals[f"callee_{register}"]
            )
        for offset, field in enumerate(FIELDS[:9], 8):
            self.state.memory.store(
                state + offset, self.state.globals[f"callee_{field}"]
            )


class Finish(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(DONE)


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for field in FIELDS:
        values[field] = claripy.BVS(f"{prefix}_{field}", 8)
    for register in REGISTERS:
        values[f"callee_{register}"] = (
            claripy.Concat(
                claripy.BVS(f"{prefix}_callee_flags", 4), claripy.BVV(0, 4)
            )
            if register == "f"
            else claripy.BVS(f"{prefix}_callee_{register}", 8)
        )
    for field in FIELDS[:9]:
        values[f"callee_{field}"] = claripy.BVS(
            f"{prefix}_callee_{field}", 8
        )
    return values


def _setup_globals(
    state: angr.SimState, values: dict[str, claripy.ast.BV]
) -> None:
    for field in FIELDS:
        state.globals[field] = values[field]
    for register in REGISTERS:
        state.globals[f"callee_{register}"] = values[f"callee_{register}"]
    for field in FIELDS[:9]:
        state.globals[f"callee_{field}"] = values[f"callee_{field}"]
    state.globals["call_registers"] = claripy.BVV(0, 64)


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "Multiply")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
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
    project.hook(base, SavePair("hl", base + 1), length=1)
    project.hook(base + 1, SavePair("bc", base + 2), length=1)
    project.hook(base + 7, BankswitchMultiplySummary(base + 10), length=3)
    project.hook(base + 10, RestorePair("bc", base + 11), length=1)
    project.hook(base + 11, RestorePair("hl", base + 12), length=1)
    project.hook(base + 12, Finish(), length=1)
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
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_multiply_wrapper")
    multiply = project.loader.find_symbol("port_multiply")
    assert function is not None and multiply is not None
    project.hook(multiply.rebased_addr, NativeMultiplySummary())
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
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_multiply_wrapper_pathwise_equivalence() -> None:
    values = _inputs("multiply_wrapper")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "state", "call_registers"),
    )
