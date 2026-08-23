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
    z80_flags_to_sm83,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
DONE = 0xEFFF
EXPECTED = bytes.fromhex(
    "e5d5c5f0b8f53e0de0b8ea0020cda57df1e0b8ea0020c1d1e1c9"
)
FIELDS = (
    "dividend0",
    "dividend1",
    "dividend2",
    "dividend3",
    "divisor",
    "buffer0",
    "buffer1",
    "buffer2",
    "buffer3",
    "buffer4",
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


class LoadBank(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals["loaded_rom_bank"]
        self.jump(self.next_address)


class SaveAf(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["saved_a"] = self.state.regs.a
        self.state.globals["saved_f"] = z80_flags_to_sm83(self.state.regs.f)
        self.jump(self.next_address)


class RestoreAf(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals["saved_a"]
        self.state.regs.f = sm83_flags_to_z80(self.state.globals["saved_f"])
        self.jump(self.next_address)


class WriteBank(angr.SimProcedure):
    def __init__(self, field: str, next_address: int):
        super().__init__()
        self.field = field
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.globals[self.field] = self.state.regs.a
        self.jump(self.next_address)


class DivideSummary(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        call = assembly_registers(self.state)
        self.state.globals["call_registers"] = claripy.Concat(
            *(call[register] for register in REGISTERS)
        )
        for register in REGISTERS:
            value = self.state.globals[f"callee_{register}"]
            if register == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, register, value)
        for field in FIELDS[:10]:
            self.state.globals[field] = self.state.globals[f"callee_{field}"]
        self.jump(self.next_address)


class NativeDivideSummary(angr.SimProcedure):
    def run(self, state: claripy.ast.BV) -> None:  # type: ignore[override]
        self.state.globals["call_registers"] = self.state.memory.load(state, 8)
        for offset, register in enumerate(REGISTERS):
            self.state.memory.store(
                state + offset, self.state.globals[f"callee_{register}"]
            )
        for offset, field in enumerate(FIELDS[:10], 8):
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
    for field in FIELDS[:10]:
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
    for field in FIELDS[:10]:
        state.globals[f"callee_{field}"] = values[f"callee_{field}"]
    state.globals["call_registers"] = claripy.BVV(0, 64)


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "Divide")
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
    project.hook(base + 1, SavePair("de", base + 2), length=1)
    project.hook(base + 2, SavePair("bc", base + 3), length=1)
    project.hook(base + 3, LoadBank(base + 5), length=2)
    project.hook(base + 5, SaveAf(base + 6), length=1)
    project.hook(base + 8, WriteBank("loaded_rom_bank", base + 10), length=2)
    project.hook(base + 10, WriteBank("mapper_bank", base + 13), length=3)
    project.hook(base + 13, DivideSummary(base + 16), length=3)
    project.hook(base + 16, RestoreAf(base + 17), length=1)
    project.hook(base + 17, WriteBank("loaded_rom_bank", base + 19), length=2)
    project.hook(base + 19, WriteBank("mapper_bank", base + 22), length=3)
    project.hook(base + 22, RestorePair("bc", base + 23), length=1)
    project.hook(base + 23, RestorePair("de", base + 24), length=1)
    project.hook(base + 24, RestorePair("hl", base + 25), length=1)
    project.hook(base + 25, Finish(), length=1)
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
    function = project.loader.find_symbol("port_divide_wrapper")
    divide = project.loader.find_symbol("port_divide")
    assert function is not None and divide is not None
    project.hook(divide.rebased_addr, NativeDivideSummary())
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
def test_divide_wrapper_pathwise_equivalence() -> None:
    values = _inputs("divide_wrapper")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "state", "call_registers"),
    )
