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
    Sm83StoreAHighImmediate,
    Sm83SubImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x110000
STACK = 0xD000
RETURN = 0xFFFF
AUTO = 0xFFBA
LOADED_BANK = 0xFFB8
BANK_TEMP = 0xFF8B
ROMB = 0x2000
COPY_SOURCE = 0xFFC7
COPY_DEST = 0xFFC9
COPY_SIZE = 0xFFC6
VBLANK = 0xFFD6
ADDRESSES = (
    AUTO,
    LOADED_BANK,
    BANK_TEMP,
    ROMB,
    COPY_SOURCE,
    COPY_SOURCE + 1,
    COPY_DEST,
    COPY_DEST + 1,
    COPY_SIZE,
    VBLANK,
)
FIELDS = (
    "auto",
    "loaded_bank",
    "bank_temp",
    "romb",
    "copy_source",
    "copy_source_high",
    "copy_dest",
    "copy_dest_high",
    "copy_size",
    "vblank",
)
EXPECTED = bytes.fromhex(
    "f0baf5afe0baf0b8e08b78e0b8ea00207be0c77ae0c87de0c97ce0ca"
    "79fe083010e0c6cdaf20f08be0b8ea0020f1e0bac93e08e0c6cdaf2079"
    "d6084f18de"
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
    calls: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class XorA(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x40, 8)
        self.jump(self._next_address)


class StoreRomb(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["romb"] = self.state.regs.a
        self.jump(self._next_address)


class AssemblyDelayFrame(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        registers = assembly_registers(self.state)
        self.state.globals["calls"] = self.state.globals["calls"] + (
            claripy.Concat(
                *(registers[name] for name in REGISTERS),
                self.state.memory.load(VBLANK, 1),
                self.state.memory.load(COPY_SIZE, 1),
            ),
        )
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x50, 8)
        self.state.memory.store(VBLANK, claripy.BVV(0, 8))
        return_address = self.state.memory.load(
            self.state.regs.sp, 2, endness="Iend_LE"
        )
        self.state.regs.sp += 2
        self.jump(return_address)


class NativeDelayFrame(angr.SimProcedure):
    def run(
        self, state: claripy.ast.BV, _observations: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        memory = self.state.globals["parent_memory"]
        self.state.globals["calls"] = self.state.globals["calls"] + (
            claripy.Concat(
                self.state.memory.load(state, 9),
                self.state.memory.load(memory + COPY_SIZE, 1),
            ),
        )
        self.state.memory.store(state, claripy.BVV(0, 8))
        self.state.memory.store(state + 1, claripy.BVV(0xA0, 8))
        self.state.memory.store(state + 8, claripy.BVV(0, 8))


def _inputs(prefix: str, quotient: int) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    remainder = claripy.BVS(f"{prefix}_remainder", 3)
    values["c"] = claripy.Concat(claripy.BVV(quotient, 5), remainder)
    for field in FIELDS:
        values[field] = claripy.BVS(f"{prefix}_{field}", 8)
    return values


def _memory(state: angr.SimState, base: int = 0) -> claripy.ast.BV:
    return claripy.Concat(
        *(
            state.globals["romb"]
            if base == 0 and address == ROMB
            else state.memory.load(base + address, 1)
            for address in ADDRESSES
        )
    )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "CopyVideoData")
    delay = symbol_location(SYMBOLS, "DelayFrame")
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
    q = location.address
    for offset, address in (
        (0, AUTO),
        (6, LOADED_BANK),
        (38, BANK_TEMP),
    ):
        project.hook(
            q + offset,
            Sm83LoadAHighImmediate(address & 0xFF, q + offset + 2),
            length=2,
        )
    for offset, address in (
        (4, AUTO),
        (8, BANK_TEMP),
        (11, LOADED_BANK),
        (17, COPY_SOURCE),
        (20, COPY_SOURCE + 1),
        (23, COPY_DEST),
        (26, COPY_DEST + 1),
        (33, COPY_SIZE),
        (40, LOADED_BANK),
        (46, AUTO),
        (51, COPY_SIZE),
    ):
        project.hook(
            q + offset,
            Sm83StoreAHighImmediate(address & 0xFF, q + offset + 2),
            length=2,
        )
    project.hook(q + 3, XorA(q + 4), length=1)
    project.hook(q + 13, StoreRomb(q + 16), length=3)
    project.hook(q + 29, Sm83CpImmediate(8, q + 31), length=2)
    project.hook(q + 42, StoreRomb(q + 45), length=3)
    project.hook(q + 57, Sm83SubImmediate(8, q + 59), length=2)
    project.hook(delay.address, AssemblyDelayFrame())
    state = project.factory.blank_state(addr=q)
    set_assembly_registers(state, values)
    state.regs.sp = claripy.BVV(STACK, 16)
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    for address, field in zip(ADDRESSES, FIELDS):
        state.memory.store(address, values[field])
    state.globals["romb"] = values["romb"]
    state.globals["calls"] = ()
    ends = collect_returns(project, state, RETURN)
    assert len(ends) == 1
    return [
        Endpoint(
            **assembly_registers(end),
            memory=_memory(end),
            calls=claripy.Concat(*end.globals["calls"]),
            constraints=tuple(end.solver.constraints),
        )
        for end in ends
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_copy_video_data")
    delay = project.loader.find_symbol("port_delay_frame")
    assert function is not None and delay is not None
    project.hook(delay.rebased_addr, NativeDelayFrame())
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    for address, field in zip(ADDRESSES, FIELDS):
        state.memory.store(NATIVE_MEMORY + address, values[field])
    state.globals["parent_memory"] = claripy.BVV(NATIVE_MEMORY, 64)
    state.globals["calls"] = ()
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=_memory(end, NATIVE_MEMORY),
            calls=claripy.Concat(*end.globals["calls"]),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(
    not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`"
)
def test_copy_video_data_all_counts_pathwise_equivalence() -> None:
    for quotient in range(32):
        values = _inputs(f"copy_video_data_{quotient}", quotient)
        assert_pathwise_equivalent(
            _assembly(values),
            _native(values),
            (*REGISTERS, "memory", "calls"),
        )
