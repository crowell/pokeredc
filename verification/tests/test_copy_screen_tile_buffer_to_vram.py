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
from verification.harness.rom import collect_returns, rom_window, symbol_location
from verification.harness.sm83_shims import Sm83StoreAHighImmediate

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x400000
GB_STACK = 0xD000
GB_RETURN = 0xFFFF

BG_SOURCE = 0xFFC1
BG_DEST = 0xFFC3
BG_NUM_ROWS = 0xFFC5
MEMORY_ADDRESSES = (
    BG_SOURCE,
    BG_SOURCE + 1,
    BG_DEST,
    BG_DEST + 1,
    BG_NUM_ROWS,
)


class GetRowColAddressBgMap(angr.SimProcedure):
    """Transition of the independently proven GetRowColAddressBgMap port."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        row = self.state.regs.h
        self.state.regs.l |= (row & 7) << 5
        self.state.regs.h = self.state.regs.b | claripy.LShR(row, 3)
        self.state.regs.a = self.state.regs.h
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x40, 8),
            claripy.BVV(0, 8),
        )
        self.jump(self._next_address)


class DelayFrameInline(angr.SimProcedure):
    """Terminal transition of the independently proven DelayFrame port."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x50, 8)
        self.jump(self._next_address)


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


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for index, address in enumerate(MEMORY_ADDRESSES):
        values[f"memory_{address:x}"] = claripy.BVS(f"{prefix}_memory_{index}", 8)
    return values


def _assembly(values: dict[str, claripy.ast.BV]) -> Endpoint:
    location = symbol_location(SYMBOLS, "CopyScreenTileBufferToVRAM")
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
    setup = base + 0x26

    # Execute the linked body and its internal setup routine. Only the two
    # independently proven callees and SM83-only LDH opcodes are summarized.
    project.hook(setup + 0x03, GetRowColAddressBgMap(setup + 0x06), length=3)
    project.hook(base + 0x0B, DelayFrameInline(base + 0x0E), length=3)
    project.hook(base + 0x17, DelayFrameInline(base + 0x1A), length=3)
    project.hook(base + 0x23, DelayFrameInline(GB_RETURN), length=3)
    project.hook(setup + 0x01, Sm83StoreAHighImmediate(0xC2, setup + 0x03), length=2)
    project.hook(setup + 0x07, Sm83StoreAHighImmediate(0xC3, setup + 0x09), length=2)
    project.hook(setup + 0x0A, Sm83StoreAHighImmediate(0xC4, setup + 0x0C), length=2)
    project.hook(setup + 0x0D, Sm83StoreAHighImmediate(0xC5, setup + 0x0F), length=2)
    project.hook(setup + 0x10, Sm83StoreAHighImmediate(0xC1, setup + 0x12), length=2)

    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.regs.sp = claripy.BVV(GB_STACK, 16)
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    for address in MEMORY_ADDRESSES:
        state.memory.store(address, values[f"memory_{address:x}"])
    returned = collect_returns(project, state, GB_RETURN)
    assert len(returned) == 1
    end = returned[0]
    return Endpoint(
        **assembly_registers(end),
        memory=claripy.Concat(
            *(end.memory.load(address, 1) for address in MEMORY_ADDRESSES)
        ),
        constraints=tuple(end.solver.constraints),
    )


def _native(values: dict[str, claripy.ast.BV]) -> Endpoint:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_copy_screen_tile_buffer_to_vram")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    for address in MEMORY_ADDRESSES:
        state.memory.store(NATIVE_MEMORY + address, values[f"memory_{address:x}"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    end = manager.deadended[0]
    return Endpoint(
        **native_registers(end, NATIVE_STATE),
        memory=claripy.Concat(
            *(end.memory.load(NATIVE_MEMORY + address, 1) for address in MEMORY_ADDRESSES)
        ),
        constraints=tuple(end.solver.constraints),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_copy_screen_tile_buffer_to_vram_pathwise_equivalence() -> None:
    values = _inputs("copy_screen")
    assert_pathwise_equivalent(
        [_assembly(values)],
        [_native(values)],
        (*REGISTERS, "memory"),
    )
