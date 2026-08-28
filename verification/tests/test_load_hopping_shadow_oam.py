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
from verification.harness.rom import linked_bytes, rom_window, symbol_location

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xEFFF

AUTO = 0xFFBA
LOADED_BANK = 0xFFB8
BANK_TEMP = 0xFF8B
ROMB = 0x2000
COPY_SOURCE = 0xFFCC
COPY_DEST = 0xFFCE
COPY_SIZE = 0xFFCB
VBLANK_OCCURRED = 0xFFD6
SHADOW_OAM = 0xC390


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


def _return_from_call(procedure: angr.SimProcedure) -> None:
    target = procedure.state.memory.load(
        procedure.state.regs.sp, 2, endness="Iend_LE"
    )
    procedure.state.regs.sp = procedure.state.regs.sp + 2
    procedure.jump(target)


class CopyVideoDataDoubleBoundary(angr.SimProcedure):
    """Complete c=1 CopyVideoDataDouble transition used by the caller."""

    def run(self) -> None:  # type: ignore[override]
        saved_auto = self.state.memory.load(AUTO, 1)
        saved_bank = self.state.memory.load(LOADED_BANK, 1)
        saved_f = self.state.regs.f

        self.state.memory.store(AUTO, claripy.BVV(0, 8))
        self.state.memory.store(BANK_TEMP, saved_bank)
        self.state.memory.store(LOADED_BANK, self.state.regs.b)
        self.state.memory.store(ROMB, self.state.regs.b)
        self.state.memory.store(COPY_SOURCE, self.state.regs.e)
        self.state.memory.store(COPY_SOURCE + 1, self.state.regs.d)
        self.state.memory.store(COPY_DEST, self.state.regs.l)
        self.state.memory.store(COPY_DEST + 1, self.state.regs.h)
        self.state.memory.store(COPY_SIZE, self.state.regs.c)
        self.state.memory.store(VBLANK_OCCURRED, claripy.BVV(0, 8))

        self.state.memory.store(LOADED_BANK, saved_bank)
        self.state.memory.store(ROMB, saved_bank)
        self.state.memory.store(AUTO, saved_auto)
        self.state.regs.a = saved_auto
        self.state.regs.f = saved_f
        _return_from_call(self)


class WriteOAMBlockBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        values = (
            0x54, 0x48, 0xFF, 0x10,
            0x54, 0x50, 0xFF, 0x30,
            0x5C, 0x48, 0xFF, 0x50,
            0x5C, 0x50, 0xFF, 0x70,
        )
        for index, value in enumerate(values):
            self.state.memory.store(SHADOW_OAM + index, claripy.BVV(value, 8))
        self.state.regs.a = claripy.BVV(0x70, 8)
        # The assembly-side register is still in the Z80 flag layout here;
        # H is bit 4 (the equivalence adapter maps it to canonical SM83 H).
        self.state.regs.f = claripy.BVV(0x10, 8)
        self.state.regs.b = claripy.BVV(0x5C, 8)
        self.state.regs.c = claripy.BVV(0x50, 8)
        self.state.regs.d = claripy.BVV(0x67, 8)
        self.state.regs.e = claripy.BVV(0x18, 8)
        self.state.regs.h = claripy.BVV(0xC3, 8)
        self.state.regs.l = claripy.BVV(0xA0, 8)
        _return_from_call(self)


class NativeDelayFrame(angr.SimProcedure):
    def run(self, delay_state: claripy.ast.BV, _observations: claripy.ast.BV) -> None:
        self.state.memory.store(delay_state, claripy.BVV(0, 8))
        self.state.memory.store(delay_state + 1, claripy.BVV(0x20, 8))
        self.state.memory.store(delay_state + 8, claripy.BVV(0, 8))


def _setup(state: angr.SimState, base: int, values: dict[str, claripy.ast.BV]) -> None:
    state.memory.store(base + AUTO, values["auto"])
    state.memory.store(base + LOADED_BANK, values["loaded_bank"])
    state.memory.store(base + BANK_TEMP, values["bank_temp"])
    state.memory.store(base + ROMB, values["romb"])
    state.memory.store(base + COPY_SOURCE, values["copy_source"])
    state.memory.store(base + COPY_SOURCE + 1, values["copy_source_high"])
    state.memory.store(base + COPY_DEST, values["copy_dest"])
    state.memory.store(base + COPY_DEST + 1, values["copy_dest_high"])
    state.memory.store(base + COPY_SIZE, values["copy_size"])
    state.memory.store(base + VBLANK_OCCURRED, values["vblank"])
    for index in range(16):
        state.memory.store(base + SHADOW_OAM + index, values[f"oam{index}"])


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    addresses = (
        AUTO, LOADED_BANK, BANK_TEMP, ROMB, COPY_SOURCE, COPY_SOURCE + 1,
        COPY_DEST, COPY_DEST + 1, COPY_SIZE, VBLANK_OCCURRED,
    )
    return claripy.Concat(
        *(state.memory.load(base + address, 1) for address in addresses),
        state.memory.load(base + SHADOW_OAM, 16),
    )


def _endpoint(state: angr.SimState, *, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    registers = native_registers(state, NATIVE_STATE) if native else assembly_registers(state)
    return Endpoint(
        **registers,
        memory=_memory(state, base),
        constraints=tuple(state.solver.constraints),
    )


def _values(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for field in (
        "auto", "loaded_bank", "bank_temp", "romb", "copy_source",
        "copy_source_high", "copy_dest", "copy_dest_high", "copy_size",
        "vblank",
    ):
        values[field] = claripy.BVS(f"{prefix}_{field}", 8)
    for index in range(16):
        values[f"oam{index}"] = claripy.BVS(f"{prefix}_oam{index}", 8)
    return values


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "LoadHoppingShadowOAM")
    shadow = symbol_location(SYMBOLS, "LedgeHoppingShadow")
    body = linked_bytes(ROM, location, shadow.address - location.address)
    assert len(body) == 24
    assert body == bytes.fromhex(
        "21f08f110867010106cd86183e09014854111067cd973ac9"
    )
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
    project.hook(0x1886, CopyVideoDataDoubleBoundary(), length=3)
    project.hook(0x3A97, WriteOAMBlockBoundary(), length=3)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    _setup(state, 0, values)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN, num_find=4)
    assert not manager.errored and len(manager.found) == 1
    return [_endpoint(end, native=False) for end in manager.found]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_load_hopping_shadow_oam")
    delay = project.loader.find_symbol("port_delay_frame")
    assert function is not None and delay is not None
    project.hook(delay.rebased_addr, NativeDelayFrame())
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, NATIVE_MEMORY, values)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [_endpoint(end, native=True) for end in manager.deadended]


@pytest.mark.skipif(
    not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),
    reason="build artifacts missing",
)
def test_load_hopping_shadow_oam_pathwise_equivalence() -> None:
    values = _values("load_hopping_shadow_oam")
    assert_pathwise_equivalent(
        _assembly(values), _native(values), (*REGISTERS, "memory")
    )
