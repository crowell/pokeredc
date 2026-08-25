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
from verification.tests.test_copy_video_data import (
    ADDRESSES,
    AUTO,
    BANK_TEMP,
    COPY_DEST,
    COPY_SIZE,
    COPY_SOURCE,
    EXPECTED as COPY_VIDEO_EXPECTED,
    FIELDS,
    LOADED_BANK,
    ROMB,
    AssemblyDelayFrame,
    NativeDelayFrame,
    StoreRomb,
    XorA,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xFFFF
WHOSE_TURN = 0xFFF3
EXPECTED = bytes.fromhex("f0f3a7211093280321009011e8c6013100c34818")


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
    calls: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class AndA(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.f = claripy.BVV(0x10, 8) | claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x40, 8),
            claripy.BVV(0, 8),
        )
        self.jump(self._next_address)


def _hook_copy_video_data(project: angr.Project, q: int) -> None:
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


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["whose_turn"] = claripy.BVS(f"{prefix}_whose_turn", 8)
    for field in FIELDS:
        values[field] = claripy.BVS(f"{prefix}_{field}", 8)
    return values


def _state(state: angr.SimState, base: int = 0) -> claripy.ast.BV:
    hardware = (
        state.globals["romb"]
        if base == 0
        else state.memory.load(base + ROMB, 1)
    )
    return claripy.Concat(
        state.memory.load(base + WHOSE_TURN, 1),
        *(
            hardware
            if address == ROMB
            else state.memory.load(base + address, 1)
            for address in ADDRESSES
        ),
    )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "CopyTempPicToMonPic")
    copy_video = symbol_location(SYMBOLS, "CopyVideoData")
    delay = symbol_location(SYMBOLS, "DelayFrame")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    assert (
        linked_bytes(ROM, copy_video, len(COPY_VIDEO_EXPECTED))
        == COPY_VIDEO_EXPECTED
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
    project.hook(
        location.address,
        Sm83LoadAHighImmediate(WHOSE_TURN & 0xFF, location.address + 2),
        length=2,
    )
    project.hook(location.address + 2, AndA(location.address + 3), length=1)
    _hook_copy_video_data(project, copy_video.address)
    project.hook(delay.address, AssemblyDelayFrame())
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.regs.sp = claripy.BVV(STACK, 16)
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    state.memory.store(WHOSE_TURN, values["whose_turn"])
    for address, field in zip(ADDRESSES, FIELDS):
        state.memory.store(address, values[field])
    state.globals["romb"] = values["romb"]
    state.globals["calls"] = ()
    ends = collect_returns(project, state, RETURN)
    assert len(ends) == 2
    return [
        Endpoint(
            **assembly_registers(end),
            state=_state(end),
            calls=claripy.Concat(*end.globals["calls"]),
            constraints=tuple(end.solver.constraints),
        )
        for end in ends
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_copy_temp_pic_to_mon_pic")
    copy_video = project.loader.find_symbol("port_copy_video_data")
    delay = project.loader.find_symbol("port_delay_frame")
    assert function is not None and copy_video is not None and delay is not None
    project.hook(delay.rebased_addr, NativeDelayFrame())
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_MEMORY + WHOSE_TURN, values["whose_turn"])
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
            state=_state(end, NATIVE_MEMORY),
            calls=claripy.Concat(*end.globals["calls"]),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(
    not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`"
)
def test_copy_temp_pic_to_mon_pic_pathwise_equivalence() -> None:
    values = _inputs("copy_temp_pic_to_mon_pic")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "state", "calls"),
    )
