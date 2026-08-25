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
from verification.tests.test_copy_temp_pic_to_mon_pic import (
    _hook_copy_video_data,
)
from verification.tests.test_copy_video_data import (
    ADDRESSES,
    EXPECTED as COPY_VIDEO_EXPECTED,
    FIELDS,
    ROMB,
    AssemblyDelayFrame,
    NativeDelayFrame,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xFFFF
EXPECTED = bytes.fromhex("21f08f11594a01011cc34818")


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
    hardware: claripy.ast.BV
    calls: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for field in FIELDS:
        values[field] = claripy.BVS(f"{prefix}_{field}", 8)
    return values


def _hardware(state: angr.SimState, base: int = 0) -> claripy.ast.BV:
    romb = (
        state.globals["romb"]
        if base == 0
        else state.memory.load(base + ROMB, 1)
    )
    return claripy.Concat(
        *(
            romb
            if address == ROMB
            else state.memory.load(base + address, 1)
            for address in ADDRESSES
        )
    )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "LoadBattleTransitionTile")
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
    _hook_copy_video_data(project, copy_video.address)
    project.hook(delay.address, AssemblyDelayFrame())
    state = project.factory.blank_state(addr=location.address)
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
            hardware=_hardware(end),
            calls=claripy.Concat(*end.globals["calls"]),
            constraints=tuple(end.solver.constraints),
        )
        for end in ends
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_load_battle_transition_tile")
    copy_video = project.loader.find_symbol("port_copy_video_data")
    delay = project.loader.find_symbol("port_delay_frame")
    assert function is not None and copy_video is not None and delay is not None
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
            hardware=_hardware(end, NATIVE_MEMORY),
            calls=claripy.Concat(*end.globals["calls"]),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(
    not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`"
)
def test_load_battle_transition_tile_pathwise_equivalence() -> None:
    values = _inputs("load_battle_transition_tile")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "hardware", "calls"),
    )
