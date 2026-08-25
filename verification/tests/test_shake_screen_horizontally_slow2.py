from __future__ import annotations

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
)
from verification.harness.rom import (
    collect_returns,
    linked_bytes,
    rom_window,
    symbol_location,
)
from verification.tests.test_shake_screen_horizontally_slow import (
    AssemblySlowSummary,
    Endpoint,
    NativeSlowSummary,
    _inputs,
    _setup,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
STACK = 0xD000
RETURN = 0xFFFF
EXPECTED = bytes.fromhex("010203")


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "ShakeScreenHorizontallySlow2")
    slow = symbol_location(SYMBOLS, "AnimationShakeScreenHorizontallySlow")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    assert location.address + len(EXPECTED) == slow.address
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
    project.hook(slow.address, AssemblySlowSummary())
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.regs.sp = claripy.BVV(STACK, 16)
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    state.globals["wx"] = values["wx"]
    state.globals["vblank"] = values["vblank"]
    _setup(state, values)
    return [
        Endpoint(
            **assembly_registers(end),
            state=claripy.Concat(end.globals["wx"], end.globals["vblank"]),
            slow_call=end.globals["slow_call"],
            constraints=tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, RETURN)
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_shake_screen_horizontally_slow2")
    slow = project.loader.find_symbol(
        "port_animation_shake_screen_horizontally_slow"
    )
    assert function is not None and slow is not None
    project.hook(slow.rebased_addr, NativeSlowSummary())
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(
        NATIVE_STATE + 8, claripy.Concat(values["wx"], values["vblank"])
    )
    _setup(state, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            state=end.memory.load(NATIVE_STATE + 8, 2),
            slow_call=end.globals["slow_call"],
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_shake_screen_horizontally_slow2_pathwise_equivalence() -> None:
    values = _inputs("shake_screen_horizontally_slow2")
    assert_pathwise_equivalent(
        _assembly(values), _native(values), (*REGISTERS, "state", "slow_call")
    )
