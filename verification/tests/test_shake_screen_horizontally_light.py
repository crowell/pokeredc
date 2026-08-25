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
from verification.harness.rom import collect_returns, linked_bytes, rom_window, symbol_location
from verification.tests.test_shake_screen_horizontally_heavy import (
    AssemblyHorizontalSummary,
    Endpoint,
    NativeHorizontalSummary,
    STATE_FIELDS,
    _assembly_state,
    _inputs,
    _setup_globals,
)
from verification.tests.test_shake_screen_vertically import (
    AssemblySoundSummary,
    NativeSoundSummary,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
STACK = 0xD000
RETURN = 0xFFFF
EXPECTED = bytes.fromhex("cd6a5e0602c31052")


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    function = symbol_location(SYMBOLS, "ShakeScreenHorizontallyLight")
    horizontal = symbol_location(
        SYMBOLS, "AnimationShakeScreenHorizontallyFast"
    )
    assert linked_bytes(ROM, function, len(EXPECTED)) == EXPECTED
    project = angr.Project(
        rom_window(ROM, function.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": function.address,
        },
    )
    project.hook(
        function.address, AssemblySoundSummary(function.address + 3), length=3
    )
    project.hook(horizontal.address, AssemblyHorizontalSummary(), length=1)
    state = project.factory.blank_state(addr=function.address)
    set_assembly_registers(state, values)
    state.regs.sp = claripy.BVV(STACK, 16)
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    _setup_globals(state, values)
    ends = collect_returns(project, state, RETURN)
    assert len(ends) == 1
    return [
        Endpoint(
            **assembly_registers(end),
            state=_assembly_state(end),
            sound_call=end.globals["sound_call"],
            horizontal_call=end.globals["horizontal_call"],
            constraints=tuple(end.solver.constraints),
        )
        for end in ends
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_shake_screen_horizontally_light")
    sound = project.loader.find_symbol("port_play_applying_attack_sound")
    horizontal = project.loader.find_symbol(
        "port_animation_shake_screen_horizontally_fast"
    )
    assert function is not None and sound is not None and horizontal is not None
    project.hook(sound.rebased_addr, NativeSoundSummary())
    project.hook(horizontal.rebased_addr, NativeHorizontalSummary())
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(
        NATIVE_STATE + 8,
        claripy.Concat(*(values[name] for name in STATE_FIELDS)),
    )
    _setup_globals(state, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            state=end.memory.load(NATIVE_STATE, 38),
            sound_call=end.globals["sound_call"],
            horizontal_call=end.globals["horizontal_call"],
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_shake_screen_horizontally_light_pathwise_equivalence() -> None:
    values = _inputs("shake_screen_horizontally_light")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "state", "sound_call", "horizontal_call"),
    )
