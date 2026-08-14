from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
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
from verification.harness.sm83_shims import Sm83StoreAImmediate


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification" / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
GB_STACK = 0xD000
GB_RETURN = 0xFFFF
NATIVE_STATE = 0x100000
W_AUDIO_FADE_OUT_CONTROL = 0xCFC7
W_AUDIO_FADE_OUT_COUNTER_RELOAD = 0xCFC8
W_AUDIO_FADE_OUT_COUNTER = 0xCFC9


class JumpTo(angr.SimProcedure):
    """Replace a ``jp`` with a direct jump to a fixed address (used to model
    the ``jp GBFadeOutToWhite`` tail as the function's endpoint)."""

    def __init__(self, address: int, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._address = address

    def run(self) -> None:  # type: ignore[override]
        self.jump(self._address)


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
    m_control: claripy.ast.BV
    m_reload: claripy.ast.BV
    m_counter: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _assembly_endpoint(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "HoFFadeOutScreenAndMusic")
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
    state = project.factory.blank_state(addr=location.address)
    base = location.address
    # SM83 EA absolute stores (opcode EA absent from the Z80 p-code)
    project.hook(
        base + 0x02,
        Sm83StoreAImmediate(W_AUDIO_FADE_OUT_COUNTER_RELOAD, base + 0x05),
        length=3,
    )
    project.hook(
        base + 0x05,
        Sm83StoreAImmediate(W_AUDIO_FADE_OUT_COUNTER, base + 0x08),
        length=3,
    )
    project.hook(
        base + 0x0A,
        Sm83StoreAImmediate(W_AUDIO_FADE_OUT_CONTROL, base + 0x0D),
        length=3,
    )
    # jp GBFadeOutToWhite -> endpoint
    project.hook(base + 0x0D, JumpTo(GB_RETURN), length=3)
    set_assembly_registers(state, inputs)
    state.regs.sp = claripy.BVV(GB_STACK, 16)
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    return [
        Endpoint(
            **assembly_registers(end),
            m_control=end.memory.load(W_AUDIO_FADE_OUT_CONTROL, 1),
            m_reload=end.memory.load(W_AUDIO_FADE_OUT_COUNTER_RELOAD, 1),
            m_counter=end.memory.load(W_AUDIO_FADE_OUT_COUNTER, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in returned
    ]


def _native_endpoint(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(
        "port_ho_f_fade_out_screen_and_music"
    )
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, claripy.BVV(0, 64)
    )
    store_native_registers(state, NATIVE_STATE, inputs)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            m_control=end.memory.load(W_AUDIO_FADE_OUT_CONTROL, 1),
            m_reload=end.memory.load(W_AUDIO_FADE_OUT_COUNTER_RELOAD, 1),
            m_counter=end.memory.load(W_AUDIO_FADE_OUT_COUNTER, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_ho_f_fade_out_screen_and_music_symbolic_equivalence() -> None:
    inputs = symbolic_registers("hof")
    assembly = _assembly_endpoint(inputs)
    native = _native_endpoint(inputs)
    assert_pathwise_equivalent(
        assembly,
        native,
        (
            "a",
            "f",
            "b",
            "c",
            "d",
            "e",
            "h",
            "l",
            "m_control",
            "m_reload",
            "m_counter",
        ),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_ho_f_fade_out_screen_and_music_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "HoFFadeOutScreenAndMusic")
    expected = bytes.fromhex("3e0aeac8cfeac9cf3effeac7cfc3d820")
    assert linked_bytes(ROM, location, len(expected)) == expected
