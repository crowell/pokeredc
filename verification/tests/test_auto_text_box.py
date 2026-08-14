from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.rom import (
    collect_returns,
    linked_bytes,
    rom_window,
    sm83_flags_to_z80,
    symbol_location,
    z80_flags_to_sm83,
)
from verification.harness.sm83_shims import Sm83StoreAImmediate


ROOT = Path(__file__).resolve().parents[2]
VERIFY = ROOT / "verification"
NATIVE_ELF = VERIFY / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
GB_STACK = 0xD000
GB_RETURN = 0xFFFF
NATIVE_STATE = 0x100000
REGISTERS = ("a", "f", "b", "c", "d", "e", "h", "l")


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
    auto_control: claripy.ast.BV
    do_not_wait: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _assembly_endpoint(symbol: str, inputs: dict[str, claripy.ast.BV]) -> Endpoint:
    location = symbol_location(SYMBOLS, symbol)
    auto_control = symbol_location(SYMBOLS, "wAutoTextBoxDrawingControl").address
    do_not_wait = symbol_location(
        SYMBOLS, "wDoNotWaitForButtonPressAfterDisplayingText"
    ).address
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
    if symbol == "DisableWaitingAfterTextDisplay":
        project.hook(
            location.address + 2,
            Sm83StoreAImmediate(
                address=do_not_wait, next_address=location.address + 5
            ),
            length=3,
        )
    else:
        project.hook(
            0x3C41,
            Sm83StoreAImmediate(address=auto_control, next_address=0x3C44),
            length=3,
        )
        project.hook(
            0x3C45,
            Sm83StoreAImmediate(address=do_not_wait, next_address=0x3C48),
            length=3,
        )
    state = project.factory.blank_state(addr=location.address)
    for register in REGISTERS:
        value = inputs[register]
        if register == "f":
            value = sm83_flags_to_z80(value)
        setattr(state.regs, register, value)
    state.memory.store(auto_control, inputs["auto_control"])
    state.memory.store(do_not_wait, inputs["do_not_wait"])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    assert len(returned) == 1
    end = returned[0]
    return Endpoint(
        a=end.regs.a,
        f=z80_flags_to_sm83(end.regs.f),
        b=end.regs.b,
        c=end.regs.c,
        d=end.regs.d,
        e=end.regs.e,
        h=end.regs.h,
        l=end.regs.l,
        auto_control=end.memory.load(auto_control, 1),
        do_not_wait=end.memory.load(do_not_wait, 1),
        constraints=tuple(end.solver.constraints),
    )


def _native_endpoint(c_symbol: str, inputs: dict[str, claripy.ast.BV]) -> Endpoint:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(c_symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    for offset, register in enumerate(REGISTERS):
        state.memory.store(NATIVE_STATE + offset, inputs[register])
    state.memory.store(NATIVE_STATE + 8, inputs["auto_control"])
    state.memory.store(NATIVE_STATE + 9, inputs["do_not_wait"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    end = manager.deadended[0]
    values = {
        register: end.memory.load(NATIVE_STATE + offset, 1)
        for offset, register in enumerate(REGISTERS)
    }
    return Endpoint(
        **values,
        auto_control=end.memory.load(NATIVE_STATE + 8, 1),
        do_not_wait=end.memory.load(NATIVE_STATE + 9, 1),
        constraints=tuple(end.solver.constraints),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("assembly_symbol", "c_symbol"),
    [
        ("EnableAutoTextBoxDrawing", "port_enable_auto_text_box_drawing"),
        ("DisableAutoTextBoxDrawing", "port_disable_auto_text_box_drawing"),
        (
            "DisableWaitingAfterTextDisplay",
            "port_disable_waiting_after_text_display",
        ),
        (
            "AutoTextBoxDrawingCommon",
            "port_auto_text_box_drawing_common",
        ),
    ],
)
def test_auto_text_box_symbolic_equivalence(
    assembly_symbol: str, c_symbol: str
) -> None:
    inputs = {
        name: (
            claripy.Concat(claripy.BVS(f"{assembly_symbol}_flags", 4), claripy.BVV(0, 4))
            if name == "f"
            else claripy.BVS(f"{assembly_symbol}_{name}", 8)
        )
        for name in (*REGISTERS, "auto_control", "do_not_wait")
    }
    assert_pathwise_equivalent(
        [_assembly_endpoint(assembly_symbol, inputs)],
        [_native_endpoint(c_symbol, inputs)],
        (*REGISTERS, "auto_control", "do_not_wait"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_auto_text_box_machine_code_is_fully_accounted_for() -> None:
    location = symbol_location(SYMBOLS, "EnableAutoTextBoxDrawing")
    # Includes both public entries and their shared tail. The two EA opcodes
    # are covered by Sm83StoreAImmediate hooks in the proof above.
    assert linked_bytes(ROM, location, 13) == bytes.fromhex(
        "af18023e01ea0ccfafea3cccc9"
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_disable_waiting_after_text_display_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "DisableWaitingAfterTextDisplay")
    destination = symbol_location(
        SYMBOLS, "wDoNotWaitForButtonPressAfterDisplayingText"
    ).address
    assert linked_bytes(ROM, location, 6) == bytes(
        (0x3E, 1, 0xEA, destination & 0xFF, destination >> 8, 0xC9)
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_auto_text_box_drawing_common_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "AutoTextBoxDrawingCommon")
    auto_control = symbol_location(SYMBOLS, "wAutoTextBoxDrawingControl").address
    do_not_wait = symbol_location(
        SYMBOLS, "wDoNotWaitForButtonPressAfterDisplayingText"
    ).address
    assert linked_bytes(ROM, location, 8) == bytes(
        (
            0xEA,
            auto_control & 0xFF,
            auto_control >> 8,
            0xAF,
            0xEA,
            do_not_wait & 0xFF,
            do_not_wait >> 8,
            0xC9,
        )
    )
