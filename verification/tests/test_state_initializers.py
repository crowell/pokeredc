from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode
from pypcode import Context

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
    REGISTERS,
    assembly_registers,
    native_registers,
    set_assembly_registers,
    store_native_registers,
    symbolic_registers,
)
from verification.harness.rom import collect_returns, linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import (
    Sm83StoreAHighImmediate,
    Sm83StoreAImmediate,
)


ROOT = Path(__file__).resolve().parents[2]
VERIFY = ROOT / "verification"
NATIVE_ELF = VERIFY / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
GB_STACK = 0xD000
GB_RETURN = 0xFFFF
NATIVE_STATE = 0x100000


@dataclass(frozen=True)
class TwoMemoryEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    memory0: claripy.ast.BV
    memory1: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class OneMemoryEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    memory0: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class ThreeMemoryEndpoint(TwoMemoryEndpoint):
    memory2: claripy.ast.BV


def _project(symbol: str) -> tuple[angr.Project, int]:
    location = symbol_location(SYMBOLS, symbol)
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
    return project, location.address


def _return_state(project: angr.Project, address: int, inputs: dict[str, claripy.ast.BV]) -> angr.SimState:
    state = project.factory.blank_state(addr=address)
    set_assembly_registers(state, inputs)
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    assert len(returned) == 1
    return returned[0]


def _native_return(c_symbol: str, inputs: dict[str, claripy.ast.BV]) -> angr.SimState:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(c_symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    return manager.deadended[0]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_init_options_symbolic_equivalence() -> None:
    inputs = symbolic_registers("init_options")
    inputs["memory0"] = claripy.BVS("init_options_delay", 8)
    inputs["memory1"] = claripy.BVS("init_options_options", 8)
    project, address = _project("InitOptions")
    delay = symbol_location(SYMBOLS, "wLetterPrintingDelayFlags").address
    options = symbol_location(SYMBOLS, "wOptions").address
    project.hook(address + 2, Sm83StoreAImmediate(delay, address + 5), length=3)
    project.hook(address + 7, Sm83StoreAImmediate(options, address + 10), length=3)
    initial = project.factory.blank_state(addr=address)
    set_assembly_registers(initial, inputs)
    initial.memory.store(delay, inputs["memory0"])
    initial.memory.store(options, inputs["memory1"])
    initial.regs.sp = GB_STACK
    initial.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    assembly_state = collect_returns(project, initial, GB_RETURN)[0]
    assembly = TwoMemoryEndpoint(
        **assembly_registers(assembly_state),
        memory0=assembly_state.memory.load(delay, 1),
        memory1=assembly_state.memory.load(options, 1),
        constraints=tuple(assembly_state.solver.constraints),
    )
    native_state = _native_return("port_init_options", inputs)
    native = TwoMemoryEndpoint(
        **native_registers(native_state, NATIVE_STATE),
        memory0=native_state.memory.load(NATIVE_STATE + 8, 1),
        memory1=native_state.memory.load(NATIVE_STATE + 9, 1),
        constraints=tuple(native_state.solver.constraints),
    )
    assert_pathwise_equivalent([assembly], [native], (*REGISTERS, "memory0", "memory1"))


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_discard_button_presses_symbolic_equivalence() -> None:
    inputs = symbolic_registers("discard_buttons")
    for index, name in enumerate(("held", "pressed", "released")):
        inputs[f"memory{index}"] = claripy.BVS(f"discard_buttons_{name}", 8)
    project, address = _project("DiscardButtonPresses")
    offsets = (0xB4, 0xB3, 0xB2)
    for index, offset in enumerate(offsets):
        start = address + 1 + index * 2
        project.hook(start, Sm83StoreAHighImmediate(offset, start + 2), length=2)
    initial = project.factory.blank_state(addr=address)
    set_assembly_registers(initial, inputs)
    for index, offset in enumerate(offsets):
        initial.memory.store(0xFF00 | offset, inputs[f"memory{index}"])
    initial.regs.sp = GB_STACK
    initial.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    assembly_state = collect_returns(project, initial, GB_RETURN)[0]
    assembly = ThreeMemoryEndpoint(
        **assembly_registers(assembly_state),
        memory0=assembly_state.memory.load(0xFFB4, 1),
        memory1=assembly_state.memory.load(0xFFB3, 1),
        memory2=assembly_state.memory.load(0xFFB2, 1),
        constraints=tuple(assembly_state.solver.constraints),
    )
    native_state = _native_return("port_discard_button_presses", inputs)
    native = ThreeMemoryEndpoint(
        **native_registers(native_state, NATIVE_STATE),
        memory0=native_state.memory.load(NATIVE_STATE + 8, 1),
        memory1=native_state.memory.load(NATIVE_STATE + 9, 1),
        memory2=native_state.memory.load(NATIVE_STATE + 10, 1),
        constraints=tuple(native_state.solver.constraints),
    )
    assert_pathwise_equivalent(
        [assembly], [native], (*REGISTERS, "memory0", "memory1", "memory2")
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_init_yes_no_text_box_parameters_symbolic_equivalence() -> None:
    inputs = symbolic_registers("init_yes_no")
    inputs["memory0"] = claripy.BVS("init_yes_no_menu_id", 8)
    project, address = _project("InitYesNoTextBoxParameters")
    menu_id = symbol_location(SYMBOLS, "wTwoOptionMenuID").address
    project.hook(address + 1, Sm83StoreAImmediate(menu_id, address + 4), length=3)
    initial = project.factory.blank_state(addr=address)
    set_assembly_registers(initial, inputs)
    initial.memory.store(menu_id, inputs["memory0"])
    initial.regs.sp = GB_STACK
    initial.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    assembly_state = collect_returns(project, initial, GB_RETURN)[0]
    assembly = OneMemoryEndpoint(
        **assembly_registers(assembly_state),
        memory0=assembly_state.memory.load(menu_id, 1),
        constraints=tuple(assembly_state.solver.constraints),
    )
    native_state = _native_return("port_init_yes_no_text_box_parameters", inputs)
    native = OneMemoryEndpoint(
        **native_registers(native_state, NATIVE_STATE),
        memory0=native_state.memory.load(NATIVE_STATE + 8, 1),
        constraints=tuple(native_state.solver.constraints),
    )
    assert_pathwise_equivalent([assembly], [native], (*REGISTERS, "memory0"))


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_reset_using_strength_bit_symbolic_equivalence() -> None:
    inputs = symbolic_registers("reset_strength")
    inputs["memory0"] = claripy.BVS("reset_strength_status", 8)
    project, address = _project("ResetUsingStrengthOutOfBattleBit")
    status = symbol_location(SYMBOLS, "wStatusFlags1").address
    initial = project.factory.blank_state(addr=address)
    set_assembly_registers(initial, inputs)
    initial.memory.store(status, inputs["memory0"])
    initial.regs.sp = GB_STACK
    initial.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    assembly_state = collect_returns(project, initial, GB_RETURN)[0]
    assembly = OneMemoryEndpoint(
        **assembly_registers(assembly_state),
        memory0=assembly_state.memory.load(status, 1),
        constraints=tuple(assembly_state.solver.constraints),
    )
    native_project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = native_project.loader.find_symbol("port_reset_using_strength_out_of_battle_bit")
    assert function is not None
    native_initial = native_project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(native_initial, NATIVE_STATE, inputs)
    native_initial.memory.store(NATIVE_STATE + 8, inputs["memory0"])
    manager = native_project.factory.simulation_manager(native_initial)
    manager.run()
    native_state = manager.deadended[0]
    native = OneMemoryEndpoint(
        **native_registers(native_state, NATIVE_STATE),
        memory0=native_state.memory.load(NATIVE_STATE + 8, 1),
        constraints=tuple(native_state.solver.constraints),
    )
    assert_pathwise_equivalent([assembly], [native], (*REGISTERS, "memory0"))


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "size", "expected"),
    [
        ("InitOptions", 11, "3e01ea58d33e03ea55d3c9"),
        ("DiscardButtonPresses", 8, "afe0b4e0b3e0b2c9"),
        ("InitYesNoTextBoxParameters", 11, "afea2cd1213ac4010f08c9"),
    ],
)
def test_state_initializer_machine_code_is_accounted_for(
    symbol: str, size: int, expected: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, size) == bytes.fromhex(expected)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_reset_using_strength_bit_uses_z80_compatible_encodings() -> None:
    location = symbol_location(SYMBOLS, "ResetUsingStrengthOutOfBattleBit")
    instructions = Context("z80:LE:16:default").disassemble(
        linked_bytes(ROM, location, 6), location.address
    ).instructions
    assert [(item.mnem, item.body, item.length) for item in instructions] == [
        ("LD", "HL,0xd728", 3),
        ("RES", "0x0,(HL)", 2),
        ("RET", "", 1),
    ]
