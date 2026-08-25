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
    sm83_flags_to_z80,
    symbol_location,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
STACK = 0xD000
RETURN = 0xFFFF
EXPECTED = bytes.fromhex("0608")

W_PREDEF_ID = 0xCC4E
SAVED = (0xCC4F, 0xCC50, 0xCC51, 0xCC52, 0xCC53, 0xCC54)
W_PREDEF_PARENT = 0xCF12
W_PREDEF_BANK = 0xD0B7
MUTATE_WX = 0xFF97
WX = 0xFF4B
H_LOADED_ROM_BANK = 0xFFB8
R_ROMB = 0x2000
MEMORY_FIELDS = (
    *SAVED,
    MUTATE_WX,
    WX,
    W_PREDEF_ID,
    W_PREDEF_PARENT,
    W_PREDEF_BANK,
    H_LOADED_ROM_BANK,
    R_ROMB,
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
    state: claripy.ast.BV
    wrapper_call: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _assembly_state(state: angr.SimState) -> claripy.ast.BV:
    return claripy.Concat(
        *(assembly_registers(state)[name] for name in REGISTERS),
        *(state.memory.load(address, 1) for address in MEMORY_FIELDS),
    )


class AssemblyHorizontalWrapper(angr.SimProcedure):
    def run(self) -> None:
        self.state.globals["wrapper_call"] = _assembly_state(self.state)
        for name in REGISTERS:
            value = self.state.globals[f"wrapper_out_{name}"]
            if name == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, name, value)
        for index, address in enumerate(MEMORY_FIELDS):
            self.state.memory.store(address, self.state.globals[f"wrapper_out_{index}"])
        return_address = self.state.memory.load(
            self.state.regs.sp, 2, endness="Iend_LE"
        )
        self.state.regs.sp += 2
        self.jump(return_address)


class NativeHorizontalWrapper(angr.SimProcedure):
    def run(self) -> None:
        address = self.state.regs.rdi
        self.state.globals["wrapper_call"] = self.state.memory.load(address, 21)
        self.state.memory.store(
            address,
            claripy.Concat(
                *(self.state.globals[f"wrapper_out_{name}"] for name in REGISTERS),
                *(self.state.globals[f"wrapper_out_{index}"] for index in range(13)),
            ),
        )


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for index in range(13):
        values[f"field_{index}"] = claripy.BVS(f"{prefix}_field_{index}", 8)
        values[f"wrapper_out_{index}"] = claripy.BVS(
            f"{prefix}_wrapper_out_{index}", 8
        )
    for name in REGISTERS:
        if name == "f":
            values[f"wrapper_out_{name}"] = claripy.Concat(
                claripy.BVS(f"{prefix}_wrapper_out_flags", 4), claripy.BVV(0, 4)
            )
        else:
            values[f"wrapper_out_{name}"] = claripy.BVS(
                f"{prefix}_wrapper_out_{name}", 8
            )
    return values


def _setup_globals(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    state.globals["wrapper_call"] = claripy.BVV(0, 21 * 8)
    for name in REGISTERS:
        state.globals[f"wrapper_out_{name}"] = values[f"wrapper_out_{name}"]
    for index in range(13):
        state.globals[f"wrapper_out_{index}"] = values[f"wrapper_out_{index}"]


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    function = symbol_location(SYMBOLS, "AnimationShakeScreen")
    wrapper = symbol_location(SYMBOLS, "AnimationShakeScreenHorizontallyFast")
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
    project.hook(wrapper.address, AssemblyHorizontalWrapper(), length=1)
    state = project.factory.blank_state(addr=function.address)
    set_assembly_registers(state, values)
    for index, address in enumerate(MEMORY_FIELDS):
        state.memory.store(address, values[f"field_{index}"])
    state.regs.sp = claripy.BVV(STACK, 16)
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    _setup_globals(state, values)
    ends = collect_returns(project, state, RETURN)
    assert len(ends) == 1
    return [
        Endpoint(
            **assembly_registers(end),
            state=_assembly_state(end),
            wrapper_call=end.globals["wrapper_call"],
            constraints=tuple(end.solver.constraints),
        )
        for end in ends
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_animation_shake_screen")
    wrapper = project.loader.find_symbol(
        "port_animation_shake_screen_horizontally_fast"
    )
    assert function is not None and wrapper is not None
    project.hook(wrapper.rebased_addr, NativeHorizontalWrapper())
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(
        NATIVE_STATE + 8,
        claripy.Concat(*(values[f"field_{index}"] for index in range(13))),
    )
    _setup_globals(state, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            state=end.memory.load(NATIVE_STATE, 21),
            wrapper_call=end.globals["wrapper_call"],
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_animation_shake_screen_pathwise_equivalence() -> None:
    values = _inputs("animation_shake_screen")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "state", "wrapper_call"),
    )
