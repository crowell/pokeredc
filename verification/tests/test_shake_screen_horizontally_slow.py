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
EXPECTED = bytes.fromhex("0102061811")


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
    slow_call: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class AssemblySlowSummary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.globals["slow_call"] = claripy.Concat(
            *(assembly_registers(self.state)[name] for name in REGISTERS),
            self.state.globals["wx"],
            self.state.globals["vblank"],
        )
        for register in REGISTERS:
            value = self.state.globals[f"out_{register}"]
            if register == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, register, value)
        self.state.globals["wx"] = self.state.globals["out_wx"]
        self.state.globals["vblank"] = self.state.globals["out_vblank"]
        return_address = self.state.memory.load(
            self.state.regs.sp, 2, endness="Iend_LE"
        )
        self.state.regs.sp += 2
        self.jump(return_address)


class NativeSlowSummary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        address = self.state.regs.rdi
        self.state.globals["slow_call"] = self.state.memory.load(address, 10)
        self.state.memory.store(
            address,
            claripy.Concat(
                *(self.state.globals[f"out_{name}"] for name in REGISTERS),
                self.state.globals["out_wx"],
                self.state.globals["out_vblank"],
            ),
        )


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["wx"] = claripy.BVS(f"{prefix}_wx", 8)
    values["vblank"] = claripy.BVS(f"{prefix}_vblank", 8)
    for name in (*REGISTERS, "wx", "vblank"):
        if name == "f":
            values["out_f"] = claripy.Concat(
                claripy.BVS(f"{prefix}_out_flags", 4), claripy.BVV(0, 4)
            )
        else:
            values[f"out_{name}"] = claripy.BVS(f"{prefix}_out_{name}", 8)
    return values


def _setup(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    for name in (*REGISTERS, "wx", "vblank"):
        state.globals[f"out_{name}"] = values[f"out_{name}"]


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "ShakeScreenHorizontallySlow")
    slow = symbol_location(SYMBOLS, "AnimationShakeScreenHorizontallySlow")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
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
    function = project.loader.find_symbol("port_shake_screen_horizontally_slow")
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
def test_shake_screen_horizontally_slow_pathwise_equivalence() -> None:
    values = _inputs("shake_screen_horizontally_slow")
    assert_pathwise_equivalent(
        _assembly(values), _native(values), (*REGISTERS, "state", "slow_call")
    )
