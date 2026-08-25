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
    Sm83DecRegister,
    Sm83IncRegister,
    Sm83LoadAHighImmediate,
    Sm83StoreAHighImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
STACK = 0xD000
RETURN = 0xFFFF
WX = 0xFF4B
EXPECTED = bytes.fromhex(
    "c5c5f04b3ce04b0e02cd39370520f3c1f04b3de04b0e02cd39370520f3c10d20dfc9"
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
    wx: claripy.ast.BV
    vblank: claripy.ast.BV
    calls: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class AssemblyDelaySummary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.globals["calls"] = self.state.globals["calls"] + (
            claripy.Concat(
                *(assembly_registers(self.state)[name] for name in REGISTERS),
                self.state.memory.load(WX, 1),
                self.state.globals["vblank"],
            ),
        )
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x42, 8)
        self.state.regs.c = claripy.BVV(0, 8)
        self.state.globals["vblank"] = claripy.BVV(0, 8)
        return_address = self.state.memory.load(
            self.state.regs.sp, 2, endness="Iend_LE"
        )
        self.state.regs.sp += 2
        self.jump(return_address)


class NativeDelaySummary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        address = self.state.regs.rdi
        parent = self.state.globals["parent"]
        self.state.globals["calls"] = self.state.globals["calls"] + (
            claripy.Concat(
                self.state.memory.load(address, 8),
                self.state.memory.load(parent + 8, 1),
                self.state.memory.load(address + 8, 1),
            ),
        )
        self.state.memory.store(address, claripy.BVV(0, 8))
        self.state.memory.store(address + 1, claripy.BVV(0xC0, 8))
        self.state.memory.store(address + 3, claripy.BVV(0, 8))
        self.state.memory.store(address + 8, claripy.BVV(0, 8))


def _inputs(prefix: str, b: int) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["b"] = claripy.BVV(b, 8)
    values["c"] = claripy.BVV(2, 8)
    values["wx"] = claripy.BVS(f"{prefix}_wx", 8)
    values["vblank"] = claripy.BVS(f"{prefix}_vblank", 8)
    return values


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "AnimationShakeScreenHorizontallySlow")
    delay = symbol_location(SYMBOLS, "DelayFrames")
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
    q = location.address
    project.hook(q + 2, Sm83LoadAHighImmediate(0x4B, q + 4), length=2)
    project.hook(q + 4, Sm83IncRegister("a", q + 5), length=1)
    project.hook(q + 5, Sm83StoreAHighImmediate(0x4B, q + 7), length=2)
    project.hook(q + 12, Sm83DecRegister("b", q + 13), length=1)
    project.hook(q + 16, Sm83LoadAHighImmediate(0x4B, q + 18), length=2)
    project.hook(q + 18, Sm83DecRegister("a", q + 19), length=1)
    project.hook(q + 19, Sm83StoreAHighImmediate(0x4B, q + 21), length=2)
    project.hook(q + 26, Sm83DecRegister("b", q + 27), length=1)
    project.hook(q + 30, Sm83DecRegister("c", q + 31), length=1)
    project.hook(delay.address, AssemblyDelaySummary())
    state = project.factory.blank_state(addr=q)
    set_assembly_registers(state, values)
    state.regs.sp = claripy.BVV(STACK, 16)
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    state.memory.store(WX, values["wx"])
    state.globals["vblank"] = values["vblank"]
    state.globals["calls"] = ()
    return [
        Endpoint(
            **assembly_registers(end),
            wx=end.memory.load(WX, 1),
            vblank=end.globals["vblank"],
            calls=claripy.Concat(*end.globals["calls"]),
            constraints=tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, RETURN)
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(
        "port_animation_shake_screen_horizontally_slow"
    )
    delay = project.loader.find_symbol("port_delay_frames")
    assert function is not None and delay is not None
    project.hook(delay.rebased_addr, NativeDelaySummary())
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(
        NATIVE_STATE + 8,
        claripy.Concat(values["wx"], values["vblank"]),
    )
    state.globals["parent"] = claripy.BVV(NATIVE_STATE, 64)
    state.globals["calls"] = ()
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            wx=end.memory.load(NATIVE_STATE + 8, 1),
            vblank=end.memory.load(NATIVE_STATE + 9, 1),
            calls=claripy.Concat(*end.globals["calls"]),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_animation_shake_screen_horizontally_slow_pathwise_equivalence() -> None:
    for b in (6, 3):
        values = _inputs(f"animation_shake_slow_{b}", b)
        assert_pathwise_equivalent(
            _assembly(values),
            _native(values),
            (*REGISTERS, "wx", "vblank", "calls"),
        )
