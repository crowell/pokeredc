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
    rom_window,
    sm83_flags_to_z80,
    symbol_location,
    z80_flags_to_sm83,
)
from verification.harness.sm83_shims import Sm83LoadAHighImmediate

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
RETURN = 0xEFFF
H_JOYINPUT = 0xFFF8
H_JOYLAST = 0xFFB1
H_JOYRELEASED = 0xFFB2
H_JOYPRESSED = 0xFFB3
H_JOYHELD = 0xFFB4
H_LOADED = 0xFFB8
R_ROMB = 0x2000


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
    memory: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class JoypadBoundary(angr.SimProcedure):
    def __init__(self, inputs: tuple[int, ...], next_address: int) -> None:
        super().__init__()
        self.inputs = inputs
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        index = self.state.globals.get("poll_index", 0)
        value = self.inputs[index]
        last = self.state.memory.load(H_JOYLAST, 1)
        self.state.memory.store(H_JOYINPUT, claripy.BVV(value, 8))
        self.state.memory.store(H_JOYRELEASED, (last ^ value) & last)
        self.state.memory.store(H_JOYPRESSED, (last ^ value) & value)
        self.state.memory.store(H_JOYLAST, claripy.BVV(value, 8))
        self.state.memory.store(H_JOYHELD, claripy.BVV(value, 8))
        self.state.memory.store(R_ROMB, self.state.memory.load(H_LOADED, 1))
        self.state.regs.e = last
        self.state.regs.d = last ^ value
        self.state.regs.b = claripy.BVV(value, 8)
        self.state.globals["poll_index"] = index + 1
        self.jump(self.next_address)


class BitA(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        bit_set = (self.state.regs.a & 1) != 0
        canonical = claripy.If(bit_set, claripy.BVV(0x20, 8), claripy.BVV(0xA0, 8))
        canonical = canonical | (z80_flags_to_sm83(self.state.regs.f) & 0x10)
        self.state.regs.f = sm83_flags_to_z80(canonical)
        self.jump(self.state.addr + 2)


class BranchNZ(angr.SimProcedure):
    def __init__(self, loop: int, done: int) -> None:
        super().__init__()
        self.loop = loop
        self.done = done

    def run(self) -> None:  # type: ignore[override]
        z_set = ((self.state.regs.f >> 6) & 1) == 1
        self.inhibit_autoret = True
        taken = self.state.copy()
        fallthrough = self.state.copy()
        taken.solver.add(claripy.Not(z_set))
        fallthrough.solver.add(z_set)
        self.successors.add_successor(taken, self.loop, claripy.Not(z_set), "Ijk_Boring")
        self.successors.add_successor(fallthrough, self.done, z_set, "Ijk_Boring")


class ReturnBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.jump(RETURN)


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["last"] = claripy.BVS(f"{prefix}_last", 8)
    values["loaded"] = claripy.BVS(f"{prefix}_loaded", 8)
    values["romb"] = claripy.BVS(f"{prefix}_romb", 8)
    return values


def _setup(state: angr.SimState, base: int, values: dict[str, claripy.ast.BV]) -> None:
    state.memory.store(base + H_JOYLAST, values["last"])
    state.memory.store(base + H_JOYINPUT, claripy.BVV(0, 8))
    state.memory.store(base + H_JOYRELEASED, claripy.BVV(0, 8))
    state.memory.store(base + H_JOYPRESSED, claripy.BVV(0, 8))
    state.memory.store(base + H_JOYHELD, claripy.BVV(0, 8))
    state.memory.store(base + H_LOADED, values["loaded"])
    state.memory.store(base + R_ROMB, values["romb"])


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        state.memory.load(base + H_JOYINPUT, 1),
        state.memory.load(base + H_JOYLAST, 1),
        state.memory.load(base + H_JOYRELEASED, 1),
        state.memory.load(base + H_JOYPRESSED, 1),
        state.memory.load(base + H_JOYHELD, 1),
        state.memory.load(base + H_LOADED, 1),
        state.memory.load(base + R_ROMB, 1),
    )


def _assembly(values: dict[str, claripy.ast.BV], inputs: tuple[int, ...]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "HoldTextDisplayOpen")
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    q = location.address
    project.hook(q, JoypadBoundary(inputs, q + 3), length=3)
    project.hook(q + 3, Sm83LoadAHighImmediate(0xB4, q + 5), length=2)
    project.hook(q + 5, BitA(), length=2)
    project.hook(q + 7, BranchNZ(q, q + 9), length=2)
    project.hook(q + 9, ReturnBoundary(), length=1)
    state = project.factory.blank_state(addr=q)
    set_assembly_registers(state, values)
    _setup(state, 0, values)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    return [Endpoint(**assembly_registers(end), memory=_memory(end, 0),
                     constraints=tuple(end.solver.constraints))
            for end in collect_returns(project, state, RETURN)]


def _native(values: dict[str, claripy.ast.BV], inputs: tuple[int, ...]) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_hold_text_display_open")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    for index, value in enumerate(inputs):
        state.memory.store(NATIVE_STATE + 8 + index, claripy.BVV(value, 8))
    state.memory.store(NATIVE_STATE + 16, claripy.BVV(len(inputs), 8))
    _setup(state, NATIVE_MEMORY, values)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    end = manager.deadended[0]
    return [Endpoint(**native_registers(end, NATIVE_STATE),
                     memory=_memory(end, NATIVE_MEMORY),
                     constraints=tuple(end.solver.constraints))]


@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("inputs", ((0,), (1, 0), (0x11, 0)))
def test_hold_text_display_open_pathwise_equivalence(inputs: tuple[int, ...]) -> None:
    values = _inputs(f"hold_text_display_open_{inputs[0]:02x}")
    assert_pathwise_equivalent(
        _assembly(values, inputs), _native(values, inputs),
        (*REGISTERS, "memory"),
    )
