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
from verification.harness.rom import rom_window, sm83_flags_to_z80, symbol_location
ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
W_ON_SGB = 0xCF1B
PREDEF = 0x3E6D
DONE = 0xEFFF


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
    on_sgb: claripy.ast.BV
    call: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class LoadOnSGB(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__(); self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(W_ON_SGB, 1)
        self.jump(self.target)


class AndSelf(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__(); self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.regs.a & self.state.regs.a
        self.state.regs.f = sm83_flags_to_z80(
            claripy.If(self.state.regs.a == 0,
                       claripy.BVV(0xA0, 8), claripy.BVV(0x20, 8))
        )
        self.jump(self.target)


class LoadImmediatePreserveFlags(angr.SimProcedure):
    def __init__(self, immediate_address: int, target: int) -> None:
        super().__init__(); self.immediate_address = immediate_address; self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self.immediate_address, 1)
        self.jump(self.target)


class PrivatePalette(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.globals["call"] = claripy.Concat(
            *(assembly_registers(self.state)[register] for register in REGISTERS)
        )
        self.state.regs.a = self.state.regs.b
        self.jump(DONE)


class RetZ(angr.SimProcedure):
    def __init__(self, taken: int, fallthrough: int) -> None:
        super().__init__(); self.taken = taken; self.fallthrough = fallthrough

    def run(self) -> None:  # type: ignore[override]
        cond = ((self.state.regs.f >> 6) & 1) == 1
        taken = self.state.copy(); fallthrough = self.state.copy()
        taken.solver.add(cond); fallthrough.solver.add(claripy.Not(cond))
        self.inhibit_autoret = True
        self.successors.add_successor(taken, self.taken, cond, "Ijk_Boring")
        self.successors.add_successor(
            fallthrough, self.fallthrough, claripy.Not(cond), "Ijk_Boring"
        )


class NativePrivatePalette(angr.SimProcedure):
    def run(self, state_ptr: claripy.ast.BV, memory_ptr: claripy.ast.BV) -> None:  # type: ignore[override]
        self.state.globals["call"] = self.state.memory.load(state_ptr, 8)
        self.state.memory.store(state_ptr, self.state.memory.load(state_ptr + 2, 1))


def _setup(state: angr.SimState, base: int, on_sgb: claripy.ast.BV) -> None:
    state.memory.store(base + W_ON_SGB, on_sgb)


def _endpoint(state: angr.SimState, *, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    regs = native_registers(state, NATIVE_STATE) if native else assembly_registers(state)
    return Endpoint(
        **regs,
        on_sgb=state.memory.load(base + W_ON_SGB, 1),
        call=state.globals.get("call", claripy.BVV(0, 64)),
        constraints=tuple(state.solver.constraints),
    )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "RunPaletteCommand")
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    b = location.address
    project.hook(b, LoadOnSGB(b + 3), length=3)
    project.hook(b + 3, AndSelf(b + 4), length=1)
    project.hook(b + 4, RetZ(DONE, b + 5), length=1)
    project.hook(b + 5, LoadImmediatePreserveFlags(b + 6, b + 7), length=2)
    project.hook(PREDEF, PrivatePalette(), length=1)
    state = project.factory.blank_state(addr=b)
    set_assembly_registers(state, values)
    _setup(state, 0, values["on_sgb"])
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=2)
    assert not manager.errored and len(manager.found) == 2
    return [_endpoint(end, native=False) for end in manager.found]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_run_palette_command")
    private = project.loader.find_symbol("port_run_palette_command_private")
    assert function is not None and private is not None
    project.hook(private.rebased_addr, NativePrivatePalette())
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, NATIVE_MEMORY, values["on_sgb"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 2
    return [_endpoint(end, native=True) for end in manager.deadended]


@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_run_palette_command_pathwise_equivalence() -> None:
    values = symbolic_registers("run_palette_command")
    values["on_sgb"] = claripy.BVS("run_palette_command_on_sgb", 8)
    assert_pathwise_equivalent(_assembly(values), _native(values), (*REGISTERS, "on_sgb", "call"))
