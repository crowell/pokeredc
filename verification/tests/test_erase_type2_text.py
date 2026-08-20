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
from verification.harness.rom import linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
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
    constraints: tuple[claripy.ast.Bool, ...]


class LoadAImmediate(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0x7f, 8)
        self.jump(self.state.addr + 2)


class LoadBCImmediate(angr.SimProcedure):
    def __init__(self, value: int, next_address: int) -> None:
        super().__init__()
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.b = claripy.BVV(self.value >> 8, 8)
        self.state.regs.c = claripy.BVV(self.value & 0xff, 8)
        self.jump(self.next_address)


class Boundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(DONE)


def _assembly(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    loc = symbol_location(SYMBOLS, "EraseType2Text")
    base = loc.address
    project = angr.Project(
        rom_window(ROM, loc.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": base,
        },
    )
    project.hook(base, LoadAImmediate(), length=2)
    project.hook(base + 2, LoadBCImmediate(0x0013, base + 5), length=3)
    project.hook(base + 5, Sm83AddHlRegisterPair("bc", base + 6), length=1)
    project.hook(base + 6, LoadBCImmediate(0x0006, base + 9), length=3)
    project.hook(base + 9, Boundary(), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, inputs)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert len(manager.found) == 1
    end = manager.found[0]
    return [Endpoint(**assembly_registers(end), constraints=tuple(end.solver.constraints))]


def _native(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_erase_type2_text")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    end = manager.deadended[0]
    return [Endpoint(**native_registers(end, NATIVE_STATE), constraints=tuple(end.solver.constraints))]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_erase_type2_text_pathwise_equivalence() -> None:
    inputs = symbolic_registers("ett")
    assert_pathwise_equivalent(
        _assembly(inputs),
        _native(inputs),
        ("a", "f", "b", "c", "d", "e", "h", "l"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_erase_type2_text_exact_linked_body() -> None:
    loc = symbol_location(SYMBOLS, "EraseType2Text")
    assert linked_bytes(ROM, loc, 12) == bytes.fromhex("3e7f01130009010600c3e036")
