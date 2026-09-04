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

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
DONE = 0xEFFF
H_LOADED_ROM_BANK = 0xFFB8
R_ROMB = 0x2000
EXPECTED = bytes.fromhex(
    "21995a1100900100063e10cdf7172159591100960140013e10cdf717"
    "2159591100880140013e10cdf71721996011008001c0063e10c3f717"
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
    constraints: tuple[claripy.ast.Bool, ...]


class FarCopyData2Summary(angr.SimProcedure):
    def __init__(self, next_address: int | None = None) -> None:
        super().__init__()
        self._next = next_address

    def run(self) -> None:  # type: ignore[override]
        size = claripy.Concat(self.state.regs.b, self.state.regs.c)
        self.state.regs.hl = self.state.regs.hl + size
        self.state.regs.de = self.state.regs.de + size
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.b = claripy.BVV(0, 8)
        self.state.regs.c = claripy.BVV(0, 8)
        if self._next is not None:
            self.jump(self._next)
        else:
            self.ret()


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    return symbolic_registers(prefix)


def _setup_assembly(state: angr.SimState) -> None:
    state.memory.store(H_LOADED_ROM_BANK, claripy.BVV(0, 8))
    state.memory.store(R_ROMB, claripy.BVV(0, 8))


def _setup_native(state: angr.SimState) -> None:
    state.memory.store(NATIVE_MEMORY + H_LOADED_ROM_BANK, claripy.BVV(0, 8))
    state.memory.store(NATIVE_MEMORY + R_ROMB, claripy.BVV(0, 8))
    for source, size in ((0x5A99, 0x600), (0x5959, 0x140), (0x6099, 0x6C0)):
        state.memory.store(NATIVE_MEMORY + source, claripy.BVV(0, size * 8))


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "LoadIntroGraphics")
    assert location.bank == 0x10
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
    base = location.address
    far = symbol_location(SYMBOLS, "FarCopyData2")
    assert far.bank == 0
    project.hook(base + 11, FarCopyData2Summary(base + 14), length=3)
    project.hook(base + 25, FarCopyData2Summary(base + 28), length=3)
    project.hook(base + 39, FarCopyData2Summary(base + 42), length=3)
    project.hook(far.address, FarCopyData2Summary(DONE), length=3)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    _setup_assembly(state)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(DONE, 16), endness="Iend_LE")
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=8)
    assert not manager.errored
    assert len(manager.found) == 1
    end = manager.found[0]
    return [Endpoint(**assembly_registers(end), constraints=tuple(end.solver.constraints))]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_load_intro_graphics")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup_native(state)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    end = manager.deadended[0]
    return [Endpoint(**native_registers(end, NATIVE_STATE), constraints=tuple(end.solver.constraints))]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_load_intro_graphics_pathwise_equivalence() -> None:
    values = _inputs("load_intro_graphics")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        ("a", "f", "b", "c", "d", "e", "h", "l"),
    )
