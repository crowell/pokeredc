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
from verification.harness.rom import linked_bytes, rom_window, symbol_location

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF
TILEMAP = 0xC3A0
TILEMAP_SIZE = 20 * 18
EXPECTED = bytes.fromhex("cda03621f3c306070e0ccd2219")


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
    tilemap: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class GraphicsBoundary(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.jump(self.continuation)


class TextBoxBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        row = 0xC3F3
        height = 7
        width = 12

        def write(address: int, value: int) -> None:
            self.state.memory.store(address, claripy.BVV(value, 8))

        write(row, 0x79)
        for column in range(1, width + 1):
            write(row + column, 0x7A)
        write(row + width + 1, 0x7B)
        for y in range(1, height + 1):
            base = row + y * 20
            write(base, 0x7C)
            for column in range(1, width + 1):
                write(base + column, 0x7F)
            write(base + width + 1, 0x7C)
        base = row + (height + 1) * 20
        write(base, 0x7D)
        for column in range(1, width + 1):
            write(base + column, 0x7A)
        write(base + width + 1, 0x7E)
        self.state.regs.a = claripy.BVV(0x7A, 8)
        self.state.regs.b = claripy.BVV(0, 8)
        self.state.regs.d = claripy.BVV(0, 8)
        self.state.regs.e = claripy.BVV(20, 8)
        self.state.regs.hl = claripy.BVV(base + width + 1, 16)
        self.state.regs.f = claripy.BVV(0x42, 8)
        self.inhibit_autoret = True
        self.successors.add_successor(
            self.state.copy(), DONE, claripy.BoolV(True), "Ijk_Boring"
        )


def _endpoint(state: angr.SimState, *, native: bool, base: int) -> Endpoint:
    registers = native_registers(state, NATIVE_STATE) if native else assembly_registers(state)
    return Endpoint(
        **registers,
        tilemap=state.memory.load(base + TILEMAP, TILEMAP_SIZE),
        constraints=tuple(state.solver.constraints),
    )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "DisplayLinkBattleVersusTextBox")
    base = location.address
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    project = angr.Project(
        rom_window(ROM, location.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": base,
        },
    )
    project.hook(base, GraphicsBoundary(base + 3), length=3)
    project.hook(base + 10, TextBoxBoundary(), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    for address in range(TILEMAP, TILEMAP + TILEMAP_SIZE):
        state.memory.store(address, claripy.BVV(0x00, 8))
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored
    return [_endpoint(end, native=False, base=0) for end in manager.found]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_display_link_battle_versus_text_box")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    for address in range(TILEMAP, TILEMAP + TILEMAP_SIZE):
        state.memory.store(NATIVE_MEMORY + address, claripy.BVV(0x00, 8))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [_endpoint(end, native=True, base=NATIVE_MEMORY) for end in manager.deadended]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_display_link_battle_versus_text_box_pathwise_equivalence() -> None:
    values = symbolic_registers("link_versus")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "tilemap"),
    )
