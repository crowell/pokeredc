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
W_ON_SGB = 0xCF1B
R_BGP = 0xFF47
DONE = 0xEFFF
EXPECTED_ENTRY = bytes.fromhex("01f8fe1817")
EXPECTED_TAIL = bytes.fromhex("fa1bcfa778280179e047c9")


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
    palette: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class LoadOnSgb(angr.SimProcedure):
    def __init__(self, target: int):
        super().__init__()
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(W_ON_SGB, 1)
        self.jump(self.target)


class WritePalette(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(R_BGP, self.state.regs.a)
        self.jump(DONE)


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    entry = symbol_location(SYMBOLS, "AnimationUnusedPalette1")
    tail = symbol_location(SYMBOLS, "SetAnimationBGPalette")
    assert linked_bytes(ROM, entry, len(EXPECTED_ENTRY)) == EXPECTED_ENTRY
    assert linked_bytes(ROM, tail, len(EXPECTED_TAIL)) == EXPECTED_TAIL
    project = angr.Project(
        rom_window(ROM, entry.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0, "entry_point": entry.address,
        },
    )
    project.hook(tail.address, LoadOnSgb(tail.address + 3), length=3)
    project.hook(tail.address + 8, WritePalette(), length=3)
    state = project.factory.blank_state(addr=entry.address)
    set_assembly_registers(state, values)
    state.memory.store(W_ON_SGB, values["on_sgb"])
    state.memory.store(R_BGP, values["palette"])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=2)
    assert not manager.errored
    return [
        Endpoint(
            **assembly_registers(end),
            on_sgb=end.memory.load(W_ON_SGB, 1),
            palette=end.memory.load(R_BGP, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(
        "port_animation_unused_palette1_player"
    )
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_MEMORY + W_ON_SGB, values["on_sgb"])
    state.memory.store(NATIVE_MEMORY + R_BGP, values["palette"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            on_sgb=end.memory.load(NATIVE_MEMORY + W_ON_SGB, 1),
            palette=end.memory.load(NATIVE_MEMORY + R_BGP, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_animation_unused_palette1_pathwise_equivalence() -> None:
    values = symbolic_registers("animation_unused_palette1")
    values["on_sgb"] = claripy.BVS("animation_unused_palette1_on_sgb", 8)
    values["palette"] = claripy.BVS("animation_unused_palette1_palette", 8)
    assert_pathwise_equivalent(
        _assembly(values), _native(values),
        (*REGISTERS, "on_sgb", "palette"),
    )
