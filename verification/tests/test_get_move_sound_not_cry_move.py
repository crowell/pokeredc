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
from verification.harness.sm83_shims import Sm83LoadAAtHlIncrement, Sm83StoreAImmediate

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
DONE = 0xEFFF
SOURCE = 0xC000
FREQUENCY = 0xC0F1
TEMPO = 0xC0F2


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
    frequency: claripy.ast.BV
    tempo: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class CopyBToA(angr.SimProcedure):
    """Model SM83 LD A,B without changing flags."""

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals["input_b"]
        self.jump(self.state.addr + 1)


class Boundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(DONE)


def _assembly(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    loc = symbol_location(SYMBOLS, "GetMoveSound.NotCryMove")
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
    project.hook(base, Sm83LoadAAtHlIncrement(base + 1), length=1)
    project.hook(base + 1, Sm83StoreAImmediate(FREQUENCY, base + 4), length=3)
    project.hook(base + 4, Sm83LoadAAtHlIncrement(base + 5), length=1)
    project.hook(base + 5, Sm83StoreAImmediate(TEMPO, base + 8), length=3)
    project.hook(base + 8, CopyBToA(), length=1)
    project.hook(base + 9, Boundary(), length=1)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, inputs)
    state.regs.h = claripy.BVV(SOURCE >> 8, 8)
    state.regs.l = claripy.BVV(SOURCE & 0xff, 8)
    state.globals["input_b"] = inputs["b"]
    state.memory.store(SOURCE, inputs["source0"])
    state.memory.store(SOURCE + 1, inputs["source1"])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert len(manager.found) == 1
    end = manager.found[0]
    return [
        Endpoint(
            **assembly_registers(end),
            frequency=end.memory.load(FREQUENCY, 1),
            tempo=end.memory.load(TEMPO, 1),
            constraints=tuple(end.solver.constraints),
        )
    ]


def _native(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_get_move_sound_not_cry_move")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["source0"])
    state.memory.store(NATIVE_STATE + 9, inputs["source1"])
    state.memory.store(NATIVE_STATE + 10, claripy.BVV(0, 8))
    state.memory.store(NATIVE_STATE + 11, claripy.BVV(0, 8))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    end = manager.deadended[0]
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            frequency=end.memory.load(NATIVE_STATE + 10, 1),
            tempo=end.memory.load(NATIVE_STATE + 11, 1),
            constraints=tuple(end.solver.constraints),
        )
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_get_move_sound_not_cry_move_pathwise_equivalence() -> None:
    inputs = symbolic_registers("gmnc")
    inputs["h"] = claripy.BVV(SOURCE >> 8, 8)
    inputs["l"] = claripy.BVV(SOURCE & 0xff, 8)
    inputs["source0"] = claripy.BVS("gmnc_source0", 8)
    inputs["source1"] = claripy.BVS("gmnc_source1", 8)
    assert_pathwise_equivalent(
        _assembly(inputs),
        _native(inputs),
        ("a", "f", "b", "c", "d", "e", "h", "l", "frequency", "tempo"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_get_move_sound_not_cry_move_exact_linked_body() -> None:
    loc = symbol_location(SYMBOLS, "GetMoveSound.NotCryMove")
    assert linked_bytes(ROM, loc, 10) == bytes.fromhex("2aeaf1c02aeaf2c078c9")
