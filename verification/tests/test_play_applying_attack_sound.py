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
from verification.harness.rom import rom_window, symbol_location
from verification.harness.sm83_shims import (
    Sm83AndImmediate,
    Sm83CpImmediate,
    Sm83LoadAImmediate,
    Sm83StoreAImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
DONE = 0xEFFF
W_DAMAGE = 0xD05B
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


class Jump(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.jump(self._next_address)


class LoadImmediatePreserveFlags(angr.SimProcedure):
    def __init__(self, register: str, value: int, next_address: int) -> None:
        super().__init__()
        self._register = register
        self._value = value
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self._register, claripy.BVV(self._value, 8))
        self.jump(self._next_address)


class CopyRegisterPreserveFlags(angr.SimProcedure):
    def __init__(self, source: str, target: str, next_address: int) -> None:
        super().__init__()
        self._source = source
        self._target = target
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self._target, getattr(self.state.regs, self._source))
        self.jump(self._next_address)


class Boundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.successors.add_successor(
            self.state.copy(), DONE, claripy.BoolV(True), "Ijk_Boring"
        )


def _assembly(values: dict[str, claripy.ast.BV], multiplier: int) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "PlayApplyingAttackSound")
    base = location.address
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
    project.hook(base, Jump(base + 3), length=3)
    project.hook(base + 3, Sm83LoadAImmediate(W_DAMAGE, base + 6), length=3)
    project.hook(base + 6, Sm83AndImmediate(0x7F, base + 8), length=2)
    project.hook(base + 9, Sm83CpImmediate(10, base + 11), length=2)
    project.hook(base + 11, LoadImmediatePreserveFlags("a", 0x20, base + 13), length=2)
    project.hook(base + 13, LoadImmediatePreserveFlags("b", 0x30, base + 15), length=2)
    project.hook(base + 15, LoadImmediatePreserveFlags("c", 0xA6, base + 17), length=2)
    project.hook(base + 19, LoadImmediatePreserveFlags("a", 0xE0, base + 21), length=2)
    project.hook(base + 21, LoadImmediatePreserveFlags("b", 0xFF, base + 23), length=2)
    project.hook(base + 23, LoadImmediatePreserveFlags("c", 0xB0, base + 25), length=2)
    project.hook(base + 27, LoadImmediatePreserveFlags("a", 0x50, base + 29), length=2)
    project.hook(base + 29, LoadImmediatePreserveFlags("b", 1, base + 31), length=2)
    project.hook(base + 31, LoadImmediatePreserveFlags("c", 0xA7, base + 33), length=2)
    project.hook(base + 33, Sm83StoreAImmediate(FREQUENCY, base + 36), length=3)
    project.hook(base + 36, CopyRegisterPreserveFlags("b", "a", base + 39), length=1)
    project.hook(base + 39, Sm83StoreAImmediate(TEMPO, base + 42), length=3)
    project.hook(base + 42, CopyRegisterPreserveFlags("c", "a", base + 45), length=1)
    project.hook(base + 45, Boundary(), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.memory.store(W_DAMAGE, claripy.BVV(multiplier, 8))
    state.memory.store(FREQUENCY, values["frequency"])
    state.memory.store(TEMPO, values["tempo"])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored
    return [
        Endpoint(
            **assembly_registers(end),
            frequency=end.memory.load(FREQUENCY, 1),
            tempo=end.memory.load(TEMPO, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_play_applying_attack_sound")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, values["damage"])
    state.memory.store(NATIVE_STATE + 9, values["frequency"])
    state.memory.store(NATIVE_STATE + 10, values["tempo"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            frequency=end.memory.load(NATIVE_STATE + 9, 1),
            tempo=end.memory.load(NATIVE_STATE + 10, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
@pytest.mark.parametrize("multiplier", (9, 10, 11))
def test_play_applying_attack_sound_pathwise_equivalence(multiplier: int) -> None:
    values = symbolic_registers(f"play_applying_attack_sound_{multiplier}")
    values["damage"] = claripy.BVV(multiplier, 8)
    values["frequency"] = claripy.BVS(f"play_applying_attack_sound_{multiplier}_frequency", 8)
    values["tempo"] = claripy.BVS(f"play_applying_attack_sound_{multiplier}_tempo", 8)
    assert_pathwise_equivalent(
        _assembly(values, multiplier),
        _native(values),
        (*REGISTERS, "frequency", "tempo"),
    )
