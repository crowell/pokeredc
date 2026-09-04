"""Proof for CheckWarpsNoCollision's first warp-scan setup."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS, assembly_registers, native_registers, set_assembly_registers, store_native_registers, symbolic_registers
from verification.harness.rom import linked_bytes, rom_window, sm83_flags_to_z80, symbol_location
from verification.harness.sm83_shims import Sm83AndRegister, Sm83LoadAImmediate

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
W_NUMBER_OF_WARPS = 0xD3AE
W_Y_COORD = 0xD361
W_X_COORD = 0xD362
W_WARP_ENTRIES = 0xD3AF
EXPECTED = bytes.fromhex("faaed3a7caba07faaed306004ffa61d357fa62d35f21afd3")

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


class Skip(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__()
        self._target = target

    def run(self) -> None:  # type: ignore[override]
        self.jump(self._target)


class LoadHLImmediate(angr.SimProcedure):
    def __init__(self, value: int, target: int) -> None:
        super().__init__()
        self._value = value
        self._target = target

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = claripy.BVV(self._value >> 8, 8)
        self.state.regs.l = claripy.BVV(self._value & 0xFF, 8)
        self.jump(self._target)


def _assembly(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "CheckWarpsNoCollision")
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
    project.hook(location.address + 0x00, Sm83LoadAImmediate(W_NUMBER_OF_WARPS, location.address + 0x03), length=3)
    project.hook(location.address + 0x03, Sm83AndRegister("a", location.address + 0x04), length=1)
    project.hook(location.address + 0x04, Skip(location.address + 0x07), length=3)
    project.hook(location.address + 0x07, Sm83LoadAImmediate(W_NUMBER_OF_WARPS, location.address + 0x0A), length=3)
    project.hook(location.address + 0x0D, Sm83LoadAImmediate(W_Y_COORD, location.address + 0x10), length=3)
    project.hook(location.address + 0x11, Sm83LoadAImmediate(W_X_COORD, location.address + 0x14), length=3)
    project.hook(location.address + 0x15, LoadHLImmediate(W_WARP_ENTRIES, location.address + 0x18), length=3)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    state.memory.store(W_NUMBER_OF_WARPS, claripy.BVV(3, 8))
    state.memory.store(W_Y_COORD, claripy.BVV(9, 8))
    state.memory.store(W_X_COORD, claripy.BVV(10, 8))
    manager = project.factory.simulation_manager(state)
    manager.explore(find=lambda candidate: candidate.addr == location.address + 0x18)
    assert not manager.errored
    return [Endpoint(**assembly_registers(end), constraints=tuple(end.solver.constraints)) for end in manager.found]


def _native(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_check_warps_no_collision")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_MEMORY + W_NUMBER_OF_WARPS, claripy.BVV(3, 8))
    state.memory.store(NATIVE_MEMORY + W_Y_COORD, claripy.BVV(9, 8))
    state.memory.store(NATIVE_MEMORY + W_X_COORD, claripy.BVV(10, 8))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [Endpoint(**native_registers(end, NATIVE_STATE), constraints=tuple(end.solver.constraints)) for end in manager.deadended]


@pytest.mark.skipif(not ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_check_warps_no_collision_prefix_pathwise_equivalence() -> None:
    inputs = symbolic_registers("check_warps_no_collision")
    assert_pathwise_equivalent(_assembly(inputs), _native(inputs), REGISTERS)


def test_check_warps_no_collision_exact_prefix() -> None:
    location = symbol_location(SYMBOLS, "CheckWarpsNoCollision")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
