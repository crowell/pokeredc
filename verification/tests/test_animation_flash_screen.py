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
from verification.harness.rom import collect_returns, rom_window, symbol_location
from verification.harness.sm83_shims import (
    Sm83LoadAHighImmediate,
    Sm83StoreAHighImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x400000
STACK = 0xD000
RETURN = 0xFFFF
R_BGP = 0xFF47


class DelayFramesTwo(angr.SimProcedure):
    """Terminal transition of the proven DelayFrames loop for C=2."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.c = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x42, 8)
        self.jump(self._next_address)


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
    palette: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["palette"] = claripy.BVS(f"{prefix}_palette", 8)
    return values


def _assembly(values: dict[str, claripy.ast.BV]) -> Endpoint:
    location = symbol_location(SYMBOLS, "AnimationFlashScreen")
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
    project.hook(base, Sm83LoadAHighImmediate(0x47, base + 2), length=2)
    project.hook(base + 5, Sm83StoreAHighImmediate(0x47, base + 7), length=2)
    project.hook(base + 9, DelayFramesTwo(base + 12), length=3)
    project.hook(base + 13, Sm83StoreAHighImmediate(0x47, base + 15), length=2)
    project.hook(base + 17, DelayFramesTwo(base + 20), length=3)
    project.hook(base + 21, Sm83StoreAHighImmediate(0x47, base + 23), length=2)

    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.regs.sp = claripy.BVV(STACK, 16)
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    state.memory.store(R_BGP, values["palette"])
    returned = collect_returns(project, state, RETURN)
    assert len(returned) == 1
    end = returned[0]
    return Endpoint(
        **assembly_registers(end),
        palette=end.memory.load(R_BGP, 1),
        constraints=tuple(end.solver.constraints),
    )


def _native(values: dict[str, claripy.ast.BV]) -> Endpoint:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_animation_flash_screen")
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_MEMORY + R_BGP, values["palette"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    end = manager.deadended[0]
    return Endpoint(
        **native_registers(end, NATIVE_STATE),
        palette=end.memory.load(NATIVE_MEMORY + R_BGP, 1),
        constraints=tuple(end.solver.constraints),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_animation_flash_screen_pathwise_equivalence() -> None:
    values = _inputs("animation_flash_screen")
    assert_pathwise_equivalent(
        [_assembly(values)],
        [_native(values)],
        (*REGISTERS, "palette"),
    )
