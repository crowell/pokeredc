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
from verification.harness.sm83_shims import Sm83AddRegister


ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification" / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xd000
RETURN = 0xffff
H_CURRENT_SPRITE_OFFSET = 0xffda
BODY = bytes.fromhex("2100c1f0da85806fc9")


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
    sprite_offset: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class LoadHigh(angr.SimProcedure):
    """SM83's FF00+n load, adapted at its individual decoder seam."""

    def __init__(self, address: int, next_address: int) -> None:
        super().__init__()
        self.address = address
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self.address, 1)
        self.jump(self.next_address)


def endpoint(state: angr.SimState, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    registers = (
        native_registers(state, NATIVE_STATE)
        if native
        else assembly_registers(state)
    )
    return Endpoint(
        **registers,
        sprite_offset=state.memory.load(base + H_CURRENT_SPRITE_OFFSET, 1),
        constraints=tuple(state.solver.constraints),
    )


def assembly(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "GetSpriteScreenXYPointerCommon")
    assert linked_bytes(ROM, location, len(BODY)) == BODY
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
    start = location.address
    project.hook(
        start + 3,
        LoadHigh(H_CURRENT_SPRITE_OFFSET, start + 5),
        length=2,
    )
    project.hook(start + 5, Sm83AddRegister("l", start + 6), length=1)
    project.hook(start + 6, Sm83AddRegister("b", start + 7), length=1)

    state = project.factory.blank_state(addr=start)
    set_assembly_registers(state, inputs)
    state.memory.store(H_CURRENT_SPRITE_OFFSET, inputs["sprite_offset"])
    state.regs.sp = claripy.BVV(STACK, 16)
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN)
    assert not manager.errored and len(manager.found) == 1
    return [endpoint(manager.found[0], False)]


def native(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_get_sprite_screen_xy_pointer_common")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_MEMORY + H_CURRENT_SPRITE_OFFSET, inputs["sprite_offset"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [endpoint(manager.deadended[0], True)]


@pytest.mark.skipif(
    not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),
    reason="build artifacts missing",
)
def test_get_sprite_screen_xy_pointer_common_pathwise_equivalence() -> None:
    inputs = symbolic_registers("sprite_screen_pointer_common")
    inputs["sprite_offset"] = claripy.BVS("sprite_screen_pointer_common_offset", 8)
    assert_pathwise_equivalent(
        assembly(inputs),
        native(inputs),
        (*REGISTERS, "sprite_offset"),
    )
