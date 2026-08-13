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
from verification.harness.rom import collect_returns, linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair


ROOT = Path(__file__).resolve().parents[2]
VERIFY = ROOT / "verification"
NATIVE_ELF = VERIFY / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
GB_STACK = 0xD000
GB_RETURN = 0xFFFF
NATIVE_STATE = 0x100000


class StoreBoundary(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["destination"] = self.state.regs.a
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
    destination: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _assembly(inputs: dict[str, claripy.ast.BV]) -> Endpoint:
    location = symbol_location(SYMBOLS, "SetSpriteImageIndexAfterSettingFacingDirection")
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
    project.hook(
        location.address + 3,
        Sm83AddHlRegisterPair("de", location.address + 4),
        length=1,
    )
    project.hook(
        location.address + 4,
        StoreBoundary(location.address + 5),
        length=1,
    )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    assert len(returned) == 1
    end = returned[0]
    return Endpoint(
        **assembly_registers(end),
        destination=end.globals["destination"],
        constraints=tuple(end.solver.constraints),
    )


def _native_for_symbol(
    c_symbol: str, inputs: dict[str, claripy.ast.BV]
) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(c_symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["destination"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            destination=end.memory.load(NATIVE_STATE + 8, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_set_sprite_image_index_symbolic_equivalence() -> None:
    inputs = symbolic_registers("set_sprite_image_index")
    inputs["destination"] = claripy.BVS("set_sprite_image_index_destination", 8)
    assert_pathwise_equivalent(
        [_assembly(inputs)],
        _native_for_symbol(
            "port_set_sprite_image_index_after_setting_facing_direction", inputs
        ),
        (*REGISTERS, "destination"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_set_sprite_image_index_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "SetSpriteImageIndexAfterSettingFacingDirection")
    assert linked_bytes(ROM, location, 6) == bytes.fromhex("11f9ff1977c9")


def _overwrite_moves_assembly(inputs: dict[str, claripy.ast.BV]) -> Endpoint:
    location = symbol_location(SYMBOLS, "OverwritewMoves")
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
    project.hook(
        location.address + 6,
        Sm83AddHlRegisterPair("de", location.address + 7),
        length=1,
    )
    project.hook(
        location.address + 8,
        StoreBoundary(location.address + 9),
        length=1,
    )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    assert len(returned) == 1
    end = returned[0]
    return Endpoint(
        **assembly_registers(end),
        destination=end.globals["destination"],
        constraints=tuple(end.solver.constraints),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_overwrite_w_moves_symbolic_equivalence() -> None:
    inputs = symbolic_registers("overwrite_w_moves")
    inputs["destination"] = claripy.BVS("overwrite_w_moves_destination", 8)
    assert_pathwise_equivalent(
        [_overwrite_moves_assembly(inputs)],
        _native_for_symbol("port_overwrite_w_moves", inputs),
        (*REGISTERS, "destination"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_overwrite_w_moves_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "OverwritewMoves")
    moves = symbol_location(SYMBOLS, "wMoves").address
    assert linked_bytes(ROM, location, 10) == bytes(
        (0x21, moves & 0xFF, moves >> 8, 0x58, 0x16, 0, 0x19, 0x79, 0x77, 0xC9)
    )
