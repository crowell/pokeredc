"""Proof for the EnterMap prefix through LoadMapData."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import assembly_registers, native_registers, set_assembly_registers, store_native_registers, symbolic_registers
from verification.harness.rom import linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import Sm83StoreAImmediate

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xFFFF
EXPECTED = bytes.fromhex("3effea6bcdcd41")
W_JOY_IGNORE = 0x416B
H_LOADED_ROM_BANK = 0xFFB8
R_ROMB = 0x2000
W_STATUS_FLAGS6 = 0xD732
W_STATUS_FLAGS7 = 0xD733
W_CURRENT_MAP_VIEW = 0xC3A0
W_MAP_VIEW_BYTES = 32 * 18


@dataclass(frozen=True)
class Endpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    joy_ignore: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class LoadMapDataBoundary(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__()
        self._target = target

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(H_LOADED_ROM_BANK, 1)
        self.jump(self._target)


class NativeNoop(angr.SimProcedure):
    def run(self, *args, **kwargs) -> None:  # type: ignore[override]
        return


def _assembly(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "EnterMap")
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
    project.hook(location.address + 0x02, Sm83StoreAImmediate(W_JOY_IGNORE, location.address + 0x05), length=3)
    load_map_data = symbol_location(SYMBOLS, "LoadMapData")
    project.hook(load_map_data.address, LoadMapDataBoundary(location.address + 0x07), length=1)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    state.memory.store(H_LOADED_ROM_BANK, claripy.BVV(2, 8))
    state.memory.store(R_ROMB, claripy.BVV(2, 8))
    state.memory.store(W_STATUS_FLAGS6, claripy.BVV(0, 8))
    state.memory.store(W_STATUS_FLAGS7, claripy.BVV(0, 8))
    for offset in range(W_MAP_VIEW_BYTES):
        state.memory.store(W_CURRENT_MAP_VIEW + offset, claripy.BVV(0, 8))
    manager = project.factory.simulation_manager(state)
    manager.explore(find=lambda candidate: candidate.addr == location.address + 0x07)
    assert not manager.errored
    return [
        Endpoint(
            a=assembly_registers(end)["a"],
            f=assembly_registers(end)["f"],
            joy_ignore=end.memory.load(W_JOY_IGNORE, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_enter_map")
    assert function is not None
    for name in (
        "port_disable_lcd",
        "port_load_text_box_tile_patterns",
        "port_load_map_header",
        "port_init_map_sprites",
        "port_load_tile_block_map",
        "port_load_tileset_tile_pattern_data",
        "port_load_current_map_view",
        "port_enable_lcd",
        "port_run_palette_command",
        "port_load_player_sprite_graphics",
        "port_update_music_6_times",
        "port_play_default_music_fade_out_current",
    ):
        symbol = project.loader.find_symbol(name)
        assert symbol is not None
        project.hook(symbol.rebased_addr, NativeNoop())
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_MEMORY + H_LOADED_ROM_BANK, claripy.BVV(2, 8))
    state.memory.store(NATIVE_MEMORY + R_ROMB, claripy.BVV(2, 8))
    state.memory.store(NATIVE_MEMORY + W_STATUS_FLAGS6, claripy.BVV(0, 8))
    state.memory.store(NATIVE_MEMORY + W_STATUS_FLAGS7, claripy.BVV(0, 8))
    for offset in range(W_MAP_VIEW_BYTES):
        state.memory.store(NATIVE_MEMORY + W_CURRENT_MAP_VIEW + offset, claripy.BVV(0, 8))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            a=native_registers(end, NATIVE_STATE)["a"],
            f=native_registers(end, NATIVE_STATE)["f"],
            joy_ignore=end.memory.load(NATIVE_MEMORY + W_JOY_IGNORE, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_enter_map_loader_prefix_pathwise_equivalence() -> None:
    inputs = symbolic_registers("enter_map")
    assert_pathwise_equivalent(_assembly(inputs), _native(inputs), ("a", "f", "joy_ignore"))


def test_enter_map_exact_linked_prefix() -> None:
    location = symbol_location(SYMBOLS, "EnterMap")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
