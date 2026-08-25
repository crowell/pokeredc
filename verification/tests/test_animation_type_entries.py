from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS, assembly_registers, native_registers, set_assembly_registers, store_native_registers, symbolic_registers
from verification.harness.rom import (
    collect_returns,
    linked_bytes,
    rom_window,
    sm83_flags_to_z80,
    symbol_location,
)
from verification.harness.sm83_shims import Sm83LoadAHighImmediate, Sm83LoadAImmediate

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification" / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
STACK = 0xD000
RETURN = 0xFFFF
WHOSE_TURN = 0xFFF3
TILEMAP_START = 0xC3AC
TILEMAP_SIZE = 0xC484 - TILEMAP_START
CASES = (
    ("GetPlayerAnimationType", "wPlayerMoveEffect", "PlayPlayerMoveAnimation", "port_get_player_animation_type", bytes.fromhex("a73e0428023e05")),
    ("GetEnemyAnimationType", "wEnemyMoveEffect", "PlayEnemyMoveAnimation", "port_get_enemy_animation_type", bytes.fromhex("a73e0128083e021804")),
)


@dataclass(frozen=True)
class Endpoint:
    a: claripy.ast.BV; f: claripy.ast.BV; b: claripy.ast.BV; c: claripy.ast.BV
    d: claripy.ast.BV; e: claripy.ast.BV; h: claripy.ast.BV; l: claripy.ast.BV
    effect: claripy.ast.BV; continuation: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def assembly(symbol: str, memory_symbol: str, tail_symbol: str, inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, symbol)
    memory = symbol_location(SYMBOLS, memory_symbol).address
    tail = symbol_location(SYMBOLS, tail_symbol).address
    project = angr.Project(rom_window(ROM, location.bank), auto_load_libs=False, rebase_granularity=0x100, main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0, "entry_point": location.address})
    project.hook(location.address, Sm83LoadAImmediate(memory, location.address + 3), length=3)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    state.memory.store(memory, inputs["effect"])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=tail, num_find=2)
    assert not manager.errored and manager.found
    return [Endpoint(**assembly_registers(end), effect=end.memory.load(memory, 1), continuation=claripy.BVV(1, 8), constraints=tuple(end.solver.constraints)) for end in manager.found]


def native(c_symbol: str, inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(c_symbol)
    assert function
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["effect"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and manager.deadended
    return [Endpoint(**native_registers(end, NATIVE_STATE), effect=end.memory.load(NATIVE_STATE + 8, 1), continuation=claripy.BVV(1, 8), constraints=tuple(end.solver.constraints)) for end in manager.deadended]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.parametrize("symbol,memory_symbol,tail_symbol,c_symbol,_suffix", CASES)
def test_animation_type_entry_equivalence(symbol: str, memory_symbol: str, tail_symbol: str, c_symbol: str, _suffix: bytes) -> None:
    inputs = symbolic_registers(symbol.lower())
    inputs["effect"] = claripy.BVS(f"{symbol}_effect", 8)
    assert_pathwise_equivalent(assembly(symbol, memory_symbol, tail_symbol, inputs), native(c_symbol, inputs), (*REGISTERS, "effect", "continuation"))


@pytest.mark.parametrize("symbol,memory_symbol,_tail_symbol,_c_symbol,suffix", CASES)
def test_animation_type_entry_exact_body(symbol: str, memory_symbol: str, _tail_symbol: str, _c_symbol: str, suffix: bytes) -> None:
    location = symbol_location(SYMBOLS, symbol)
    memory = symbol_location(SYMBOLS, memory_symbol).address
    expected = bytes((0xfa, memory & 0xff, memory >> 8)) + suffix
    assert linked_bytes(ROM, location, len(expected)) == expected


@dataclass(frozen=True)
class HideEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    state: claripy.ast.BV
    clear_call: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class AssemblyClearSummary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.globals["clear_call"] = claripy.Concat(
            *(assembly_registers(self.state)[name] for name in REGISTERS),
            self.state.memory.load(TILEMAP_START, TILEMAP_SIZE),
        )
        for register in REGISTERS:
            value = self.state.globals[f"clear_out_{register}"]
            if register == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, register, value)
        self.state.memory.store(
            TILEMAP_START, self.state.globals["clear_out_tilemap"]
        )
        return_address = self.state.memory.load(
            self.state.regs.sp, 2, endness="Iend_LE"
        )
        self.state.regs.sp += 2
        self.jump(return_address)


class NativeClearSummary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        address = self.state.regs.rdi
        self.state.globals["clear_call"] = claripy.Concat(
            self.state.memory.load(address, 8),
            self.state.memory.load(
                address + 8 + TILEMAP_START, TILEMAP_SIZE
            ),
        )
        for index, register in enumerate(REGISTERS):
            self.state.memory.store(
                address + index, self.state.globals[f"clear_out_{register}"]
            )
        self.state.memory.store(
            address + 8 + TILEMAP_START,
            self.state.globals["clear_out_tilemap"],
        )


def hide_inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["whose_turn"] = claripy.BVS(f"{prefix}_whose_turn", 8)
    values["tilemap"] = claripy.BVS(f"{prefix}_tilemap", TILEMAP_SIZE * 8)
    for register in REGISTERS:
        if register == "f":
            values["clear_out_f"] = claripy.Concat(
                claripy.BVS(f"{prefix}_clear_out_flags", 4),
                claripy.BVV(0, 4),
            )
        else:
            values[f"clear_out_{register}"] = claripy.BVS(
                f"{prefix}_clear_out_{register}", 8
            )
    values["clear_out_tilemap"] = claripy.BVS(
        f"{prefix}_clear_out_tilemap", TILEMAP_SIZE * 8
    )
    return values


def setup_hide_outputs(
    state: angr.SimState, values: dict[str, claripy.ast.BV]
) -> None:
    for register in REGISTERS:
        state.globals[f"clear_out_{register}"] = values[
            f"clear_out_{register}"
        ]
    state.globals["clear_out_tilemap"] = values["clear_out_tilemap"]


def hide_assembly(inputs: dict[str, claripy.ast.BV]) -> list[HideEndpoint]:
    location = symbol_location(SYMBOLS, "AnimationHideMonPic")
    clear = symbol_location(SYMBOLS, "ClearMonPicFromTileMap")
    expected = bytes((0xF0, WHOSE_TURN & 0xFF)) + bytes.fromhex(
        "a728043e0c18023e65"
    )
    assert linked_bytes(ROM, location, len(expected)) == expected
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
        location.address,
        Sm83LoadAHighImmediate(WHOSE_TURN, location.address + 2),
        length=2,
    )
    project.hook(clear.address, AssemblyClearSummary())
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    state.regs.sp = claripy.BVV(STACK, 16)
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    state.memory.store(WHOSE_TURN, inputs["whose_turn"])
    state.memory.store(TILEMAP_START, inputs["tilemap"])
    setup_hide_outputs(state, inputs)
    return [
        HideEndpoint(
            **assembly_registers(end),
            state=claripy.Concat(
                end.memory.load(WHOSE_TURN, 1),
                end.memory.load(TILEMAP_START, TILEMAP_SIZE),
            ),
            clear_call=end.globals["clear_call"],
            constraints=tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, RETURN)
    ]


def hide_native(inputs: dict[str, claripy.ast.BV]) -> list[HideEndpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_animation_hide_mon_pic")
    clear = project.loader.find_symbol("port_clear_mon_pic_from_tilemap")
    assert function is not None and clear is not None
    project.hook(clear.rebased_addr, NativeClearSummary())
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(
        NATIVE_STATE + 8 + WHOSE_TURN, inputs["whose_turn"]
    )
    state.memory.store(
        NATIVE_STATE + 8 + TILEMAP_START, inputs["tilemap"]
    )
    setup_hide_outputs(state, inputs)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [
        HideEndpoint(
            **native_registers(end, NATIVE_STATE),
            state=claripy.Concat(
                end.memory.load(NATIVE_STATE + 8 + WHOSE_TURN, 1),
                end.memory.load(
                    NATIVE_STATE + 8 + TILEMAP_START, TILEMAP_SIZE
                ),
            ),
            clear_call=end.globals["clear_call"],
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
def test_animation_hide_mon_pic_pathwise_equivalence() -> None:
    inputs = hide_inputs("animation_hide_mon_pic")
    assert_pathwise_equivalent(
        hide_assembly(inputs),
        hide_native(inputs),
        (*REGISTERS, "state", "clear_call"),
    )


def test_animation_hide_mon_pic_entry_exact_body() -> None:
    location = symbol_location(SYMBOLS, "AnimationHideMonPic")
    memory = symbol_location(SYMBOLS, "hWhoseTurn").address
    expected = bytes((0xf0, memory & 0xff)) + bytes.fromhex("a728043e0c18023e65")
    assert linked_bytes(ROM, location, len(expected)) == expected
