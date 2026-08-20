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
from verification.harness.sm83_shims import (
    Sm83CpImmediate,
    Sm83DecRegister,
    Sm83IncRegister,
    Sm83LoadAAtHlIncrement,
    Sm83LoadAAtHlDecrement,
    Sm83LoadAHighImmediate,
    Sm83LoadAImmediate,
    Sm83StoreAAtHlDecrement,
    Sm83StoreAAtHlIncrement,
    Sm83StoreAHighImmediate,
    Sm83StoreAImmediate,
    Sm83SubRegister,
    Sm83SwapRegister,
)


ROOT = Path(__file__).resolve().parents[2]
VERIFY = ROOT / "verification"
NATIVE_ELF = VERIFY / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
GB_STACK = 0xD000
GB_RETURN = 0xFFFF
NATIVE_STATE = 0x100000


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
    memory: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class RegisterEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class PaletteEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    on_sgb: claripy.ast.BV
    animation_palette: claripy.ast.BV
    animation_id: claripy.ast.BV
    object_palette0: claripy.ast.BV
    object_palette1: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class ShareMoveEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    whose_turn: claripy.ast.BV
    animation_id: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class FallingInitEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    num_objects: claripy.ast.BV
    memory: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class FallingOamEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    movement_byte: claripy.ast.BV
    oam_entry: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class AdjustOamEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    adjustment: claripy.ast.BV
    oam: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class OamWriteEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    base_x: claripy.ast.BV
    oam_entry: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _z80_project(symbol: str) -> tuple[angr.Project, int]:
    location = symbol_location(SYMBOLS, symbol)
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
    return project, location.address


def _assembly_endpoints(
    symbol: str, inputs: dict[str, claripy.ast.BV]
) -> list[Endpoint]:
    project, address = _z80_project(symbol)
    if symbol.startswith("GetSubanimationTransform"):
        memory = symbol_location(SYMBOLS, "hWhoseTurn").address
        load_offset = 1 if symbol.endswith("1") else 0
        project.hook(
            address + load_offset,
            Sm83LoadAHighImmediate(0xF3, address + load_offset + 2),
            length=2,
        )
    else:
        memory = symbol_location(SYMBOLS, "wAnimationID").address
        project.hook(address, Sm83LoadAImmediate(memory, address + 3), length=3)
        project.hook(address + 3, Sm83CpImmediate(0x2D, address + 5), length=2)
        project.hook(address + 7, Sm83CpImmediate(0x2E, address + 9), length=2)
    state = project.factory.blank_state(addr=address)
    set_assembly_registers(state, inputs)
    state.memory.store(memory, inputs["memory"])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    return [
        Endpoint(
            **assembly_registers(end),
            memory=end.memory.load(memory, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, GB_RETURN)
    ]


def _native_endpoints(
    c_symbol: str, inputs: dict[str, claripy.ast.BV]
) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(c_symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["memory"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=end.memory.load(NATIVE_STATE + 8, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


def _tilemap_assembly(
    inputs: dict[str, claripy.ast.BV]
) -> list[Endpoint]:
    project, address = _z80_project("GetMonSpriteTileMapPointerFromRowCount")
    memory = symbol_location(SYMBOLS, "hWhoseTurn").address
    project.hook(
        address + 1,
        Sm83LoadAHighImmediate(0xF3, address + 3),
        length=2,
    )
    project.hook(address + 21, Sm83SubRegister("b", address + 22), length=1)
    project.hook(address + 29, Sm83DecRegister("a", address + 30), length=1)
    state = project.factory.blank_state(addr=address)
    set_assembly_registers(state, inputs)
    state.memory.store(memory, inputs["memory"])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    return [
        Endpoint(
            **assembly_registers(end),
            memory=end.memory.load(memory, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, GB_RETURN)
    ]


def _tilemap_native(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    return _native_endpoints(
        "port_get_mon_sprite_tilemap_pointer_from_row_count", inputs
    )


def _tile_id_assembly(inputs: dict[str, claripy.ast.BV]) -> RegisterEndpoint:
    project, address = _z80_project("GetTileIDList")
    for offset in (9, 11, 13):
        project.hook(
            address + offset,
            Sm83LoadAAtHlIncrement(address + offset + 1),
            length=1,
        )
    project.hook(
        address + 19,
        Sm83SwapRegister("a", address + 21),
        length=2,
    )
    state = project.factory.blank_state(addr=address)
    set_assembly_registers(state, inputs)
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    end = collect_returns(project, state, GB_RETURN)[0]
    return RegisterEndpoint(
        **assembly_registers(end), constraints=tuple(end.solver.constraints)
    )


def _tile_id_native(inputs: dict[str, claripy.ast.BV]) -> RegisterEndpoint:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_get_tile_id_list")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    end = manager.deadended[0]
    return RegisterEndpoint(
        **native_registers(end, NATIVE_STATE),
        constraints=tuple(end.solver.constraints),
    )


def _copy_row_assembly(
    symbol: str, count: int, inputs: dict[str, claripy.ast.BV]
) -> Endpoint:
    project, address = _z80_project(symbol)
    if symbol == "AnimCopyRowLeft":
        project.hook(address, Sm83LoadAAtHlDecrement(address + 1), length=1)
        project.hook(address + 1, Sm83StoreAAtHlIncrement(address + 2), length=1)
        row_base = 0xC4FF
    else:
        project.hook(address, Sm83LoadAAtHlIncrement(address + 1), length=1)
        project.hook(address + 1, Sm83StoreAAtHlDecrement(address + 2), length=1)
        row_base = 0xC500 - count + 1
    project.hook(address + 3, Sm83DecRegister("c", address + 4), length=1)
    state = project.factory.blank_state(addr=address)
    set_assembly_registers(state, inputs)
    state.memory.store(row_base, inputs["memory"])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    end = collect_returns(project, state, GB_RETURN)[0]
    return Endpoint(
        **assembly_registers(end),
        memory=end.memory.load(row_base, 8),
        constraints=tuple(end.solver.constraints),
    )


def _copy_row_native(
    c_symbol: str, inputs: dict[str, claripy.ast.BV]
) -> Endpoint:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(c_symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["memory"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    end = manager.deadended[0]
    return Endpoint(
        **native_registers(end, NATIVE_STATE),
        memory=end.memory.load(NATIVE_STATE + 8, 8),
        constraints=tuple(end.solver.constraints),
    )


PALETTE_MEMORY_NAMES = (
    "on_sgb",
    "animation_palette",
    "animation_id",
    "object_palette0",
    "object_palette1",
)


def _palette_addresses() -> dict[str, int]:
    return {
        "on_sgb": symbol_location(SYMBOLS, "wOnSGB").address,
        "animation_palette": symbol_location(SYMBOLS, "wAnimPalette").address,
        "animation_id": symbol_location(SYMBOLS, "wAnimationID").address,
        "object_palette0": 0xFF48,
        "object_palette1": 0xFF49,
    }


def _palette_assembly(inputs: dict[str, claripy.ast.BV]) -> list[PaletteEndpoint]:
    project, address = _z80_project("SetAnimationPalette")
    addresses = _palette_addresses()
    project.hook(address, Sm83LoadAImmediate(addresses["on_sgb"], address + 3), length=3)
    project.hook(
        address + 10,
        Sm83StoreAImmediate(addresses["animation_palette"], address + 13),
        length=3,
    )
    project.hook(
        address + 15,
        Sm83LoadAImmediate(addresses["animation_id"], address + 18),
        length=3,
    )
    project.hook(address + 18, Sm83CpImmediate(0xAA, address + 20), length=2)
    project.hook(address + 22, Sm83CpImmediate(0xAE, address + 24), length=2)
    project.hook(
        address + 29,
        Sm83StoreAHighImmediate(0x48, address + 31),
        length=2,
    )
    project.hook(
        address + 33,
        Sm83StoreAHighImmediate(0x49, address + 35),
        length=2,
    )
    project.hook(
        address + 38,
        Sm83StoreAImmediate(addresses["animation_palette"], address + 41),
        length=3,
    )
    project.hook(
        address + 41,
        Sm83StoreAHighImmediate(0x48, address + 43),
        length=2,
    )
    project.hook(
        address + 45,
        Sm83StoreAHighImmediate(0x49, address + 47),
        length=2,
    )
    state = project.factory.blank_state(addr=address)
    set_assembly_registers(state, inputs)
    for name, memory_address in addresses.items():
        state.memory.store(memory_address, inputs[name])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    return [
        PaletteEndpoint(
            **assembly_registers(end),
            **{
                name: end.memory.load(memory_address, 1)
                for name, memory_address in addresses.items()
            },
            constraints=tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, GB_RETURN)
    ]


def _palette_native(inputs: dict[str, claripy.ast.BV]) -> list[PaletteEndpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_set_animation_palette")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    for offset, name in enumerate(PALETTE_MEMORY_NAMES, 8):
        state.memory.store(NATIVE_STATE + offset, inputs[name])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        PaletteEndpoint(
            **native_registers(end, NATIVE_STATE),
            **{
                name: end.memory.load(NATIVE_STATE + offset, 1)
                for offset, name in enumerate(PALETTE_MEMORY_NAMES, 8)
            },
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


def _falling_movement_assembly(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, address = _z80_project("FallingObjects_UpdateMovementByte")
    memory_address = symbol_location(SYMBOLS, "wFallingObjectMovementByte").address
    project.hook(address, Sm83LoadAImmediate(memory_address, address + 3), length=3)
    project.hook(address + 3, Sm83IncRegister("a", address + 4), length=1)
    project.hook(address + 7, Sm83CpImmediate(9, address + 9), length=2)
    project.hook(
        address + 16,
        Sm83StoreAImmediate(memory_address, address + 19),
        length=3,
    )
    state = project.factory.blank_state(addr=address)
    set_assembly_registers(state, inputs)
    state.memory.store(memory_address, inputs["memory"])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    return [
        Endpoint(
            **assembly_registers(end),
            memory=end.memory.load(memory_address, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, GB_RETURN)
    ]


def _share_move_assembly(inputs: dict[str, claripy.ast.BV]) -> list[ShareMoveEndpoint]:
    project, address = _z80_project("ShareMoveAnimations")
    turn_address = symbol_location(SYMBOLS, "hWhoseTurn").address
    animation_address = symbol_location(SYMBOLS, "wAnimationID").address
    project.hook(address, Sm83LoadAHighImmediate(0xF3, address + 2), length=2)
    project.hook(
        address + 4,
        Sm83LoadAImmediate(animation_address, address + 7),
        length=3,
    )
    project.hook(address + 7, Sm83CpImmediate(0x85, address + 9), length=2)
    project.hook(address + 13, Sm83CpImmediate(0x9C, address + 15), length=2)
    project.hook(
        address + 19,
        Sm83StoreAImmediate(animation_address, address + 22),
        length=3,
    )
    state = project.factory.blank_state(addr=address)
    set_assembly_registers(state, inputs)
    state.memory.store(turn_address, inputs["whose_turn"])
    state.memory.store(animation_address, inputs["animation_id"])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    return [
        ShareMoveEndpoint(
            **assembly_registers(end),
            whose_turn=end.memory.load(turn_address, 1),
            animation_id=end.memory.load(animation_address, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, GB_RETURN)
    ]


def _share_move_native(inputs: dict[str, claripy.ast.BV]) -> list[ShareMoveEndpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_share_move_animations")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["whose_turn"])
    state.memory.store(NATIVE_STATE + 9, inputs["animation_id"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        ShareMoveEndpoint(
            **native_registers(end, NATIVE_STATE),
            whose_turn=end.memory.load(NATIVE_STATE + 8, 1),
            animation_id=end.memory.load(NATIVE_STATE + 9, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


def _falling_init_assembly(
    symbol: str, count: int, inputs: dict[str, claripy.ast.BV]
) -> FallingInitEndpoint:
    project, address = _z80_project(symbol)
    num_address = symbol_location(SYMBOLS, "wNumFallingObjects").address
    if symbol == "FallingObjects_InitXCoords":
        destination = symbol_location(SYMBOLS, "wShadowOAMSprite00XCoord").address
        memory_size = 80
        dec_offset = 16
    else:
        destination = symbol_location(SYMBOLS, "wFallingObjectsMovementData").address
        memory_size = 20
        dec_offset = 13
    project.hook(
        address + 6,
        Sm83LoadAImmediate(num_address, address + 9),
        length=3,
    )
    project.hook(
        address + 11,
        Sm83StoreAAtHlIncrement(address + 12),
        length=1,
    )
    project.hook(
        address + dec_offset,
        Sm83DecRegister("c", address + dec_offset + 1),
        length=1,
    )
    state = project.factory.blank_state(addr=address)
    set_assembly_registers(state, inputs)
    state.memory.store(num_address, claripy.BVV(count, 8))
    state.memory.store(destination, inputs["memory"])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    end = collect_returns(project, state, GB_RETURN)[0]
    return FallingInitEndpoint(
        **assembly_registers(end),
        num_objects=end.memory.load(num_address, 1),
        memory=end.memory.load(destination, memory_size),
        constraints=tuple(end.solver.constraints),
    )


def _falling_init_native(
    c_symbol: str, count: int, memory_size: int, inputs: dict[str, claripy.ast.BV]
) -> FallingInitEndpoint:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(c_symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, claripy.BVV(count, 8))
    state.memory.store(NATIVE_STATE + 9, inputs["memory"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    end = manager.deadended[0]
    return FallingInitEndpoint(
        **native_registers(end, NATIVE_STATE),
        num_objects=end.memory.load(NATIVE_STATE + 8, 1),
        memory=end.memory.load(NATIVE_STATE + 9, memory_size),
        constraints=tuple(end.solver.constraints),
    )


def _falling_oam_assembly(
    offset: int, inputs: dict[str, claripy.ast.BV]
) -> list[FallingOamEndpoint]:
    project, address = _z80_project("FallingObjects_UpdateOAMEntry")
    movement_address = symbol_location(SYMBOLS, "wFallingObjectMovementByte").address
    oam_address = symbol_location(SYMBOLS, "wShadowOAM").address + offset
    project.hook(address + 7, Sm83CpImmediate(112, address + 9), length=2)
    project.hook(
        address + 13,
        Sm83StoreAAtHlIncrement(address + 14),
        length=1,
    )
    project.hook(
        address + 14,
        Sm83LoadAImmediate(movement_address, address + 17),
        length=3,
    )
    project.hook(
        address + 35,
        Sm83StoreAAtHlIncrement(address + 36),
        length=1,
    )
    project.hook(address + 43, Sm83SubRegister("b", address + 44), length=1)
    project.hook(
        address + 44,
        Sm83StoreAAtHlIncrement(address + 45),
        length=1,
    )
    state = project.factory.blank_state(addr=address)
    set_assembly_registers(state, inputs)
    state.memory.store(movement_address, inputs["movement_byte"])
    state.memory.store(oam_address, inputs["oam_entry"])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    return [
        FallingOamEndpoint(
            **assembly_registers(end),
            movement_byte=end.memory.load(movement_address, 1),
            oam_entry=end.memory.load(oam_address, 4),
            constraints=tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, GB_RETURN)
    ]


def _falling_oam_native(
    inputs: dict[str, claripy.ast.BV]
) -> list[FallingOamEndpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_falling_objects_update_oam_entry")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["movement_byte"])
    state.memory.store(NATIVE_STATE + 9, inputs["oam_entry"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        FallingOamEndpoint(
            **native_registers(end, NATIVE_STATE),
            movement_byte=end.memory.load(NATIVE_STATE + 8, 1),
            oam_entry=end.memory.load(NATIVE_STATE + 9, 4),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


def _adjust_oam_assembly(
    symbol: str, threshold: int, inputs: dict[str, claripy.ast.BV]
) -> list[AdjustOamEndpoint]:
    project, address = _z80_project(symbol)
    prefix = 0 if symbol.endswith("Pos2") else 2
    adjustment_address = symbol_location(SYMBOLS, "wCoordAdjustmentAmount").address
    project.hook(
        address + prefix + 3,
        Sm83LoadAImmediate(adjustment_address, address + prefix + 6),
        length=3,
    )
    project.hook(
        address + prefix + 9,
        Sm83CpImmediate(threshold, address + prefix + 11),
        length=2,
    )
    project.hook(
        address + prefix + 16,
        Sm83StoreAAtHlIncrement(address + prefix + 17),
        length=1,
    )
    project.hook(
        address + prefix + 19,
        Sm83DecRegister("c", address + prefix + 20),
        length=1,
    )
    state = project.factory.blank_state(addr=address)
    set_assembly_registers(state, inputs)
    state.memory.store(adjustment_address, inputs["adjustment"])
    state.memory.store(0xC300, inputs["oam"])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    return [
        AdjustOamEndpoint(
            **assembly_registers(end),
            adjustment=end.memory.load(adjustment_address, 1),
            oam=end.memory.load(0xC300, 16),
            constraints=tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, GB_RETURN)
    ]


def _adjust_oam_native(
    c_symbol: str, inputs: dict[str, claripy.ast.BV]
) -> list[AdjustOamEndpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(c_symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["adjustment"])
    state.memory.store(NATIVE_STATE + 9, inputs["oam"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        AdjustOamEndpoint(
            **native_registers(end, NATIVE_STATE),
            adjustment=end.memory.load(NATIVE_STATE + 8, 1),
            oam=end.memory.load(NATIVE_STATE + 9, 16),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


def _oam_write_assembly(inputs: dict[str, claripy.ast.BV]) -> OamWriteEndpoint:
    project, address = _z80_project("BattleAnimWriteOAMEntry")
    base_x_address = symbol_location(SYMBOLS, "wBaseCoordX").address
    for offset in (4, 8, 10, 12):
        project.hook(
            address + offset,
            Sm83StoreAAtHlIncrement(address + offset + 1),
            length=1,
        )
    project.hook(
        address + 5,
        Sm83LoadAImmediate(base_x_address, address + 8),
        length=3,
    )
    state = project.factory.blank_state(addr=address)
    set_assembly_registers(state, inputs)
    state.memory.store(base_x_address, inputs["base_x"])
    state.memory.store(0xC300, inputs["oam_entry"])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    end = collect_returns(project, state, GB_RETURN)[0]
    return OamWriteEndpoint(
        **assembly_registers(end),
        base_x=end.memory.load(base_x_address, 1),
        oam_entry=end.memory.load(0xC300, 4),
        constraints=tuple(end.solver.constraints),
    )


def _oam_write_native(inputs: dict[str, claripy.ast.BV]) -> OamWriteEndpoint:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_battle_anim_write_oam_entry")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["base_x"])
    state.memory.store(NATIVE_STATE + 9, inputs["oam_entry"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    end = manager.deadended[0]
    return OamWriteEndpoint(
        **native_registers(end, NATIVE_STATE),
        base_x=end.memory.load(NATIVE_STATE + 8, 1),
        oam_entry=end.memory.load(NATIVE_STATE + 9, 4),
        constraints=tuple(end.solver.constraints),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("assembly_symbol", "c_symbol"),
    [
        ("GetSubanimationTransform1", "port_get_subanimation_transform1"),
        ("GetSubanimationTransform2", "port_get_subanimation_transform2"),
    ],
)
def test_battle_animation_helper_symbolic_equivalence(
    assembly_symbol: str, c_symbol: str
) -> None:
    inputs = symbolic_registers(assembly_symbol)
    inputs["memory"] = claripy.BVS(f"{assembly_symbol}_memory", 8)
    assert_pathwise_equivalent(
        _assembly_endpoints(assembly_symbol, inputs),
        _native_endpoints(c_symbol, inputs),
        (*REGISTERS, "memory"),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("row_count", range(1, 8))
def test_mon_sprite_tilemap_pointer_symbolic_equivalence(row_count: int) -> None:
    prefix = f"mon_sprite_tilemap_{row_count}"
    inputs = symbolic_registers(prefix)
    inputs["b"] = claripy.BVV(row_count, 8)
    inputs["memory"] = claripy.BVS(f"{prefix}_whose_turn", 8)
    assert_pathwise_equivalent(
        _tilemap_assembly(inputs),
        _tilemap_native(inputs),
        (*REGISTERS, "memory"),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("tilemap_index", range(8))
def test_get_tile_id_list_symbolic_equivalence(tilemap_index: int) -> None:
    inputs = symbolic_registers(f"get_tile_id_list_{tilemap_index}")
    inputs["a"] = claripy.BVV(tilemap_index, 8)
    assert_pathwise_equivalent(
        [_tile_id_assembly(inputs)],
        [_tile_id_native(inputs)],
        REGISTERS,
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("assembly_symbol", "c_symbol", "count"),
    [
        ("AnimCopyRowLeft", "port_anim_copy_row_left", 3),
        ("AnimCopyRowLeft", "port_anim_copy_row_left", 7),
        ("AnimCopyRowRight", "port_anim_copy_row_right", 3),
        ("AnimCopyRowRight", "port_anim_copy_row_right", 7),
    ],
)
def test_anim_copy_row_symbolic_equivalence(
    assembly_symbol: str, c_symbol: str, count: int
) -> None:
    prefix = f"{assembly_symbol}_{count}"
    inputs = symbolic_registers(prefix)
    inputs["c"] = claripy.BVV(count, 8)
    inputs["h"] = claripy.BVV(0xC5, 8)
    inputs["l"] = claripy.BVV(0, 8)
    inputs["memory"] = claripy.BVS(f"{prefix}_memory", 64)
    assert_pathwise_equivalent(
        [_copy_row_assembly(assembly_symbol, count, inputs)],
        [_copy_row_native(c_symbol, inputs)],
        (*REGISTERS, "memory"),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_set_animation_palette_symbolic_equivalence() -> None:
    inputs = symbolic_registers("set_animation_palette")
    for name in PALETTE_MEMORY_NAMES:
        inputs[name] = claripy.BVS(f"set_animation_palette_{name}", 8)
    assert_pathwise_equivalent(
        _palette_assembly(inputs),
        _palette_native(inputs),
        (*REGISTERS, *PALETTE_MEMORY_NAMES),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_falling_movement_byte_symbolic_equivalence() -> None:
    inputs = symbolic_registers("falling_movement_byte")
    inputs["memory"] = claripy.BVS("falling_movement_byte_memory", 8)
    assert_pathwise_equivalent(
        _falling_movement_assembly(inputs),
        _native_endpoints("port_falling_objects_update_movement_byte", inputs),
        (*REGISTERS, "memory"),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_share_move_animations_symbolic_equivalence() -> None:
    inputs = symbolic_registers("share_move_animations")
    inputs["whose_turn"] = claripy.BVS("share_move_animations_turn", 8)
    inputs["animation_id"] = claripy.BVS("share_move_animations_id", 8)
    assert_pathwise_equivalent(
        _share_move_assembly(inputs),
        _share_move_native(inputs),
        (*REGISTERS, "whose_turn", "animation_id"),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("assembly_symbol", "c_symbol", "count", "memory_size"),
    [
        ("FallingObjects_InitXCoords", "port_falling_objects_init_x_coords", 3, 80),
        ("FallingObjects_InitXCoords", "port_falling_objects_init_x_coords", 20, 80),
        (
            "FallingObjects_InitMovementData",
            "port_falling_objects_init_movement_data",
            3,
            20,
        ),
        (
            "FallingObjects_InitMovementData",
            "port_falling_objects_init_movement_data",
            20,
            20,
        ),
    ],
)
def test_falling_object_initializers_symbolic_equivalence(
    assembly_symbol: str, c_symbol: str, count: int, memory_size: int
) -> None:
    prefix = f"{assembly_symbol}_{count}"
    inputs = symbolic_registers(prefix)
    inputs["memory"] = claripy.BVS(f"{prefix}_memory", memory_size * 8)
    assert_pathwise_equivalent(
        [_falling_init_assembly(assembly_symbol, count, inputs)],
        [_falling_init_native(c_symbol, count, memory_size, inputs)],
        (*REGISTERS, "num_objects", "memory"),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("offset", range(0, 80, 4))
def test_falling_object_oam_update_symbolic_equivalence(offset: int) -> None:
    prefix = f"falling_oam_{offset}"
    inputs = symbolic_registers(prefix)
    inputs["d"] = claripy.BVV(offset >> 8, 8)
    inputs["e"] = claripy.BVV(offset & 0xFF, 8)
    inputs["movement_byte"] = claripy.BVS(f"{prefix}_movement", 8)
    inputs["oam_entry"] = claripy.BVS(f"{prefix}_entry", 32)
    assert_pathwise_equivalent(
        _falling_oam_assembly(offset, inputs),
        _falling_oam_native(inputs),
        (*REGISTERS, "movement_byte", "oam_entry"),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("assembly_symbol", "c_symbol", "threshold", "count"),
    [
        ("AdjustOAMBlockXPos2", "port_adjust_oam_block_x_pos2", 168, 1),
        ("AdjustOAMBlockXPos2", "port_adjust_oam_block_x_pos2", 168, 2),
        ("AdjustOAMBlockXPos2", "port_adjust_oam_block_x_pos2", 168, 3),
        ("AdjustOAMBlockXPos2", "port_adjust_oam_block_x_pos2", 168, 4),
        ("AdjustOAMBlockYPos2", "port_adjust_oam_block_y_pos2", 112, 1),
        ("AdjustOAMBlockYPos2", "port_adjust_oam_block_y_pos2", 112, 2),
        ("AdjustOAMBlockYPos2", "port_adjust_oam_block_y_pos2", 112, 3),
        ("AdjustOAMBlockYPos2", "port_adjust_oam_block_y_pos2", 112, 4),
        ("AdjustOAMBlockXPos", "port_adjust_oam_block_x_pos", 168, 4),
        ("AdjustOAMBlockYPos", "port_adjust_oam_block_y_pos", 112, 4),
    ],
)
def test_adjust_oam_block_symbolic_equivalence(
    assembly_symbol: str, c_symbol: str, threshold: int, count: int
) -> None:
    prefix = f"{assembly_symbol}_{count}"
    inputs = symbolic_registers(prefix)
    inputs["c"] = claripy.BVV(count, 8)
    if assembly_symbol.endswith("Pos2"):
        inputs["h"] = claripy.BVV(0xC3, 8)
        inputs["l"] = claripy.BVV(0x01, 8)
    else:
        inputs["d"] = claripy.BVV(0xC3, 8)
        inputs["e"] = claripy.BVV(0x01, 8)
    inputs["adjustment"] = claripy.BVS(f"{prefix}_adjustment", 8)
    inputs["oam"] = claripy.BVS(f"{prefix}_oam", 128)
    assert_pathwise_equivalent(
        _adjust_oam_assembly(assembly_symbol, threshold, inputs),
        _adjust_oam_native(c_symbol, inputs),
        (*REGISTERS, "adjustment", "oam"),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_battle_anim_write_oam_entry_symbolic_equivalence() -> None:
    inputs = symbolic_registers("battle_anim_write_oam_entry")
    inputs["h"] = claripy.BVV(0xC3, 8)
    inputs["l"] = claripy.BVV(0, 8)
    inputs["base_x"] = claripy.BVS("battle_anim_write_oam_entry_base_x", 8)
    inputs["oam_entry"] = claripy.BVS("battle_anim_write_oam_entry_memory", 32)
    assert_pathwise_equivalent(
        [_oam_write_assembly(inputs)],
        [_oam_write_native(inputs)],
        (*REGISTERS, "base_x", "oam_entry"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "size", "expected"),
    [
        ("GetSubanimationTransform1", 8, "47f0f3a778c0afc9"),
        ("GetSubanimationTransform2", 8, "f0f3a73e40c8afc9"),
        ("IsCryMove", 15, "fa7cd0fe2d2806fe2e2802a7c937c9"),
        (
            "GetMonSpriteTileMapPointerFromRowCount",
            34,
            "d5f0f3a720043e6518023e0c21a0c35f1600193e0790a72807111400193d20fcd1c9",
        ),
        (
            "GetTileIDList",
            25,
            "21ea5a5f16001919192a5f2a572a47e60f4f78cb37e60f47c9",
        ),
        ("AnimCopyRowLeft", 7, "3a22230d20fac9"),
        ("AnimCopyRowRight", 7, "2a322b0d20fac9"),
        (
            "SetAnimationPalette",
            48,
            "fa1bcfa73ee4281c3ef0ea79cc06e4fa7cd0feaa3806feae300206f078e0483e6ce049c93ee4ea79cce0483e6ce049c9",
        ),
        (
            "FallingObjects_UpdateMovementByte",
            20,
            "fa8ad03c47e67ffe09782004e680ee80ea8ad0c9",
        ),
        (
            "ShareMoveAnimations",
            23,
            "f0f3a7c8fa7cd0fe8506bf2805fe9c06bdc078ea7cd0c9",
        ),
        (
            "FallingObjects_InitXCoords",
            20,
            "2101c3113e5dfa8bd04f1a22232323130d20f7c9",
        ),
        (
            "FallingObjects_InitMovementData",
            17,
            "213dcd11635dfa8bd04f1a22130d20fac9",
        ),
        (
            "FallingObjects_UpdateOAMEntry",
            50,
            "2100c3197e3c3cfe7038023ea022fa8ad047110d5de67f833001145f78e68020071a862223af18081a477e9022233e2077c9",
        ),
        (
            "AdjustOAMBlockXPos2",
            23,
            "110400fa8ad0477e80fea838042b3ea02277190d20edc9",
        ),
        (
            "AdjustOAMBlockYPos2",
            23,
            "110400fa8ad0477e80fe7038042b3ea02277190d20edc9",
        ),
        (
            "AdjustOAMBlockXPos",
            25,
            "6b62110400fa8ad0477e80fea838042b3ea02277190d20edc9",
        ),
        (
            "AdjustOAMBlockYPos",
            25,
            "6b62110400fa8ad0477e80fe7038042b3ea02277190d20edc9",
        ),
        (
            "BattleAnimWriteOAMEntry",
            14,
            "7bc6085f22fa81d0227a22af22c9",
        ),
    ],
)
def test_battle_animation_helper_code_is_accounted_for(
    symbol: str, size: int, expected: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, size) == bytes.fromhex(expected)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_tile_id_list_pointer_table_is_accounted_for() -> None:
    location = symbol_location(SYMBOLS, "TileIDListPointerTable")
    assert linked_bytes(ROM, location, 24) == bytes.fromhex(
        "245b77555b57785b378d5b77be5b77ef5b77205c86505c3c"
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "expected"),
    [
        ("FallingObjects_InitialXCoords", "3840506070889056674a77849832225c6c7d8e99"),
        ("FallingObjects_InitialMovementData", "0084068102880183058909800787038204850886"),
        (
            "FallingObjects_DeltaXs",
            "0001030507090b0d0ffa8ad03c47e67ffe09782004e680ee80ea8ad0c92101c3113e5dfa8bd04f1a22232323130d20f7c93840506070889056674a77849832225c6c7d8e99213dcd11635dfa8bd04f1a22130d20fac90084068102880183058909800787038204850886111093210080013100cd4818afe0ae210098cd0d5e3e",
        ),
    ],
)
def test_falling_object_tables_are_accounted_for(symbol: str, expected: str) -> None:
    location = symbol_location(SYMBOLS, symbol)
    expected_bytes = bytes.fromhex(expected)
    assert linked_bytes(ROM, location, len(expected_bytes)) == expected_bytes
