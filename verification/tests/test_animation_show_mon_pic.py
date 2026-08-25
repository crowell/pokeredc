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
from verification.harness.rom import (
    collect_returns,
    linked_bytes,
    rom_window,
    sm83_flags_to_z80,
    symbol_location,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
STACK = 0xD000
RETURN = 0xFFFF
WHOSE_TURN = 0xFFF3
BASE_TILE = 0xFF8B
AUTO_TRANSFER = 0xFFBA
TILEMAP_START = 0xC3AC
TILEMAP_SIZE = 0xC484 - TILEMAP_START
EXPECTED = bytes.fromhex("afcd4258cd2058cdae5ac3d73d")
CALLS = ("tile_ids", "pointer", "copy", "delay")


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
    state: claripy.ast.BV
    calls: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class XorA(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x40, 8)
        self.jump(self._next_address)


def _output_registers(
    state: angr.SimState, name: str, native: bool = False
) -> None:
    for index, register in enumerate(REGISTERS):
        value = state.globals[f"{name}_out_{register}"]
        if register == "f" and not native:
            value = sm83_flags_to_z80(value)
        if native:
            state.memory.store(state.regs.rdi + index, value)
        else:
            setattr(state.regs, register, value)


class AssemblySummary(angr.SimProcedure):
    def __init__(self, name: str) -> None:
        super().__init__()
        self._name = name

    def run(self) -> None:  # type: ignore[override]
        call = [assembly_registers(self.state)[name] for name in REGISTERS]
        if self._name == "pointer":
            call.append(self.state.memory.load(WHOSE_TURN, 1))
        elif self._name == "copy":
            call.extend(
                (
                    self.state.memory.load(BASE_TILE, 1),
                    self.state.memory.load(AUTO_TRANSFER, 1),
                    self.state.memory.load(WHOSE_TURN, 1),
                    self.state.memory.load(TILEMAP_START, TILEMAP_SIZE),
                )
            )
        elif self._name == "delay":
            call.append(self.state.memory.load(TILEMAP_START, TILEMAP_SIZE))
        self.state.globals[f"{self._name}_call"] = claripy.Concat(*call)
        _output_registers(self.state, self._name)
        if self._name == "copy":
            self.state.memory.store(
                BASE_TILE, self.state.globals["copy_out_base_tile"]
            )
            self.state.memory.store(
                AUTO_TRANSFER, self.state.globals["copy_out_auto_transfer"]
            )
            self.state.memory.store(
                TILEMAP_START, self.state.globals["copy_out_tilemap"]
            )
        return_address = self.state.memory.load(
            self.state.regs.sp, 2, endness="Iend_LE"
        )
        self.state.regs.sp += 2
        self.jump(return_address)


class NativeSummary(angr.SimProcedure):
    def __init__(self, name: str) -> None:
        super().__init__()
        self._name = name

    def run(self) -> None:  # type: ignore[override]
        address = self.state.regs.rdi
        call = [self.state.memory.load(address, 8)]
        if self._name == "pointer":
            call.append(self.state.memory.load(address + 8, 1))
        elif self._name == "copy":
            call.extend(
                (
                    self.state.memory.load(address + 8, 2),
                    self.state.memory.load(address + 18, 1),
                    self.state.memory.load(
                        self.state.regs.rsi + TILEMAP_START, TILEMAP_SIZE
                    ),
                )
            )
        elif self._name == "delay":
            call.append(
                self.state.memory.load(
                    self.state.regs.rsi + TILEMAP_START, TILEMAP_SIZE
                )
            )
        self.state.globals[f"{self._name}_call"] = claripy.Concat(*call)
        _output_registers(self.state, self._name, native=True)
        if self._name == "copy":
            self.state.memory.store(
                address + 8, self.state.globals["copy_out_base_tile"]
            )
            self.state.memory.store(
                address + 9, self.state.globals["copy_out_auto_transfer"]
            )
            self.state.memory.store(
                self.state.regs.rsi + TILEMAP_START,
                self.state.globals["copy_out_tilemap"],
            )


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["whose_turn"] = claripy.BVS(f"{prefix}_whose_turn", 8)
    values["base_tile"] = claripy.BVS(f"{prefix}_base_tile", 8)
    values["auto_transfer"] = claripy.BVS(f"{prefix}_auto_transfer", 8)
    values["tilemap"] = claripy.BVS(f"{prefix}_tilemap", TILEMAP_SIZE * 8)
    for call in CALLS:
        for register in REGISTERS:
            if register == "f":
                values[f"{call}_out_f"] = claripy.Concat(
                    claripy.BVS(f"{prefix}_{call}_out_flags", 4),
                    claripy.BVV(0, 4),
                )
            else:
                values[f"{call}_out_{register}"] = claripy.BVS(
                    f"{prefix}_{call}_out_{register}", 8
                )
    values["copy_out_base_tile"] = claripy.BVS(
        f"{prefix}_copy_out_base_tile", 8
    )
    values["copy_out_auto_transfer"] = claripy.BVS(
        f"{prefix}_copy_out_auto_transfer", 8
    )
    values["copy_out_tilemap"] = claripy.BVS(
        f"{prefix}_copy_out_tilemap", TILEMAP_SIZE * 8
    )
    return values


def _setup_globals(
    state: angr.SimState, values: dict[str, claripy.ast.BV]
) -> None:
    for call in CALLS:
        for register in REGISTERS:
            state.globals[f"{call}_out_{register}"] = values[
                f"{call}_out_{register}"
            ]
    for name in (
        "copy_out_base_tile",
        "copy_out_auto_transfer",
        "copy_out_tilemap",
    ):
        state.globals[name] = values[name]


def _calls(state: angr.SimState) -> claripy.ast.BV:
    return claripy.Concat(*(state.globals[f"{name}_call"] for name in CALLS))


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "AnimationShowMonPic")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
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
        XorA(location.address + 1),
        length=1,
    )
    for name, symbol in (
        ("tile_ids", "GetTileIDList"),
        ("pointer", "GetMonSpriteTileMapPointerFromRowCount"),
        ("copy", "CopyPicTiles"),
        ("delay", "Delay3"),
    ):
        project.hook(symbol_location(SYMBOLS, symbol).address, AssemblySummary(name))
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.regs.sp = claripy.BVV(STACK, 16)
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    state.memory.store(WHOSE_TURN, values["whose_turn"])
    state.memory.store(BASE_TILE, values["base_tile"])
    state.memory.store(AUTO_TRANSFER, values["auto_transfer"])
    state.memory.store(TILEMAP_START, values["tilemap"])
    _setup_globals(state, values)
    return [
        Endpoint(
            **assembly_registers(end),
            state=claripy.Concat(
                end.memory.load(WHOSE_TURN, 1),
                end.memory.load(BASE_TILE, 1),
                end.memory.load(AUTO_TRANSFER, 1),
                end.memory.load(TILEMAP_START, TILEMAP_SIZE),
            ),
            calls=_calls(end),
            constraints=tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, RETURN)
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_animation_show_mon_pic")
    assert function is not None
    for name, symbol in (
        ("tile_ids", "port_get_tile_id_list"),
        ("pointer", "port_get_mon_sprite_tilemap_pointer_from_row_count"),
        ("copy", "port_copy_pic_tiles"),
        ("delay", "port_delay3"),
    ):
        callee = project.loader.find_symbol(symbol)
        assert callee is not None
        project.hook(callee.rebased_addr, NativeSummary(name))
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(
        NATIVE_STATE + 8,
        claripy.Concat(
            values["whose_turn"],
            values["base_tile"],
            values["auto_transfer"],
        ),
    )
    state.memory.store(
        NATIVE_STATE + 11 + TILEMAP_START, values["tilemap"]
    )
    _setup_globals(state, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            state=claripy.Concat(
                end.memory.load(NATIVE_STATE + 8, 3),
                end.memory.load(
                    NATIVE_STATE + 11 + TILEMAP_START, TILEMAP_SIZE
                ),
            ),
            calls=_calls(end),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_animation_show_mon_pic_pathwise_equivalence() -> None:
    values = _inputs("animation_show_mon_pic")
    assert_pathwise_equivalent(
        _assembly(values), _native(values), (*REGISTERS, "state", "calls")
    )
