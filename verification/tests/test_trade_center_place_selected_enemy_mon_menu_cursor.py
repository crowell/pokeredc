from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
    set_assembly_registers,
    store_native_registers,
    symbolic_registers,
)
from verification.harness.rom import (
    collect_returns,
    linked_bytes,
    rom_window,
    symbol_location,
)
from verification.harness.sm83_shims import Sm83LoadAImmediate


class AddNTimesInline(angr.SimProcedure):
    """Model ``call AddNTimes``: hl = hl + bc * a (a = 0 leaves hl unchanged),
    a = 0, b/c preserved."""

    def __init__(self, next_address: int, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        state = self.state
        a = state.regs.a
        bc = claripy.ZeroExt(8, state.regs.c) | (claripy.ZeroExt(8, state.regs.b) << 8)
        hl = claripy.ZeroExt(8, state.regs.l) | (claripy.ZeroExt(8, state.regs.h) << 8)
        new_hl = (hl + bc * claripy.ZeroExt(8, a)) & 0xFFFF
        state.regs.a = claripy.BVV(0, 8)
        state.regs.h = claripy.Extract(15, 8, new_hl)
        state.regs.l = claripy.Extract(7, 0, new_hl)
        self.jump(self._next_address)


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification" / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
GB_RETURN = 0xFFFF
NATIVE_STATE = 0x100000

W_TILE_MAP = 0xC3A0
W_SERIAL = 0xCC3D
SCREEN_WIDTH = 20
CURSOR = 0xEC
# Menu rows 0..5 cover the six party slots.
ROWS = (0, 1, 2, 3, 4, 5)


def _store_row(state: angr.SimState, row: int) -> None:
    # The selected row is loaded from [wSerialSyncAndExchangeNybbleReceiveData];
    # kept concrete so the tilemap store address is concrete.
    state.memory.store(W_SERIAL, claripy.BVV(row, 8))


@dataclass(frozen=True)
class Endpoint:
    m_cursor: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _load(end: angr.SimState, row: int) -> Endpoint:
    addr = W_TILE_MAP + 9 * SCREEN_WIDTH + 1 + row * SCREEN_WIDTH
    return Endpoint(
        m_cursor=end.memory.load(addr, 1),
        constraints=tuple(end.solver.constraints),
    )


def _assembly_endpoint(row: int) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "TradeCenter_PlaceSelectedEnemyMonMenuCursor")
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
    # ld a, [wSerialSyncAndExchangeNybbleReceiveData] (0xFA) -> a = row.
    project.hook(base + 0x00, Sm83LoadAImmediate(W_SERIAL, base + 0x03), length=3)
    # call AddNTimes: hl = hl + bc*a (bc = SCREEN_WIDTH, a = row).
    project.hook(base + 0x09, AddNTimesInline(base + 0x0C), length=3)
    # ld hl, wTileMap+1+9*SCREEN_WIDTH, ld bc, SCREEN_WIDTH, ld [hl], CURSOR,
    # ret run natively.
    state = project.factory.blank_state(addr=base)
    _store_row(state, row)
    set_assembly_registers(state, symbolic_registers("tc"))
    state.regs.sp = claripy.BVV(0xE000, 16)
    state.memory.store(0xE000, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    return [_load(end, row) for end in returned]


def _native_endpoint(row: int) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(
        "port_trade_center_place_selected_enemy_mon_menu_cursor"
    )
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, claripy.BVV(0, 64)
    )
    store_native_registers(state, NATIVE_STATE, symbolic_registers("tc"))
    _store_row(state, row)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [_load(end, row) for end in manager.deadended]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("row", ROWS)
def test_trade_center_cursor_symbolic_equivalence(row: int) -> None:
    assembly = _assembly_endpoint(row)
    native = _native_endpoint(row)
    assert_pathwise_equivalent(assembly, native, ("m_cursor",))


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_trade_center_cursor_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "TradeCenter_PlaceSelectedEnemyMonMenuCursor")
    expected = bytes.fromhex("fa3dcc2155c4011400cd873a36ecc9")
    assert linked_bytes(ROM, location, len(expected)) == expected
