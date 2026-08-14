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
from verification.harness.sm83_shims import (
    Sm83LoadAImmediate,
    Sm83StoreAImmediate,
    Sm83LoadAAtHlIncrement,
    Sm83StoreAAtHlIncrement,
)
class AddNTimesInline(angr.SimProcedure):
    """Model ``call AddNTimes``: hl = hl + bc*a (a = 0 leaves hl unchanged)."""

    def __init__(self, return_address: int) -> None:
        super().__init__()
        self._return_address = return_address

    def run(self) -> None:  # type: ignore[override]
        state = self.state
        a = state.regs.a
        bc = claripy.ZeroExt(8, state.regs.c) | (claripy.ZeroExt(8, state.regs.b) << 8)
        hl = claripy.ZeroExt(8, state.regs.l) | (claripy.ZeroExt(8, state.regs.h) << 8)
        new_hl = (hl + bc * claripy.ZeroExt(8, a)) & 0xFFFF
        state.regs.a = claripy.BVV(0, 8)
        state.regs.h = claripy.Extract(15, 8, new_hl)
        state.regs.l = claripy.Extract(7, 0, new_hl)
        self.jump(self._return_address)


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification" / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
GB_RETURN = 0xFFFF
NATIVE_STATE = 0x100000

W_WHICHPOKEMON = 0xCF92
W_PARTY_MON1_MOVES = 0xD173
W_FIELD_MOVES = 0xCD3D
W_NUM_FIELD_MOVES = 0xCD41
W_FIELD_MOVES_LEFTMOST_XCOORD = 0xCD42
W_LAST_FIELD_MOVE_ID = 0xCD43
FIELD_MOVE_DISPLAY_DATA = 0x7823

# Concrete FieldMoveDisplayData table read from ROM (move_id, name_index,
# xcoord)*9 then $ff. Move ids are every third byte.
_TABLE = linked_bytes(ROM, symbol_location(SYMBOLS, "FieldMoveDisplayData"), 30)
_MOVE_IDS = [b for i, b in enumerate(_TABLE[:27]) if i % 3 == 0]

# Party-move sets exercising: all-field, none-field, mixed, field-then-empty.
MOVES_SETS = [
    tuple(_MOVE_IDS[:4]),
    (1, 2, 3, 4),
    (_MOVE_IDS[0], 1, _MOVE_IDS[3], 2),
    (_MOVE_IDS[0], 0, 0, 0),
]

@dataclass(frozen=True)
class Endpoint:
    m_wfieldmoves: claripy.ast.BV
    m_nfm: claripy.ast.BV
    m_leftmost: claripy.ast.BV
    m_lastid: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]
def _store_inputs(state: angr.SimState, moves) -> None:
    state.memory.store(W_WHICHPOKEMON, claripy.BVV(0, 8))
    for i, m in enumerate(moves):
        state.memory.store(W_PARTY_MON1_MOVES + i, claripy.BVV(m, 8))
    for i, byte in enumerate(_TABLE):
        state.memory.store(FIELD_MOVE_DISPLAY_DATA + i, claripy.BVV(byte, 8))
    # Caller precondition: the field-move output region is cleared beforehand.
    for i in range(4):
        state.memory.store(W_FIELD_MOVES + i, claripy.BVV(0, 8))
    state.memory.store(W_LAST_FIELD_MOVE_ID, claripy.BVV(0, 8))
    state.memory.store(W_NUM_FIELD_MOVES, claripy.BVV(0, 8))
    state.memory.store(W_FIELD_MOVES_LEFTMOST_XCOORD, claripy.BVV(0xFF, 8))


def _load(end: angr.SimState) -> Endpoint:
    return Endpoint(
        m_wfieldmoves=claripy.Concat(
            *[end.memory.load(W_FIELD_MOVES + i, 1) for i in range(4)]
        ),
        m_nfm=end.memory.load(W_NUM_FIELD_MOVES, 1),
        m_leftmost=end.memory.load(W_FIELD_MOVES_LEFTMOST_XCOORD, 1),
        m_lastid=end.memory.load(W_LAST_FIELD_MOVE_ID, 1),
        constraints=tuple(end.solver.constraints),
    )


def _assembly_endpoint(moves) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "GetMonFieldMoves")
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
    project.hook(base + 0x00, Sm83LoadAImmediate(0xCF92, base + 0x03), length=3)
    project.hook(base + 0x09, AddNTimesInline(base + 0x0C), length=3)
    project.hook(base + 0x20, Sm83LoadAAtHlIncrement(base + 0x21), length=1)
    project.hook(base + 0x2D, Sm83StoreAImmediate(0xCD43, base + 0x30), length=3)
    project.hook(base + 0x30, Sm83LoadAAtHlIncrement(base + 0x31), length=1)
    project.hook(base + 0x33, Sm83StoreAAtHlIncrement(base + 0x34), length=1)
    project.hook(base + 0x34, Sm83LoadAImmediate(0xCD41, base + 0x37), length=3)
    project.hook(base + 0x38, Sm83StoreAImmediate(0xCD41, base + 0x3B), length=3)
    project.hook(base + 0x3B, Sm83LoadAImmediate(0xCD42, base + 0x3E), length=3)
    project.hook(base + 0x42, Sm83StoreAImmediate(0xCD42, base + 0x45), length=3)
    project.hook(base + 0x45, Sm83LoadAImmediate(0xCD43, base + 0x48), length=3)
    state = project.factory.blank_state(addr=base)
    _store_inputs(state, moves)
    set_assembly_registers(state, symbolic_registers("gm"))
    state.regs.sp = claripy.BVV(0xE000, 16)
    state.memory.store(0xE000, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    return [_load(end) for end in returned]


def _native_endpoint(moves) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_get_mon_field_moves")
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, claripy.BVV(0, 64)
    )
    store_native_registers(state, NATIVE_STATE, symbolic_registers("gm"))
    _store_inputs(state, moves)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [_load(end) for end in manager.deadended]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("moves", MOVES_SETS, ids=[str(s) for s in MOVES_SETS])
def test_get_mon_field_moves_equivalence(moves) -> None:
    assembly = _assembly_endpoint(moves)
    native = _native_endpoint(moves)
    assert_pathwise_equivalent(
        assembly, native, ("m_wfieldmoves", "m_nfm", "m_leftmost", "m_lastid")
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_get_mon_field_moves_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "GetMonFieldMoves")
    expected = bytes.fromhex(
        "fa92cf2173d1012c00cd873a545d0e05213dcde50d28341aa728304713212378"
        "2afeff28efb82804232318f478ea43cd2a46e122fa41cd3cea41cdfa42cdb8"
        "380478ea42cdfa43cd4718c8e1c9"
    )
    assert linked_bytes(ROM, location, len(expected)) == expected
