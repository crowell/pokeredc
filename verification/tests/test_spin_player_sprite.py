from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
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
)


class CopyDataSim(angr.SimProcedure):
    """Inline ``call CopyData``: copy BC bytes from [HL] to [DE], then return."""

    def __init__(self, next_address: int, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        state = self.state
        h = int(state.solver.eval(state.regs.h))
        l = int(state.solver.eval(state.regs.l))
        d = int(state.solver.eval(state.regs.d))
        e = int(state.solver.eval(state.regs.e))
        b = int(state.solver.eval(state.regs.b))
        c = int(state.solver.eval(state.regs.c))
        hl = (h << 8) | l
        de = (d << 8) | e
        bc = (b << 8) | c
        for _ in range(bc):
            byte = state.memory.load(hl, 1)
            state.memory.store(de, byte)
            hl = (hl + 1) & 0xFFFF
            de = (de + 1) & 0xFFFF
        state.regs.h = claripy.BVV((hl >> 8) & 0xFF, 8)
        state.regs.l = claripy.BVV(hl & 0xFF, 8)
        state.regs.d = claripy.BVV((de >> 8) & 0xFF, 8)
        state.regs.e = claripy.BVV(de & 0xFF, 8)
        state.regs.b = claripy.BVV(0, 8)
        state.regs.c = claripy.BVV(0, 8)
        state.regs.a = claripy.BVV(0, 8)
        self.jump(self._next_address)


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification" / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
GB_RETURN = 0xFFFF
NATIVE_STATE = 0x100000

W_SPRITE_PLAYER_STATE_DATA1_IMAGE_INDEX = 0xC102
W_FACING_DIRECTION_LIST = 0xCD48
HL_BASE = 0xC600  # concrete input pointer for the `ld a, [hl]` image index


@lru_cache(maxsize=None)
def _pp_inputs() -> tuple[claripy.ast.BV, ...]:
    # Symbolic image-index source byte and the four facing-list entries, shared
    # between the asm and native endpoints.
    return (
        claripy.BVS("sps_inbyte", 8),
        claripy.BVS("sps_f0", 8),
        claripy.BVS("sps_f1", 8),
        claripy.BVS("sps_f2", 8),
        claripy.BVS("sps_f3", 8),
    )


def _store_inputs(state: angr.SimState) -> None:
    inbyte, f0, f1, f2, f3 = _pp_inputs()
    state.memory.store(HL_BASE, inbyte)
    state.memory.store(W_FACING_DIRECTION_LIST + 0, f0)
    state.memory.store(W_FACING_DIRECTION_LIST + 1, f1)
    state.memory.store(W_FACING_DIRECTION_LIST + 2, f2)
    state.memory.store(W_FACING_DIRECTION_LIST + 3, f3)


@dataclass(frozen=True)
class Endpoint:
    m_image: claripy.ast.BV
    m_flist0: claripy.ast.BV
    m_flist1: claripy.ast.BV
    m_flist2: claripy.ast.BV
    m_flist3: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _load(end: angr.SimState) -> Endpoint:
    return Endpoint(
        m_image=end.memory.load(W_SPRITE_PLAYER_STATE_DATA1_IMAGE_INDEX, 1),
        m_flist0=end.memory.load(W_FACING_DIRECTION_LIST + 0, 1),
        m_flist1=end.memory.load(W_FACING_DIRECTION_LIST + 1, 1),
        m_flist2=end.memory.load(W_FACING_DIRECTION_LIST + 2, 1),
        m_flist3=end.memory.load(W_FACING_DIRECTION_LIST + 3, 1),
        constraints=tuple(end.solver.constraints),
    )


def _assembly_endpoint(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "SpinPlayerSprite")
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
    # ld [a16], a (0xEA, settings the image index and FACING_LIST+3) is shimmed.
    project.hook(base + 0x01, Sm83StoreAImmediate(0xC102, base + 0x04), length=3)
    # call CopyData is modeled as a BC-byte forward copy from [HL] to [DE].
    project.hook(base + 0x0E, CopyDataSim(base + 0x11), length=3)
    # ld a, [a16] (0xFA, reading the rotated former-first entry) is shimmed.
    project.hook(base + 0x11, Sm83LoadAImmediate(0xCD47, base + 0x14), length=3)
    project.hook(base + 0x14, Sm83StoreAImmediate(0xCD4B, base + 0x17), length=3)
    state = project.factory.blank_state(addr=base)
    _store_inputs(state)
    set_assembly_registers(state, inputs)
    state.regs.sp = claripy.BVV(0xE000, 16)
    state.memory.store(0xE000, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    return [_load(end) for end in returned]


def _native_endpoint(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_spin_player_sprite")
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, claripy.BVV(0, 64)
    )
    store_native_registers(state, NATIVE_STATE, inputs)
    _store_inputs(state)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [_load(end) for end in manager.deadended]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_spin_player_sprite_symbolic_equivalence() -> None:
    inputs = symbolic_registers("sps")
    # The caller passes the image-index source pointer in HL; fix it concrete so
    # the store/copy addresses are concrete (the five name bytes stay symbolic).
    inputs["h"] = claripy.BVV((HL_BASE >> 8) & 0xFF, 8)
    inputs["l"] = claripy.BVV(HL_BASE & 0xFF, 8)
    assembly = _assembly_endpoint(inputs)
    native = _native_endpoint(inputs)
    assert_pathwise_equivalent(
        assembly,
        native,
        ("m_image", "m_flist0", "m_flist1", "m_flist2", "m_flist3"),
    )

@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_spin_player_sprite_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "SpinPlayerSprite")
    expected = bytes.fromhex(
        "7eea02c1e52148cd1147cd010400cdb500fa47cdea4bcde1c9"
    )
    assert linked_bytes(ROM, location, len(expected)) == expected
