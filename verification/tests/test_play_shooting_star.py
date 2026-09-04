"""Proof for PlayShootingStar's linked orchestration path."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
    assembly_registers,
    native_registers,
    set_assembly_registers,
    store_native_registers,
    symbolic_registers,
)
from verification.harness.rom import collect_returns, linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import (
    Sm83LoadAFromImmediate,
    Sm83ResAtHl,
    Sm83SetAtHl,
    Sm83StoreAHighImmediate,
    Sm83StoreAImmediate,
)
ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF
R_BGP = 0xFF47
R_LCDC = 0xFF40
W_CUR_OPPONENT = 0xD059
W_NEW_SOUND_ID = 0xC0EE
W_AUDIO_ROM_BANK = 0xC0EF
W_AUDIO_SAVED_ROM_BANK = 0xC0F0
H_LOADED_ROM_BANK = 0xFFB8
R_ROMB = 0x2000
W_SHADOW_OAM = 0xC300
H_JOY_HELD = 0xFFB4
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


def _memory_endpoint(state: angr.SimState, base: int) -> claripy.ast.BV:
    addresses = (
        R_BGP,
        R_LCDC,
        W_CUR_OPPONENT,
        W_NEW_SOUND_ID,
        W_AUDIO_ROM_BANK,
        W_AUDIO_SAVED_ROM_BANK,
        H_LOADED_ROM_BANK,
        R_ROMB,
        H_JOY_HELD,
    )
    chunks = [state.memory.load(base + address, 1) for address in addresses]
    chunks.append(state.memory.load(base + W_SHADOW_OAM, 160))
    return claripy.Concat(*chunks)


def _endpoint(state: angr.SimState, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    return Endpoint(
        **(native_registers(state, NATIVE_STATE) if native else assembly_registers(state)),
        memory=_memory_endpoint(state, base),
        constraints=tuple(state.solver.constraints),
    )


class Boundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(self.addr + 3)


class AnimateInterrupted(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.f = claripy.BVV(0x01, 8)
        self.jump(self.addr + 3)


class EnableLCD(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(R_LCDC, self.state.memory.load(R_LCDC, 1) | 0x80)
        self.jump(self.addr + 3)


class PlaySound(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(W_NEW_SOUND_ID, claripy.BVV(0, 8))
        self.jump(self.addr + 3)


class ClearSprites(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(W_SHADOW_OAM, claripy.BVV(0, 160 * 8))
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x42, 8)
        self.state.regs.b = claripy.BVV(0, 8)
        self.state.regs.c = claripy.BVV(0, 8)
        self.state.regs.d = claripy.BVV(0xC3, 8)
        self.state.regs.e = claripy.BVV(0x10, 8)
        self.state.regs.h = claripy.BVV(0xC3, 8)
        self.state.regs.l = claripy.BVV(0xA0, 8)
        self.jump(self.addr + 3)


class Delay3(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.f = claripy.BVV(0x42, 8)
        self.jump(DONE)
def _assembly(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "PlayShootingStar")
    expected = bytes.fromhex(
        "060ccdef3d0601213845cdd6353ee4e0470eb4cd3937cd0f19cd6100afea59d0cde958cd5258cd7b002140ffcbaecbde0e40cd3937061c214440cdd635f5f138050e28cd39373e1feaefc0eaf0c03edceaeec0cdb123cdf857cd8200c3d73dcd"
    )
    assert linked_bytes(ROM, location, len(expected)) == expected
    base = location.address
    project = angr.Project(
        rom_window(ROM, location.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": base,
        },
    )
    for offset in (0x02, 0x0A, 0x13, 0x16, 0x19, 0x21, 0x24, 0x33):
        project.hook(base + offset, Boundary(), length=3)
    project.hook(base + 0x0D, Sm83LoadAFromImmediate(base + 0x0E, base + 0x0F), length=2)
    project.hook(base + 0x0F, Sm83StoreAHighImmediate(0x47, base + 0x11), length=2)
    project.hook(base + 0x26, EnableLCD(), length=3)
    project.hook(base + 0x3A, AnimateInterrupted(), length=3)
    project.hook(base + 0x46, Sm83LoadAFromImmediate(base + 0x47, base + 0x48), length=2)
    project.hook(base + 0x4E, Sm83LoadAFromImmediate(base + 0x4F, base + 0x50), length=2)
    project.hook(base + 0x1D, Sm83StoreAImmediate(W_CUR_OPPONENT, base + 0x20), length=3)
    project.hook(base + 0x2C, Sm83ResAtHl(5, base + 0x2E), length=2)
    project.hook(base + 0x2E, Sm83SetAtHl(3, base + 0x30), length=2)
    project.hook(base + 0x48, Sm83StoreAImmediate(W_AUDIO_ROM_BANK, base + 0x4B), length=3)
    project.hook(base + 0x4B, Sm83StoreAImmediate(W_AUDIO_SAVED_ROM_BANK, base + 0x4E), length=3)
    project.hook(base + 0x51, Sm83StoreAImmediate(W_NEW_SOUND_ID, base + 0x54), length=3)
    project.hook(base + 0x53, PlaySound(), length=3)
    project.hook(base + 0x57, Boundary(), length=3)
    project.hook(base + 0x59, ClearSprites(), length=3)
    project.hook(base + 0x5C, Delay3(), length=3)

    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, inputs)
    for address in (
        R_BGP, R_LCDC, W_CUR_OPPONENT, W_NEW_SOUND_ID,
        W_AUDIO_ROM_BANK, W_AUDIO_SAVED_ROM_BANK, H_LOADED_ROM_BANK, R_ROMB,
    ):
        state.memory.store(address, claripy.BVV(0, 8))
    state.memory.store(W_SHADOW_OAM, claripy.BVV(0, 160 * 8))
    state.memory.store(0xD000, claripy.BVV(DONE, 16), endness="Iend_LE")
    state.memory.store(H_JOY_HELD, claripy.BVV(0x46, 8))
    state.regs.sp = claripy.BVV(0xD000, 16)
    returned = collect_returns(project, state, DONE)
    return [_endpoint(end, native=False) for end in returned]


def _native(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_play_shooting_star")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_MEMORY, claripy.BVV(0, 65536 * 8))
    state.memory.store(NATIVE_MEMORY + H_JOY_HELD, claripy.BVV(0x46, 8))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    return [_endpoint(manager.deadended[0], native=True)]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_play_shooting_star_interrupted_pathwise_equivalence() -> None:
    inputs = symbolic_registers("play_shooting_star")
    assert_pathwise_equivalent(
        _assembly(inputs),
        _native(inputs),
        ("a", "f", "b", "c", "d", "e", "h", "l", "memory"),
    )
