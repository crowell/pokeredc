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
from verification.harness.rom import rom_window, symbol_location
from verification.harness.sm83_shims import Sm83DecRegister, Sm83StoreAHighImmediate

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
DONE = 0xEFFF

H_AUTO_BG_TRANSFER_DEST_HI = 0xFFBD

# TitleScreenCopyTileMapToVRAM: e0bd c3d73d
#   ldh [hAutoBGTransferDest + 1], a / jp Delay3


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
    h_auto_bg_transfer_dest_hi: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class DelayFrameTerminal(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x50, 8)
        self.jump(self.next_address)


class ReturnBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(DONE)


def _inputs(tag: str) -> dict:
    return symbolic_registers(tag)


def _assembly(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "TitleScreenCopyTileMapToVRAM")
    base = location.address
    delay_frames = symbol_location(SYMBOLS, "DelayFrames").address
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
    # `ldh [a8], a` (opcode E0) is absent from the Z80.
    # Bytes: e0bd c3d73d
    project.hook(base + 0x00, Sm83StoreAHighImmediate(0xBD, base + 0x02), length=2)
    project.hook(
        delay_frames,
        DelayFrameTerminal(delay_frames + 3),
        length=3,
    )
    project.hook(
        delay_frames + 3,
        Sm83DecRegister("c", delay_frames + 4),
        length=1,
    )
    project.hook(delay_frames + 6, ReturnBoundary(), length=1)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, inputs)
    state.regs.sp = 0xD000
    state.memory.store(0xD000, claripy.BVV(0xFFFF, 16), endness="Iend_LE")
    m = project.factory.simulation_manager(state)
    m.explore(find=DONE, num_find=1)
    assert len(m.found) == 1
    end = m.found[0]
    return [
        Endpoint(
            **assembly_registers(end),
            h_auto_bg_transfer_dest_hi=end.memory.load(H_AUTO_BG_TRANSFER_DEST_HI, 1),
            constraints=tuple(end.solver.constraints),
        )
    ]


def _native(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(
        "port_title_screen_copy_tilemap_to_vram"
    )
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, claripy.BVV(0, 64)
    )
    store_native_registers(state, NATIVE_STATE, inputs)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    end = manager.deadended[0]
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            h_auto_bg_transfer_dest_hi=end.memory.load(H_AUTO_BG_TRANSFER_DEST_HI, 1),
            constraints=tuple(end.solver.constraints),
        )
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_title_screen_copy_tilemap_to_vram_symbolic_equivalence() -> None:
    i = _inputs("tct")
    assert_pathwise_equivalent(
        _assembly(i),
        _native(i),
        (
            "a",
            "f",
            "b",
            "c",
            "d",
            "e",
            "h",
            "l",
            "h_auto_bg_transfer_dest_hi",
        ),
    )
