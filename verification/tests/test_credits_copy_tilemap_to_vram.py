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
from verification.harness.rom import linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import (
    Sm83LoadAFromImmediate,
    Sm83StoreAHighImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
DONE = 0xEFFF

H_AUTO_BG_TRANSFER_DEST = 0xFFBC
H_AUTO_BG_TRANSFER_ENABLED = 0xFFBA

# CreditsCopyTileMapToVRAM: 7d e0bc 7c e0bd 3e01 e0ba c3d73d
#   ld a,l / ldh [hAutoBGTransferDest],a / ld a,h / ldh [hAutoBGTransferDest+1],a
#   / ld a,1 / ldh [hAutoBGTransferEnabled],a / jp Delay3


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
    h_auto_bg_transfer_dest: claripy.ast.BV
    h_auto_bg_transfer_dest_hi: claripy.ast.BV
    h_auto_bg_transfer_enabled: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class Boundary(angr.SimProcedure):
    """The `jp Delay3` tail: an explicit boundary sentinel."""

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.jump(DONE)


def _inputs(tag: str) -> dict:
    return symbolic_registers(tag)


def _assembly(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "CreditsCopyTileMapToVRAM")
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
    # The three SM83 `ldh [a8], a` stores (opcode E0) are absent from the Z80,
    # and `ld a, n` (opcode 3E) is shimmed to clear all flags as SM83 requires.
    # Bytes: 7d e0bc 7c e0bd 3e01 e0ba c3d73d
    project.hook(base + 0x01, Sm83StoreAHighImmediate(0xBC, base + 0x03), length=2)
    project.hook(base + 0x04, Sm83StoreAHighImmediate(0xBD, base + 0x06), length=2)
    project.hook(base + 0x06, Sm83LoadAFromImmediate(base + 0x07, base + 0x08), length=2)
    project.hook(base + 0x08, Sm83StoreAHighImmediate(0xBA, base + 0x0A), length=2)
    # `jp Delay3` is a frame wait and is an explicit boundary.
    project.hook(base + 0x0A, Boundary(), length=3)
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
            h_auto_bg_transfer_dest=end.memory.load(H_AUTO_BG_TRANSFER_DEST, 1),
            h_auto_bg_transfer_dest_hi=end.memory.load(H_AUTO_BG_TRANSFER_DEST + 1, 1),
            h_auto_bg_transfer_enabled=end.memory.load(H_AUTO_BG_TRANSFER_ENABLED, 1),
            constraints=tuple(end.solver.constraints),
        )
    ]


def _native(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_credits_copy_tilemap_to_vram")
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
            h_auto_bg_transfer_dest=end.memory.load(H_AUTO_BG_TRANSFER_DEST, 1),
            h_auto_bg_transfer_dest_hi=end.memory.load(H_AUTO_BG_TRANSFER_DEST + 1, 1),
            h_auto_bg_transfer_enabled=end.memory.load(H_AUTO_BG_TRANSFER_ENABLED, 1),
            constraints=tuple(end.solver.constraints),
        )
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_credits_copy_tilemap_to_vram_symbolic_equivalence() -> None:
    i = _inputs("cct")
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
            "h_auto_bg_transfer_dest",
            "h_auto_bg_transfer_dest_hi",
            "h_auto_bg_transfer_enabled",
        ),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_credits_copy_tilemap_to_vram_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "CreditsCopyTileMapToVRAM")
    # Six instructions (ld a,l / ldh [dest],a / ld a,h / ldh [dest+1],a /
    # ld a,1 / ldh [hAutoBGTransferEnabled],a) followed by `jp Delay3` (c3 d7 3d).
    assert linked_bytes(ROM, location, 13) == bytes.fromhex(
        "7de0bc7ce0bd3e01e0bac3d73d"
    )
