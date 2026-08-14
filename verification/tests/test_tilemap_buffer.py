from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
    REGISTERS,
    assembly_registers,
    native_registers,
    store_native_registers,
    symbolic_registers,
)
from verification.harness.rom import linked_bytes, rom_window, symbol_location

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification" / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
DONE = 0xEFFF
HRAM = 0xFFBA


class CopyDataInline(angr.SimProcedure):
    """Model a `call CopyData`: copy BC bytes from [HL] to [DE] in real memory."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next = next_address

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
        # Z flag set in Z80 layout (bit 6); the harness remaps it to SM83 Z.
        state.regs.f = claripy.BVV(0x40, 8)
        self.jump(self._next)


class DisableBGInline(angr.SimProcedure):
    """Model `call LoadScreenTilesFromBuffer2DisableBGTransfer` for the
    LoadScreenTilesFromBuffer2 wrapper: disable auto BG transfer, set the
    HL/DE/BC copy parameters, and perform the buffer transfer."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next = next_address

    def run(self) -> None:  # type: ignore[override]
        state = self.state
        state.memory.store(HRAM, claripy.BVV(0, 8))
        hl = 0xCD81
        de = 0xC3A0
        bc = 0x0168
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
        state.regs.f = claripy.BVV(0x40, 8)
        self.jump(self._next)


class StoreHRAM(angr.SimProcedure):
    """Model `ldh [hAutoBGTransferEnabled], a` (opcode E0 BA)."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(HRAM, self.state.regs.a)
        self.jump(self._next)


class JumpDone(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next = next_address

    def run(self) -> None:  # type: ignore[override]
        self.jump(self._next)


@dataclass(frozen=True)
class E:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    memory: claripy.ast.BV
    hram: Optional[claripy.ast.BV]
    constraints: tuple[claripy.ast.Bool, ...]


class Spec:
    def __init__(self, c_symbol, asm_name, src, dst, length, call_off,
                 call_is_disable, ret_off, ldh_offs, hram):
        self.c_symbol = c_symbol
        self.asm_name = asm_name
        self.src = src
        self.dst = dst
        self.length = length
        self.call_off = call_off
        self.call_is_disable = call_is_disable
        self.ret_off = ret_off
        self.ldh_offs = ldh_offs
        self.hram = hram


# (source, destination) are the CopyData HL/DE endpoints; length is SCREEN_AREA.
SPECS = [
    Spec("port_save_screen_tiles_to_buffer1", "SaveScreenTilesToBuffer1",
         0xC3A0, 0xC508, 0x168, call_off=9, call_is_disable=False,
         ret_off=None, ldh_offs=[], hram=False),
    Spec("port_save_screen_tiles_to_buffer2", "SaveScreenTilesToBuffer2",
         0xC3A0, 0xCD81, 0x168, call_off=9, call_is_disable=False,
         ret_off=12, ldh_offs=[], hram=False),
    Spec("port_load_screen_tiles_from_buffer1", "LoadScreenTilesFromBuffer1",
         0xC508, 0xC3A0, 0x168, call_off=12, call_is_disable=False,
         ret_off=19, ldh_offs=[1, 17], hram=True),
    Spec("port_load_screen_tiles_from_buffer2_disable_bg_transfer",
         "LoadScreenTilesFromBuffer2DisableBGTransfer",
         0xCD81, 0xC3A0, 0x168, call_off=12, call_is_disable=False,
         ret_off=15, ldh_offs=[1], hram=True),
    Spec("port_load_screen_tiles_from_buffer2", "LoadScreenTilesFromBuffer2",
         0xCD81, 0xC3A0, 0x168, call_off=0, call_is_disable=True,
         ret_off=7, ldh_offs=[5], hram=True),
]


def assembly(spec, source):
    l = symbol_location(SYMBOLS, spec.asm_name)
    p = angr.Project(
        rom_window(ROM, l.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": l.address,
        },
    )
    q = l.address
    if spec.call_is_disable:
        p.hook(q + spec.call_off, DisableBGInline(q + spec.call_off + 3), length=3)
    else:
        # `call CopyData` continues at the instruction after the call (a `ret`
        # that forwards to DONE); `jp CopyData` has no return, so it must jump
        # straight to DONE.
        next_addr = DONE if spec.ret_off is None else q + spec.call_off + 3
        p.hook(q + spec.call_off, CopyDataInline(next_addr), length=3)
    if spec.ret_off is not None:
        p.hook(q + spec.ret_off, JumpDone(DONE), length=1)
    for off in spec.ldh_offs:
        p.hook(q + off, StoreHRAM(q + off + 2), length=2)
    s = p.factory.blank_state(addr=q)
    s.regs.sp = claripy.BVV(0x200, 16)
    s.memory.store(spec.src, claripy.Concat(*source))
    s.memory.store(spec.dst, claripy.BVV(0, 8 * spec.length))
    m = p.factory.simulation_manager(s)
    m.explore(find=DONE)
    assert len(m.found) == 1
    x = m.found[0]
    return E(
        **assembly_registers(x),
        memory=x.memory.load(spec.dst, spec.length),
        hram=x.memory.load(HRAM, 1) if spec.hram else None,
        constraints=tuple(x.solver.constraints),
    )


def native(spec, source):
    p = angr.Project(NATIVE_ELF, auto_load_libs=False)
    fn = p.loader.find_symbol(spec.c_symbol)
    assert fn
    s = p.factory.call_state(fn.rebased_addr, NATIVE_STATE, claripy.BVV(0, 64))
    i = symbolic_registers(spec.c_symbol)
    store_native_registers(s, NATIVE_STATE, i)
    s.memory.store(spec.src, claripy.Concat(*source))
    s.memory.store(spec.dst, claripy.BVV(0, 8 * spec.length))
    m = p.factory.simulation_manager(s)
    m.run()
    assert not m.errored
    for x in m.deadended:
        yield E(
            **native_registers(x, NATIVE_STATE),
            memory=x.memory.load(spec.dst, spec.length),
            hram=x.memory.load(HRAM, 1) if spec.hram else None,
            constraints=tuple(x.solver.constraints),
        )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native")
@pytest.mark.parametrize("spec", SPECS, ids=lambda s: s.asm_name)
def test_tilemap_buffer(spec):
    prefix = f"tilemap_{spec.asm_name}"
    source = [claripy.BVS(f"{prefix}_src{i}", 8) for i in range(spec.length)]
    a = assembly(spec, source)
    n = list(native(spec, source))
    obs = list(REGISTERS) + ["memory"]
    if spec.hram:
        obs.append("hram")
    assert_pathwise_equivalent([a], n, obs)


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native")
@pytest.mark.parametrize("spec", SPECS, ids=lambda s: s.asm_name)
def test_exact_body(spec):
    l = symbol_location(SYMBOLS, spec.asm_name)
    expected = {
        "SaveScreenTilesToBuffer1": "21a0c31108c5016801c3b500",
        "SaveScreenTilesToBuffer2": "21a0c31181cd016801cdb500c9",
        "LoadScreenTilesFromBuffer1": "afe0ba2108c511a0c3016801cdb5003e01e0bac9",
        "LoadScreenTilesFromBuffer2DisableBGTransfer": "afe0ba2181cd11a0c3016801cdb500c9",
        "LoadScreenTilesFromBuffer2": "cd09373e01e0bac9",
    }[spec.asm_name]
    assert linked_bytes(ROM, l, len(expected) // 2) == bytes.fromhex(expected)
