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
    symbol_location,
)


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification" / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
GB_STACK = 0xD000
GB_RETURN = 0xFFFF
NATIVE_STATE = 0x100000
LEN = 8
SPRITE36 = 0xC390
BUFFER = 0xCEE9
SPRITE38 = 0xC398


class CopyDataSim(angr.SimProcedure):
    """Model `call CopyData` / `jp CopyData` in AnimCutGrass_SwapOAMEntries.

    CopyData is in the home bank (not this routine's bank), so we inline its
    effect: copy BC bytes from the real source buffer at [HL] into the real
    destination buffer at [DE] (absolute addresses in the flat memory), then
    advance HL/DE/BC to zero and leave A=0 with Z set, mirroring port_copy_data.
    """

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
    sprite36: claripy.ast.BV
    buf: claripy.ast.BV
    sprite38: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _assembly_endpoint(
    inputs: dict[str, claripy.ast.BV],
    sprite36: list[claripy.ast.BV],
    buf: list[claripy.ast.BV],
    sprite38: list[claripy.ast.BV],
) -> Endpoint:
    location = symbol_location(SYMBOLS, "AnimCutGrass_SwapOAMEntries")
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
    # The body is three (ld hl,imm; ld de,imm; ld bc,imm; call/jp CopyData)
    # blocks of 12 bytes each. The two `call CopyData` sites are at +9 and +21,
    # and the tail `jp CopyData` is at +33 (CopyData is at 0x00b5, in bank 0).
    project.hook(location.address + 9, CopyDataSim(location.address + 12), length=3)
    project.hook(location.address + 21, CopyDataSim(location.address + 24), length=3)
    project.hook(location.address + 33, CopyDataSim(GB_RETURN), length=3)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    state.regs.sp = claripy.BVV(GB_STACK, 16)
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    state.memory.store(SPRITE36, claripy.Concat(*sprite36))
    state.memory.store(BUFFER, claripy.Concat(*buf))
    state.memory.store(SPRITE38, claripy.Concat(*sprite38))
    returned = collect_returns(project, state, GB_RETURN)
    assert len(returned) == 1
    end = returned[0]
    return Endpoint(
        **assembly_registers(end),
        sprite36=end.memory.load(SPRITE36, LEN),
        buf=end.memory.load(BUFFER, LEN),
        sprite38=end.memory.load(SPRITE38, LEN),
        constraints=tuple(end.solver.constraints),
    )


def _native_endpoint(
    inputs: dict[str, claripy.ast.BV],
    sprite36: list[claripy.ast.BV],
    buf: list[claripy.ast.BV],
    sprite38: list[claripy.ast.BV],
) -> Endpoint:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_anim_cut_grass_swap_oam_entries")
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, claripy.BVV(0, 64)
    )
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(SPRITE36, claripy.Concat(*sprite36))
    state.memory.store(BUFFER, claripy.Concat(*buf))
    state.memory.store(SPRITE38, claripy.Concat(*sprite38))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    end = manager.deadended[0]
    return Endpoint(
        **native_registers(end, NATIVE_STATE),
        sprite36=end.memory.load(SPRITE36, LEN),
        buf=end.memory.load(BUFFER, LEN),
        sprite38=end.memory.load(SPRITE38, LEN),
        constraints=tuple(end.solver.constraints),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_anim_cut_grass_swap_oam_entries_symbolic_equivalence() -> None:
    prefix = "acg"
    inputs = symbolic_registers(prefix)
    sprite36 = [claripy.BVS(f"{prefix}_s36_{i}", 8) for i in range(LEN)]
    buf = [claripy.BVS(f"{prefix}_buf_{i}", 8) for i in range(LEN)]
    sprite38 = [claripy.BVS(f"{prefix}_s38_{i}", 8) for i in range(LEN)]
    assembly = _assembly_endpoint(inputs, sprite36, buf, sprite38)
    native = _native_endpoint(inputs, sprite36, buf, sprite38)
    assert_pathwise_equivalent(
        [assembly],
        [native],
        (*REGISTERS, "sprite36", "buf", "sprite38"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_anim_cut_grass_swap_oam_entries_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "AnimCutGrass_SwapOAMEntries")
    # ld hl,wShadowOAMSprite36; ld de,wBuffer; ld bc,8; call CopyData;
    # ld hl,wShadowOAMSprite38; ld de,wShadowOAMSprite36; ld bc,8; call CopyData;
    # ld hl,wBuffer; ld de,wShadowOAMSprite38; ld bc,8; jp CopyData.
    expected = bytes.fromhex(
        "2190c311e9ce010800cdb5002198c31190c3010800cdb50021e9ce1198c3010800c3b500"
    )
    assert linked_bytes(ROM, location, len(expected)) == expected
