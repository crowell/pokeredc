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
from verification.harness.rom import linked_bytes, rom_window, symbol_location

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification" / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
DONE = 0xEFFF


class CopyDataInline(angr.SimProcedure):
    """Model the `call CopyData` in InGameTrade_CopyData.

    The wrapper cannot run CopyData directly (it lives in the home bank, which is
    not in this bank's window), so we inline its effect: copy BC bytes from the
    real source buffer at [HL] into the real destination buffer at [DE]. This is
    the same observable behaviour the native port delegates to port_copy_data.
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
        state.regs.b = claripy.BVV((bc >> 8) & 0xFF, 8)
        state.regs.c = claripy.BVV(bc & 0xFF, 8)
        state.regs.a = claripy.BVV(0, 8)
        # Z flag set in Z80 layout (bit 6); the harness remaps it to SM83 Z.
        state.regs.f = claripy.BVV(0x40, 8)
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
    constraints: tuple[claripy.ast.Bool, ...]


def assembly(i, source, src, dst, length):
    l = symbol_location(SYMBOLS, "InGameTrade_CopyData")
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
    # e5 c5 cd b5 00 c1 e1 c9  -> push hl; push bc; call CopyData; pop bc; pop hl; ret
    call_addr = q + 2
    pop_bc_addr = q + 5
    ret_addr = q + 7
    p.hook(call_addr, CopyDataInline(pop_bc_addr), length=3)
    p.hook(ret_addr, JumpDone(DONE), length=1)
    s = p.factory.blank_state(addr=q)
    set_assembly_registers(s, i)
    s.regs.sp = claripy.BVV(0x200, 16)
    # Source buffer holds the symbolic bytes; destination is initialised to zero
    # so a port that fails to perform the copy is caught by the equivalence.
    s.memory.store(src, claripy.Concat(*source))
    s.memory.store(dst, claripy.BVV(0, 8 * length))
    m = p.factory.simulation_manager(s)
    m.explore(find=DONE)
    assert len(m.found) == 1
    x = m.found[0]
    return E(
        **assembly_registers(x),
        memory=x.memory.load(dst, length),
        constraints=tuple(x.solver.constraints),
    )


def native(i, source, src, dst, length):
    p = angr.Project(NATIVE_ELF, auto_load_libs=False)
    fn = p.loader.find_symbol("port_in_game_trade_copy_data")
    assert fn
    s = p.factory.call_state(fn.rebased_addr, NATIVE_STATE, claripy.BVV(0, 64))
    store_native_registers(s, NATIVE_STATE, i)
    s.memory.store(src, claripy.Concat(*source))
    s.memory.store(dst, claripy.BVV(0, 8 * length))
    m = p.factory.simulation_manager(s)
    m.run()
    assert not m.errored
    return [
        E(
            **native_registers(x, NATIVE_STATE),
            memory=x.memory.load(dst, length),
            constraints=tuple(x.solver.constraints),
        )
        for x in m.deadended
    ]


# (source address, destination address, length) cases. The source bytes are
# symbolic so the proof covers every possible buffer contents; only the
# addresses and length are fixed because the loop count must be concrete.
CASES = [
    (0xC000, 0xC100, 4),
    (0xC200, 0xC300, 8),
    (0xC000, 0xC400, 3),
]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native")
@pytest.mark.parametrize("src,dst,length", CASES)
def test_copy_data_buffer(src, dst, length):
    prefix = f"igtcd_{src:x}_{dst:x}_{length}"
    source = [claripy.BVS(f"{prefix}_src{i}", 8) for i in range(length)]
    i = symbolic_registers(prefix)
    i["h"] = claripy.BVV(src >> 8, 8)
    i["l"] = claripy.BVV(src & 0xFF, 8)
    i["d"] = claripy.BVV(dst >> 8, 8)
    i["e"] = claripy.BVV(dst & 0xFF, 8)
    i["b"] = claripy.BVV(length >> 8, 8)
    i["c"] = claripy.BVV(length & 0xFF, 8)
    a = assembly(i, source, src, dst, length)
    n = native(i, source, src, dst, length)
    assert_pathwise_equivalent([a], n, (*REGISTERS, "memory"))


def test_exact_body():
    l = symbol_location(SYMBOLS, "InGameTrade_CopyData")
    assert linked_bytes(ROM, l, 8) == bytes.fromhex("e5c5cdb500c1e1c9")
