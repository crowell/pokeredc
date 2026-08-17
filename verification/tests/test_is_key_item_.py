from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode
from pypcode import Context

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.rom import (
    collect_returns,
    linked_bytes,
    rom_window,
    symbol_location,
)
from verification.harness.sm83_shims import (
    Sm83CpImmediate,
    Sm83LoadAImmediate,
    Sm83StoreAImmediate,
)


ROOT = Path(__file__).resolve().parents[2]
VERIFY = ROOT / "verification"
NATIVE_ELF = VERIFY / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
GB_STACK = 0xD000
GB_RETURN = 0xFFFF
NATIVE_STATE = 0x100000

W_IS_KEY_ITEM = 0xD124
W_CUR_ITEM = 0xCF91
W_BUFFER = 0xCEE9
KEY_ITEM_FLAGS = 0x6799
ITEM = claripy.BVS("ik_item", 8)
KIF = [claripy.BVS(f"ik_kif{j}", 8) for j in range(15)]
HM01 = 0xC4
TM01 = 0xC9


@dataclass(frozen=True)
class Endpoint:
    wisi: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class CopyDataSim(angr.SimProcedure):
    """Model `call CopyData` (bc=15): copy 15 bytes KeyItemFlags -> wBuffer."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next = next_address

    def run(self) -> None:  # type: ignore[override]
        st = self.state
        hl = (int(st.solver.eval(st.regs.h)) << 8) | int(st.solver.eval(st.regs.l))
        de = (int(st.solver.eval(st.regs.d)) << 8) | int(st.solver.eval(st.regs.e))
        bc = (int(st.solver.eval(st.regs.b)) << 8) | int(st.solver.eval(st.regs.c))
        for _ in range(bc):
            byte = st.memory.load(hl, 1)
            st.memory.store(de, byte)
            hl = (hl + 1) & 0xFFFF
            de = (de + 1) & 0xFFFF
        st.regs.h = claripy.BVV((hl >> 8) & 0xFF, 8)
        st.regs.l = claripy.BVV(hl & 0xFF, 8)
        st.regs.d = claripy.BVV((de >> 8) & 0xFF, 8)
        st.regs.e = claripy.BVV(de & 0xFF, 8)
        st.regs.b = claripy.BVV(0, 8)
        st.regs.c = claripy.BVV(0, 8)
        st.regs.a = claripy.BVV(0, 8)
        st.regs.f = claripy.BVV(0x40, 8)  # Z set
        self.jump(self._next)


class FlagActionSim(angr.SimProcedure):
    """Model `predef FlagActionPredef` (FLAG_TEST on bit c in wBuffer).

    The original FlagAction reads the flag bit and stores its value (0 or 1)
    back in register C. We rebuild the selected byte from the concrete
    wBuffer addresses with an explicit ITE: a symbolic-address memory.load
    produces a malformed, off-by-one ITE that collapses the bit to zero.
    """

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next = next_address

    def run(self) -> None:  # type: ignore[override]
        st = self.state
        c = st.regs.c  # bit index = item - 1
        idx = claripy.LShR(c, 3)
        sel = claripy.BVV(0, 8)
        for j in range(15):
            bj = st.memory.load(W_BUFFER + j, 1)
            sel = claripy.If(idx == j, bj, sel)
        bitpos = c & 7
        bit = claripy.BVV(0, 8)
        for k in range(8):
            bit = claripy.If(bitpos == k, sel & (1 << k), bit)
        c_val = claripy.If(bit == 0, claripy.BVV(0, 8), claripy.BVV(1, 8))
        st.regs.c = c_val
        st.regs.f = claripy.If(c_val == 0, claripy.BVV(0x40, 8), claripy.BVV(0x00, 8))
        self.jump(self._next)


class IsItemHMSim(angr.SimProcedure):
    """Model `call IsItemHM`: carry iff HM01 <= a < TM01."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next = next_address

    def run(self) -> None:  # type: ignore[override]
        st = self.state
        a = st.regs.a
        carry = claripy.And(a >= HM01, a < TM01)
        st.regs.f = claripy.If(carry, claripy.BVV(0x01, 8), claripy.BVV(0x00, 8))
        self.jump(self._next)


class _Fork(angr.SimProcedure):
    """Fork the path on a flag condition.

    The bundled Z80 SLEIGH does not fork JR NC / RET NZ / RET C. The guard is
    the 3rd positional arg of SimSuccessors.add_successor; inhibit_autoret
    avoids the empty-call-frame ret() that angr would otherwise emit. The guard
    is also recorded as a state constraint so pathwise equivalence can pair
    terminal paths correctly.
    """

    def __init__(self, taken: int, fallthrough: int, bit: int, invert: bool) -> None:
        super().__init__()
        self._taken = taken
        self._fall = fallthrough
        self._bit = bit
        self._invert = invert

    def _fork(self, taken_ip: int, taken_sp: int | None) -> None:
        self.inhibit_autoret = True
        f = self.state.regs.f
        flag_bit = (f >> self._bit) & 1
        cond = (flag_bit == 0) if self._invert else (flag_bit == 1)
        ts = self.state.copy()
        fs = self.state.copy()
        ts.solver.add(cond)
        fs.solver.add(claripy.Not(cond))
        ts.regs.ip = claripy.BVV(taken_ip, 16)
        fs.regs.ip = claripy.BVV(self._fall, 16)
        if taken_sp is not None:
            ts.regs.sp = claripy.BVV(taken_sp, 16)
        self.successors.add_successor(ts, taken_ip, cond, "Ijk_Boring")
        self.successors.add_successor(fs, self._fall, claripy.Not(cond), "Ijk_Boring")

    def run(self) -> None:  # type: ignore[override]
        self._fork(self._taken, None)


class ForkJR(_Fork):
    """Conditional relative jump: taken/fallthrough are absolute targets."""


class ForkRet(_Fork):
    """Conditional return: taken target is the GB return sentinel."""

    def __init__(self, fallthrough: int, bit: int, invert: bool) -> None:
        super().__init__(GB_RETURN, fallthrough, bit, invert)

    def run(self) -> None:  # type: ignore[override]
        self._fork(GB_RETURN, GB_STACK + 2)


class DoRet(angr.SimProcedure):
    """Unconditional return: jump to the GB return sentinel."""

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.state.regs.sp = claripy.BVV(GB_STACK + 2, 16)
        self.jump(GB_RETURN)


def _inputs() -> tuple[claripy.ast.BV, list[claripy.ast.BV]]:
    # Shared symbolic inputs: both endpoints must reference the *same* BVS
    # objects (module-level ITEM/KIF) so the equivalence solver treats item
    # and kif as a single variable across assembly and native.
    return ITEM, KIF


def _assembly_endpoints() -> list[Endpoint]:
    item, kif = _inputs()
    location = symbol_location(SYMBOLS, "IsKeyItem_")
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
    project.hook(location.address + 22, CopyDataSim(location.address + 25), length=3)
    project.hook(location.address + 35, FlagActionSim(location.address + 38), length=3)
    project.hook(location.address + 44, IsItemHMSim(location.address + 47), length=3)
    # The bundled Z80 SLEIGH computes SM83 flags incorrectly; fix CP here so the
    # subsequent JR NC forks correctly.
    project.hook(
        location.address + 8,
        Sm83CpImmediate(immediate=0xC4, next_address=location.address + 10),
        length=2,
    )
    # The bundled Z80 SLEIGH does not fork JR NC / RET NZ / RET C.
    project.hook(
        location.address + 10,
        ForkJR(location.address + 41, location.address + 12, 0, True),
        length=2,
    )
    project.hook(
        location.address + 40,
        ForkRet(location.address + 41, 6, True),
        length=1,
    )
    project.hook(
        location.address + 47,
        ForkRet(location.address + 48, 0, False),
        length=1,
    )
    project.hook(location.address + 52, DoRet(), length=1)
    # LR35902 bytes the Z80 SLEIGH mis-decodes as JP PE/JP M.
    project.hook(
        location.address + 2,
        Sm83StoreAImmediate(W_IS_KEY_ITEM, location.address + 5),
        length=3,
    )
    project.hook(
        location.address + 5,
        Sm83LoadAImmediate(W_CUR_ITEM, location.address + 8),
        length=3,
    )
    project.hook(
        location.address + 41,
        Sm83LoadAImmediate(W_CUR_ITEM, location.address + 44),
        length=3,
    )
    project.hook(
        location.address + 49,
        Sm83StoreAImmediate(W_IS_KEY_ITEM, location.address + 52),
        length=3,
    )
    state = project.factory.blank_state(addr=location.address)
    # Cover both branches: the key-item table (1..120) and the HM range
    # (0xC4..0xFF). The middle 121..0xC3 would read past the 15-byte table.
    state.solver.add(item >= 1)
    state.solver.add(claripy.Or(item <= 120, item >= 0xC4))
    state.memory.store(W_CUR_ITEM, item)
    for j in range(15):
        state.memory.store(KEY_ITEM_FLAGS + j, kif[j])
    state.regs.sp = claripy.BVV(GB_STACK, 16)
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    return [
        Endpoint(
            wisi=end.memory.load(W_IS_KEY_ITEM, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in returned
    ]


def _native_endpoints() -> list[Endpoint]:
    item, kif = _inputs()
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    fn = project.loader.find_symbol("port_is_key_item_")
    assert fn is not None
    state = project.factory.call_state(
        fn.rebased_addr, NATIVE_STATE, claripy.BVV(0, 64)
    )
    state.solver.add(item >= 1)
    state.solver.add(claripy.Or(item <= 120, item >= 0xC4))
    state.memory.store(W_CUR_ITEM, item)
    for j in range(15):
        state.memory.store(KEY_ITEM_FLAGS + j, kif[j])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            wisi=end.memory.load(W_IS_KEY_ITEM, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_is_key_item__symbolic_equivalence() -> None:
    assert_pathwise_equivalent(
        _assembly_endpoints(), _native_endpoints(), ("wisi",)
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_is_key_item__uses_z80_compatible_instruction_encodings() -> None:
    location = symbol_location(SYMBOLS, "IsKeyItem_")
    instructions = Context("z80:LE:16:default").disassemble(
        linked_bytes(ROM, location, 48), location.address
    ).instructions
    body = [(item.mnem, item.body, item.length) for item in instructions]
    assert ("CALL", "0xb5", 3) in body  # CopyData
    assert ("CALL", "0x3e6d", 3) in body  # Predef (FlagActionPredef)
    assert ("CALL", "0x3040", 3) in body  # IsItemHM
