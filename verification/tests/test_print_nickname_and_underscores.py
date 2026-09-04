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
from verification.harness.sm83_shims import (
    Sm83AddHlRegisterPair,
    Sm83AndRegister,
    Sm83BitRegister,
    Sm83CpImmediate,
    Sm83DecRegister,
    Sm83IncRegister,
    Sm83LoadAImmediate,
    Sm83StoreAAtHlIncrement,
    Sm83StoreAImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xFFFF

W_NAME_ROW = 0xC3D2
W_US_ROW = 0xC3E6
W_TOP_X = 0xCC25
W_CUR_ITEM = 0xCC26
W_CURSOR = 0xCC30
CURSOR_TARGET = 0xC400
W_NAME_LEN = 0xCEE9
W_STRBUF = 0xCF4B
W_TYPE = 0xD07D
W_STATUS5 = 0xD730

B = 0x680E  # PrintNicknameAndUnderscores
S = 0x18C4  # ClearScreenArea
C = 0x68EB  # CalcStringLength
P = 0x1955  # PlaceString
L = 0x38D3  # PrintLetterDelay

EXPECTED_BODY = bytes.fromhex(
    "cdeb6879eae9ce21d2c3010a01cdc41821d2c3114bcfcd551921e6c3"
    "fa7dd0fe02300406071802060a3e76220520fcfa7dd0fe02fae9ce30"
    "04fe071802fe0a2018cdf93b3e11ea25cc3e05ea26ccfa7dd0fe023e"
    "0930023e064f060021e6c3093677c9"
)

# (label, naming-screen type, name letters before the '@' terminator).
# Types 0/1 take the 7-underscore player/rival branch; 2 (and anything
# above) takes the 10-underscore mon branch.
CASES = (
    ("player-partial", 0, (0x80, 0x81, 0x82)),
    ("player-full", 0, (0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86)),
    ("rival-partial", 1, (0x90, 0x91)),
    ("mon-partial", 2, (0x80, 0x81, 0x82, 0x83, 0x84)),
    (
        "mon-full",
        2,
        (0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89),
    ),
    ("mon-empty", 2, ()),
    ("high-type-partial", 3, (0x80, 0x81, 0x82, 0x83)),
)

DICT_IMMS = (
    0x4C, 0x4B, 0x51, 0x49, 0x52, 0x53, 0x54, 0x5B, 0x5E, 0x5C, 0x5D,
    0x55, 0x56, 0x57, 0x58, 0x4A, 0x5F, 0x59, 0x5A,
)


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
    name_len: claripy.ast.BV
    name_row: claripy.ast.BV
    us_row: claripy.ast.BV
    top_x: claripy.ast.BV
    cur_item: claripy.ast.BV
    cursor_target: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class PushPair(angr.SimProcedure):
    """Exact SM83 ``PUSH rr``: stack grows down, low byte lands at [SP]."""

    def __init__(self, high: str, low: str, nxt: int) -> None:
        super().__init__()
        self._high, self._low, self._nxt = high, low, nxt

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.sp = self.state.regs.sp - 2
        self.state.memory.store(
            self.state.regs.sp, getattr(self.state.regs, self._low))
        self.state.memory.store(
            self.state.regs.sp + 1, getattr(self.state.regs, self._high))
        self.jump(self._nxt)


class PopPair(angr.SimProcedure):
    """Exact SM83 ``POP rr``."""

    def __init__(self, high: str, low: str, nxt: int) -> None:
        super().__init__()
        self._high, self._low, self._nxt = high, low, nxt

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self._low,
                self.state.memory.load(self.state.regs.sp, 1))
        setattr(self.state.regs, self._high,
                self.state.memory.load(self.state.regs.sp + 1, 1))
        self.state.regs.sp = self.state.regs.sp + 2
        self.jump(self._nxt)


class LoadAAtDe(angr.SimProcedure):
    """Exact SM83 ``LD A,[DE]`` (opcode 1A); preserves flags."""

    def __init__(self, nxt: int) -> None:
        super().__init__()
        self._nxt = nxt

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self.state.regs.de, 1)
        self.jump(self._nxt)


class RetCond(angr.SimProcedure):
    """Exact conditional ``RET Z`` (taken_if_z=True) / ``RET NZ``."""

    def __init__(self, fallthrough: int, taken_if_z: bool) -> None:
        super().__init__()
        self._fallthrough = fallthrough
        self._taken_if_z = taken_if_z

    def run(self) -> None:  # type: ignore[override]
        taken = (self.state.regs.f & 0x40) != 0
        if not self._taken_if_z:
            taken = claripy.Not(taken)
        can_take = self.state.solver.satisfiable(extra_constraints=(taken,))
        can_fall = self.state.solver.satisfiable(
            extra_constraints=(claripy.Not(taken),))
        if can_take and can_fall:
            self.inhibit_autoret = True
            cont = self.state.copy()
            self.successors.add_successor(
                cont, self._fallthrough, claripy.Not(taken), "Ijk_Boring")
            ret = self.state.copy()
            target = ret.memory.load(ret.regs.sp, 2, endness="Iend_LE")
            ret.regs.sp = ret.regs.sp + 2
            self.successors.add_successor(
                ret, ret.solver.eval(target), taken, "Ijk_Ret")
        elif can_take:
            target = self.state.memory.load(
                self.state.regs.sp, 2, endness="Iend_LE")
            self.state.regs.sp = self.state.regs.sp + 2
            self.jump(self.state.solver.eval(target))
        else:
            self.jump(self._fallthrough)


class LdImm8(angr.SimProcedure):
    """Exact flag-preserving ``LD r,n``."""

    def __init__(self, reg: str, imm: int, nxt: int) -> None:
        super().__init__()
        self._reg, self._imm, self._nxt = reg, imm, nxt

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self._reg, claripy.BVV(self._imm, 8))
        self.jump(self._nxt)


def _endpoint(state: angr.SimState, native: bool) -> Endpoint:
    fields = (native_registers(state, NATIVE_STATE) if native
              else assembly_registers(state))
    base = NATIVE_MEMORY if native else 0
    return Endpoint(
        **fields,
        name_len=state.memory.load(base + W_NAME_LEN, 1),
        name_row=state.memory.load(base + W_NAME_ROW, 10),
        us_row=state.memory.load(base + W_US_ROW, 10),
        top_x=state.memory.load(base + W_TOP_X, 1),
        cur_item=state.memory.load(base + W_CUR_ITEM, 1),
        cursor_target=state.memory.load(base + CURSOR_TARGET, 1),
        constraints=tuple(state.solver.constraints),
    )


class LdReg(angr.SimProcedure):
    """Exact flag-preserving ``LD r,r'``."""

    def __init__(self, dest: str, src: str, nxt: int) -> None:
        super().__init__()
        self._dest, self._src, self._nxt = dest, src, nxt

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self._dest,
                getattr(self.state.regs, self._src))
        self.jump(self._nxt)


class LdPair16(angr.SimProcedure):
    """Exact flag-preserving ``LD rr,nn``."""

    def __init__(self, high: str, low: str, value: int, nxt: int) -> None:
        super().__init__()
        self._high, self._low, self._value, self._nxt = high, low, value, nxt

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self._high,
                claripy.BVV(self._value >> 8, 8))
        setattr(self.state.regs, self._low,
                claripy.BVV(self._value & 0xFF, 8))
        self.jump(self._nxt)


def _is_full(ntype: int, letters: tuple[int, ...]) -> bool:
    width = 10 if ntype >= 2 else 7
    return len(letters) == width


def _inputs(prefix: str, ntype: int, letters: tuple[int, ...],
            ) -> dict[str, object]:
    values: dict[str, object] = symbolic_registers(prefix)
    values["text"] = tuple(claripy.BVV(byte, 8) for byte in (*letters, 0x50))
    values["ntype"] = claripy.BVV(ntype, 8)
    values["name_len"] = claripy.BVS(f"{prefix}_name_len", 8)
    values["name_row"] = claripy.BVS(f"{prefix}_name_row", 80)
    if ntype >= 2:
        values["us_row"] = claripy.BVS(f"{prefix}_us_row", 80)
    else:
        # The player/rival loop only paints 7 underscores; the last three
        # cells keep a fixed tile so preservation is observable too.
        values["us_row"] = claripy.Concat(
            claripy.BVS(f"{prefix}_us_row", 56),
            claripy.BVV(0x7F7F7F, 24),
        )
    if _is_full(ntype, letters):
        values["top_x"] = claripy.BVS(f"{prefix}_top_x", 8)
        values["cur_item"] = claripy.BVS(f"{prefix}_cur_item", 8)
        values["cursor_target"] = claripy.BVS(f"{prefix}_cursor_target", 8)
    else:
        values["top_x"] = claripy.BVV(0, 8)
        values["cur_item"] = claripy.BVV(0, 8)
        values["cursor_target"] = claripy.BVV(0, 8)
    return values


def _store(state: angr.SimState, values: dict[str, object], base: int = 0,
           ) -> None:
    for index, byte in enumerate(values["text"]):
        state.memory.store(base + W_STRBUF + index, byte)
    state.memory.store(base + W_TYPE, values["ntype"])
    state.memory.store(base + W_STATUS5, claripy.BVV(0x40, 8))
    state.memory.store(base + W_NAME_LEN, values["name_len"])
    state.memory.store(base + W_NAME_ROW, values["name_row"])
    state.memory.store(base + W_US_ROW, values["us_row"])
    state.memory.store(base + W_TOP_X, values["top_x"])
    state.memory.store(base + W_CUR_ITEM, values["cur_item"])
    state.memory.store(base + W_CURSOR, claripy.BVV(0x00, 8))
    state.memory.store(base + W_CURSOR + 1, claripy.BVV(0xC4, 8))
    state.memory.store(base + CURSOR_TARGET, values["cursor_target"])


def _endpoint(state: angr.SimState, native: bool,
              ptr: int | claripy.ast.BV = 0) -> Endpoint:
    fields = (native_registers(state, NATIVE_STATE) if native
              else assembly_registers(state))
    base = NATIVE_MEMORY if native else 0
    return Endpoint(
        **fields,
        name_len=state.memory.load(base + W_NAME_LEN, 1),
        name_row=state.memory.load(base + W_NAME_ROW, 10),
        us_row=state.memory.load(base + W_US_ROW, 10),
        top_x=state.memory.load(base + W_TOP_X, 1),
        cur_item=state.memory.load(base + W_CUR_ITEM, 1),
        cursor_target=state.memory.load(base + CURSOR_TARGET, 1),
        constraints=tuple(state.solver.constraints),
    )


def _hook(project: angr.Project) -> None:
    def hook(addr: int, shim: angr.SimProcedure, length: int) -> None:
        project.hook(addr, shim, length=length)

    # PrintNicknameAndUnderscores body: every SM83 load/store/compare the
    # Z80 p-code backend mis-decodes, plus flag-exact ALU seams.
    hook(B + 4, Sm83StoreAImmediate(W_NAME_LEN, B + 7), 3)
    hook(B + 43, Sm83StoreAAtHlIncrement(B + 44), 1)
    hook(B + 70, Sm83StoreAImmediate(W_TOP_X, B + 73), 3)
    hook(B + 75, Sm83StoreAImmediate(W_CUR_ITEM, B + 78), 3)
    hook(B + 28, Sm83LoadAImmediate(W_TYPE, B + 31), 3)
    hook(B + 47, Sm83LoadAImmediate(W_TYPE, B + 50), 3)
    hook(B + 52, Sm83LoadAImmediate(W_NAME_LEN, B + 55), 3)
    hook(B + 78, Sm83LoadAImmediate(W_TYPE, B + 81), 3)
    for off, imm in ((31, 2), (50, 2), (57, 7), (61, 10), (81, 2)):
        hook(B + off, Sm83CpImmediate(imm, B + off + 2), 2)
    hook(B + 44, Sm83DecRegister("b", B + 45), 1)
    # The tail loads sit between the last comparison and ADD HL,BC, so
    # they must preserve the comparison's Z/C exactly.
    hook(B + 83, LdImm8("a", 9, B + 85), 2)
    hook(B + 87, LdImm8("a", 6, B + 89), 2)
    hook(B + 89, LdReg("c", "a", B + 90), 1)
    hook(B + 90, LdImm8("b", 0, B + 92), 2)
    hook(B + 92, LdPair16("h", "l", W_US_ROW, B + 95), 3)
    hook(B + 95, Sm83AddHlRegisterPair("bc", B + 96), 1)
    # CalcStringLength (same bank): exact length loop and taken RET Z.
    hook(C + 6, Sm83CpImmediate(0x50, C + 8), 2)
    hook(C + 8, RetCond(C + 9, True), 1)
    hook(C + 10, Sm83IncRegister("c", C + 11), 1)
    # ClearScreenArea: exact 1x10 fill; PUSH/POP use software semantics.
    hook(S + 7, Sm83StoreAAtHlIncrement(S + 8), 1)
    hook(S + 8, Sm83DecRegister("c", S + 9), 1)
    hook(S + 13, Sm83AddHlRegisterPair("de", S + 14), 1)
    hook(S + 14, Sm83DecRegister("b", S + 15), 1)
    hook(0x18C9, PushPair("h", "l", 0x18CA), 1)
    hook(0x18CA, PushPair("b", "c", 0x18CB), 1)
    hook(0x18CF, PopPair("b", "c", 0x18D0), 1)
    hook(0x18D0, PopPair("h", "l", 0x18D1), 1)
    # EraseMenuCursor: the two cursor-pointer loads (rest decodes cleanly).
    hook(0x3BF9, Sm83LoadAImmediate(W_CURSOR, 0x3BFC), 3)
    hook(0x3BFD, Sm83LoadAImmediate(W_CURSOR + 1, 0x3C00), 3)
    # PlaceString plain-character path plus the full 20-entry dictionary
    # scan each character walks before its verbatim store.
    hook(P + 0, PushPair("h", "l", P + 1), 1)
    hook(P + 1, LoadAAtDe(P + 2), 1)
    hook(P + 2, Sm83CpImmediate(0x50, P + 4), 2)
    hook(P + 10, Sm83CpImmediate(0x4E, P + 12), 2)
    hook(P + 32, Sm83CpImmediate(0x4F, P + 34), 2)
    hook(P + 44, Sm83AndRegister("a", P + 45), 1)
    for index, imm in enumerate(DICT_IMMS):
        hook(P + 48 + index * 5, Sm83CpImmediate(imm, P + 50 + index * 5), 2)
    hook(P + 143, Sm83StoreAAtHlIncrement(P + 144), 1)
    hook(P + 8, PopPair("h", "l", P + 9), 1)
    # PrintLetterDelay fast path: text delay is disabled on entry, so the
    # BIT test always takes the immediate RET NZ.
    hook(L + 0, Sm83LoadAImmediate(W_STATUS5, L + 3), 3)
    hook(L + 3, Sm83BitRegister(6, "a", L + 5), 2)
    hook(L + 5, RetCond(L + 6, False), 1)


def _assembly(values: dict[str, object]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "PrintNicknameAndUnderscores")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY
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
    _hook(project)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    _store(state, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    ends = collect_returns(project, state, RETURN)
    assert len(ends) == 1
    return [_endpoint(end, native=False) for end in ends]


def _native(values: dict[str, object]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(
        "port_print_nickname_and_underscores")
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _store(state, values, NATIVE_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [_endpoint(end, native=True) for end in manager.deadended]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run red")
@pytest.mark.parametrize(
    "label,ntype,letters", CASES, ids=[case[0] for case in CASES])
def test_print_nickname_and_underscores_pathwise_equivalence(
        label: str, ntype: int, letters: tuple[int, ...]) -> None:
    values = _inputs(f"nickname_{label}", ntype, letters)
    assert_pathwise_equivalent(
        _assembly(values), _native(values),
        (*REGISTERS, "name_len", "name_row", "us_row", "top_x", "cur_item",
         "cursor_target"),
    )


def test_print_nickname_and_underscores_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "PrintNicknameAndUnderscores")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY
