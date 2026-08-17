from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode
from pypcode import Context

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.rom import symbol_location, rom_window
from verification.harness.sm83_shims import (
    Sm83AndRegister,
    Sm83BitRegister,
    Sm83CpImmediate,
    Sm83LoadAHighImmediate,
    Sm83LoadAImmediate,
    Sm83StoreAHighImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
GB_STACK = 0xD000
GB_RETURN = 0xFFFF
NATIVE_STATE = 0x100000

H_JOYINPUT = 0xFFF8
H_JOYLAST = 0xFFB1
H_JOYRELEASED = 0xFFB2
H_JOYPRESSED = 0xFFB3
H_JOYHELD = 0xFFB4
W_STATUSFLAGS5 = 0xD730
W_JOYIGNORE = 0xCD6B
PAD_BUTTONS = 0x0F
BIT_DISABLE_JOYPAD = 5

# Shared symbolic inputs: the same BVS objects are stored into both the
# assembly and native memory so the equivalence solver treats them as one.
JOYINPUT = claripy.BVS("joy_input", 8)
JOYLAST = claripy.BVS("joy_last", 8)
STATUS = claripy.BVS("w_status_flags5", 8)
JOYIGNORE = claripy.BVS("w_joy_ignore", 8)
# Outputs that are left *unchanged* on the PAD_BUTTONS early-return path.
REL_INIT = claripy.BVS("joy_released_init", 8)
PRES_INIT = claripy.BVS("joy_pressed_init", 8)
HELD_INIT = claripy.BVS("joy_held_init", 8)


@dataclass(frozen=True)
class Endpoint:
    hJoyInput: claripy.ast.BV
    hJoyLast: claripy.ast.BV
    hJoyReleased: claripy.ast.BV
    hJoyPressed: claripy.ast.BV
    hJoyHeld: claripy.ast.BV
    wStatusFlags5: claripy.ast.BV
    wJoyIgnore: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class _Fork(angr.SimProcedure):
    """Fork a path on a flag condition.

    The bundled Z80 SLEIGH does not fork JR Z / JR NZ / RET Z / RET NZ. The
    guard is the 3rd positional arg of SimSuccessors.add_successor;
    inhibit_autoret avoids the empty-call-frame ret() angr would otherwise
    emit. The guard is also recorded as a state constraint so pathwise
    equivalence can pair terminal paths correctly. In this harness Z lives at
    bit 6 (0x40) and C at bit 0 (0x01) of F.
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
    """Conditional (relative) jump: taken/fallthrough are absolute targets."""


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


def _assembly_endpoints() -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "_Joypad")
    q = location.address
    project = angr.Project(
        rom_window(ROM, location.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": q,
        },
    )
    # _Joypad (engine/joypad.asm), instruction offsets relative to q.
    project.hook(q + 0, Sm83LoadAHighImmediate(0xF8, q + 2), length=1)  # ldh a,[hJoyInput]
    project.hook(q + 2, Sm83CpImmediate(PAD_BUTTONS, q + 4), length=2)  # cp PAD_BUTTONS
    project.hook(q + 4, ForkJR(GB_RETURN, q + 7, 6, False), length=3)  # jp z,TrySoftReset -> early return
    project.hook(q + 8, Sm83LoadAHighImmediate(0xB1, q + 10), length=2)  # ldh a,[hJoyLast]
    project.hook(q + 14, Sm83StoreAHighImmediate(0xB2, q + 16), length=2)  # ldh [hJoyReleased],a
    project.hook(q + 18, Sm83StoreAHighImmediate(0xB3, q + 20), length=2)  # ldh [hJoyPressed],a
    project.hook(q + 21, Sm83StoreAHighImmediate(0xB1, q + 23), length=2)  # ldh [hJoyLast],a
    project.hook(q + 23, Sm83LoadAImmediate(W_STATUSFLAGS5, q + 26), length=3)  # ld a,[wStatusFlags5]
    project.hook(q + 26, Sm83BitRegister(BIT_DISABLE_JOYPAD, "a", q + 28), length=2)  # bit BIT_DISABLE_JOYPAD,a
    project.hook(q + 28, ForkJR(q + 52, q + 30, 6, True), length=2)  # jr nz,DiscardButtonPresses
    project.hook(q + 30, Sm83LoadAHighImmediate(0xB1, q + 32), length=2)  # ldh a,[hJoyLast]
    project.hook(q + 32, Sm83StoreAHighImmediate(0xB4, q + 34), length=2)  # ldh [hJoyHeld],a
    project.hook(q + 34, Sm83LoadAImmediate(W_JOYIGNORE, q + 37), length=3)  # ld a,[wJoyIgnore]
    project.hook(q + 37, Sm83AndRegister("a", q + 38), length=1)  # and a
    project.hook(q + 38, ForkRet(q + 39, 6, False), length=1)  # ret z
    project.hook(q + 41, Sm83LoadAHighImmediate(0xB4, q + 43), length=2)  # ldh a,[hJoyHeld]
    project.hook(q + 44, Sm83StoreAHighImmediate(0xB4, q + 46), length=2)  # ldh [hJoyHeld],a
    project.hook(q + 46, Sm83LoadAHighImmediate(0xB3, q + 48), length=2)  # ldh a,[hJoyPressed]
    project.hook(q + 49, Sm83StoreAHighImmediate(0xB3, q + 51), length=2)  # ldh [hJoyPressed],a
    project.hook(q + 51, DoRet(), length=1)  # ret (normal tail)
    project.hook(q + 53, Sm83StoreAHighImmediate(0xB4, q + 55), length=2)  # Discard: ldh [hJoyHeld],a (a=0)
    project.hook(q + 55, Sm83StoreAHighImmediate(0xB3, q + 57), length=2)  # Discard: ldh [hJoyPressed],a
    project.hook(q + 57, Sm83StoreAHighImmediate(0xB2, q + 59), length=2)  # Discard: ldh [hJoyReleased],a
    project.hook(q + 59, DoRet(), length=1)  # ret (DiscardButtonPresses)

    state = project.factory.blank_state(addr=q)
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    state.memory.store(H_JOYINPUT, JOYINPUT)
    state.memory.store(H_JOYLAST, JOYLAST)
    state.memory.store(W_STATUSFLAGS5, STATUS)
    state.memory.store(W_JOYIGNORE, JOYIGNORE)
    state.memory.store(H_JOYRELEASED, REL_INIT)
    state.memory.store(H_JOYPRESSED, PRES_INIT)
    state.memory.store(H_JOYHELD, HELD_INIT)

    from verification.harness.rom import collect_returns

    return [
        Endpoint(
            hJoyInput=end.memory.load(H_JOYINPUT, 1),
            hJoyLast=end.memory.load(H_JOYLAST, 1),
            hJoyReleased=end.memory.load(H_JOYRELEASED, 1),
            hJoyPressed=end.memory.load(H_JOYPRESSED, 1),
            hJoyHeld=end.memory.load(H_JOYHELD, 1),
            wStatusFlags5=end.memory.load(W_STATUSFLAGS5, 1),
            wJoyIgnore=end.memory.load(W_JOYIGNORE, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, GB_RETURN)
    ]


def _native_endpoints() -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    fn = project.loader.find_symbol("port_joypad")
    assert fn is not None
    # arg0 = state struct at NATIVE_STATE; arg1 = memory (NULL) so absolute GB
    # addresses land directly in angr's flat memory.
    state = project.factory.call_state(fn.rebased_addr, NATIVE_STATE, claripy.BVV(0, 64))
    state.memory.store(H_JOYINPUT, JOYINPUT)
    state.memory.store(H_JOYLAST, JOYLAST)
    state.memory.store(W_STATUSFLAGS5, STATUS)
    state.memory.store(W_JOYIGNORE, JOYIGNORE)
    state.memory.store(H_JOYRELEASED, REL_INIT)
    state.memory.store(H_JOYPRESSED, PRES_INIT)
    state.memory.store(H_JOYHELD, HELD_INIT)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            hJoyInput=end.memory.load(H_JOYINPUT, 1),
            hJoyLast=end.memory.load(H_JOYLAST, 1),
            hJoyReleased=end.memory.load(H_JOYRELEASED, 1),
            hJoyPressed=end.memory.load(H_JOYPRESSED, 1),
            hJoyHeld=end.memory.load(H_JOYHELD, 1),
            wStatusFlags5=end.memory.load(W_STATUSFLAGS5, 1),
            wJoyIgnore=end.memory.load(W_JOYIGNORE, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_joypad_symbolic_equivalence() -> None:
    assert_pathwise_equivalent(
        _assembly_endpoints(),
        _native_endpoints(),
        (
            "hJoyInput",
            "hJoyLast",
            "hJoyReleased",
            "hJoyPressed",
            "hJoyHeld",
            "wStatusFlags5",
            "wJoyIgnore",
        ),
    )
