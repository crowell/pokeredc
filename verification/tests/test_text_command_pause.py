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
from verification.harness.sm83_shims import Sm83DecRegister, Sm83LoadAHighImmediate

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
CONTINUATION = 0x1B55

H_LOADED_ROM_BANK = 0xFFB8
R_ROMB = 0x2000
H_JOYINPUT = 0xFFF8
H_JOYLAST = 0xFFB1
H_JOYRELEASED = 0xFFB2
H_JOYPRESSED = 0xFFB3
H_JOYHELD = 0xFFB4
W_STATUSFLAGS5 = 0xD730
W_JOYIGNORE = 0xCD6B
PAD_BUTTONS = 0x0F
BIT_DISABLE_JOYPAD = 5

HANDLER_EXPECTED = bytes.fromhex(
    "c5cd9a01f0b4e60320050e1ecd3937c1e1c3551b"
)
DELAY_FRAMES_EXPECTED = bytes.fromhex("cdaf200d20fac9")


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
    joy_input: claripy.ast.BV
    joy_last: claripy.ast.BV
    joy_released: claripy.ast.BV
    joy_pressed: claripy.ast.BV
    joy_held: claripy.ast.BV
    bank: claripy.ast.BV
    romb: claripy.ast.BV
    status: claripy.ast.BV
    ignore: claripy.ast.BV
    delay_frame_calls: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


MEMORY_INPUTS = (
    ("status", W_STATUSFLAGS5),
    ("ignore", W_JOYIGNORE),
    ("joy_input", H_JOYINPUT),
    ("joy_last", H_JOYLAST),
    ("joy_released", H_JOYRELEASED),
    ("joy_pressed", H_JOYPRESSED),
    ("joy_held", H_JOYHELD),
    ("bank", H_LOADED_ROM_BANK),
    ("romb", R_ROMB),
)


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["pushed_hl"] = claripy.BVS(f"{prefix}_pushed_hl", 16)
    for name, _address in MEMORY_INPUTS:
        values[name] = claripy.BVS(f"{prefix}_{name}", 8)
    return values


def _setup(
    state: angr.SimState,
    values: dict[str, claripy.ast.BV],
    native: bool,
) -> None:
    base = NATIVE_MEMORY if native else 0
    for name, address in MEMORY_INPUTS:
        state.memory.store(base + address, values[name])


def _endpoint(state: angr.SimState, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    registers = (
        native_registers(state, NATIVE_STATE)
        if native
        else assembly_registers(state)
    )
    return Endpoint(
        **registers,
        joy_input=state.memory.load(base + H_JOYINPUT, 1),
        joy_last=state.memory.load(base + H_JOYLAST, 1),
        joy_released=state.memory.load(base + H_JOYRELEASED, 1),
        joy_pressed=state.memory.load(base + H_JOYPRESSED, 1),
        joy_held=state.memory.load(base + H_JOYHELD, 1),
        bank=state.memory.load(base + H_LOADED_ROM_BANK, 1),
        romb=state.memory.load(base + R_ROMB, 1),
        status=state.memory.load(base + W_STATUSFLAGS5, 1),
        ignore=state.memory.load(base + W_JOYIGNORE, 1),
        delay_frame_calls=state.globals["delay_frame_calls"],
        constraints=tuple(state.solver.constraints),
    )


class PushBC(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        sp = self.state.solver.eval(self.state.regs.sp)
        self.state.memory.store(sp - 1, self.state.regs.b)
        self.state.memory.store(sp - 2, self.state.regs.c)
        self.state.regs.sp = claripy.BVV(sp - 2, 16)
        self.jump(self.next_address)


class PopBC(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        sp = self.state.solver.eval(self.state.regs.sp)
        self.state.regs.c = self.state.memory.load(sp, 1)
        self.state.regs.b = self.state.memory.load(sp + 1, 1)
        self.state.regs.sp = claripy.BVV(sp + 2, 16)
        self.jump(self.next_address)


class PopHL(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        sp = self.state.solver.eval(self.state.regs.sp)
        self.state.regs.l = self.state.memory.load(sp, 1)
        self.state.regs.h = self.state.memory.load(sp + 1, 1)
        self.state.regs.sp = claripy.BVV(sp + 2, 16)
        self.jump(self.next_address)


class LoadCImmediate(angr.SimProcedure):
    def __init__(self, value: int, next_address: int) -> None:
        super().__init__()
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.c = claripy.BVV(self.value, 8)
        self.jump(self.next_address)


class Sm83AndImmediateCorrect(angr.SimProcedure):
    def __init__(self, value: int, next_address: int) -> None:
        super().__init__()
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a &= self.value
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x50, 8),
            claripy.BVV(0x10, 8),
        )
        self.jump(self.next_address)


class ForkOnZ(angr.SimProcedure):
    def __init__(
        self, taken: int, fallthrough: int, taken_when_set: bool
    ) -> None:
        super().__init__()
        self.taken = taken
        self.fallthrough = fallthrough
        self.taken_when_set = taken_when_set

    def run(self) -> None:  # type: ignore[override]
        z_set = ((self.state.regs.f >> 6) & 1) == 1
        condition = z_set if self.taken_when_set else claripy.Not(z_set)
        taken = self.state.copy()
        fallthrough = self.state.copy()
        taken.solver.add(condition)
        fallthrough.solver.add(claripy.Not(condition))
        taken.regs.ip = claripy.BVV(self.taken, 16)
        fallthrough.regs.ip = claripy.BVV(self.fallthrough, 16)
        self.inhibit_autoret = True
        self.successors.add_successor(
            taken, self.taken, condition, "Ijk_Boring"
        )
        self.successors.add_successor(
            fallthrough,
            self.fallthrough,
            claripy.Not(condition),
            "Ijk_Boring",
        )


class Jump(angr.SimProcedure):
    def __init__(self, address: int) -> None:
        super().__init__()
        self.address = address

    def run(self) -> None:  # type: ignore[override]
        self.jump(self.address)


class JoypadBoundary(angr.SimProcedure):
    """Complete transition of the independently proved Joypad homecall."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        memory = self.state.memory
        input_value = memory.load(H_JOYINPUT, 1)
        last = memory.load(H_JOYLAST, 1)
        ignore = memory.load(W_JOYIGNORE, 1)
        disabled = (
            memory.load(W_STATUSFLAGS5, 1) & (1 << BIT_DISABLE_JOYPAD)
        ) != 0
        normal = input_value != PAD_BUTTONS
        unmasked = claripy.Or(disabled, ignore == 0)
        mask = ~ignore
        released = (last ^ input_value) & last
        pressed = (last ^ input_value) & input_value
        held_after = claripy.If(
            disabled,
            claripy.BVV(0, 8),
            claripy.If(ignore == 0, input_value, input_value & mask),
        )
        pressed_after = claripy.If(
            disabled,
            claripy.BVV(0, 8),
            claripy.If(ignore == 0, pressed, pressed & mask),
        )
        released_after = claripy.If(
            disabled, claripy.BVV(0, 8), released
        )

        saved_a = memory.load(H_LOADED_ROM_BANK, 1)
        saved_f = self.state.regs.f
        memory.store(
            H_JOYLAST,
            claripy.If(normal, input_value, memory.load(H_JOYLAST, 1)),
        )
        memory.store(
            H_JOYRELEASED,
            claripy.If(
                normal,
                released_after,
                memory.load(H_JOYRELEASED, 1),
            ),
        )
        memory.store(
            H_JOYPRESSED,
            claripy.If(
                normal,
                pressed_after,
                memory.load(H_JOYPRESSED, 1),
            ),
        )
        memory.store(
            H_JOYHELD,
            claripy.If(normal, held_after, memory.load(H_JOYHELD, 1)),
        )
        self.state.regs.b = claripy.If(
            normal,
            claripy.If(unmasked, input_value, mask),
            self.state.regs.b,
        )
        self.state.regs.d = claripy.If(
            normal, input_value ^ last, self.state.regs.d
        )
        self.state.regs.e = claripy.If(normal, last, self.state.regs.e)
        self.state.regs.a = saved_a
        self.state.regs.f = saved_f
        memory.store(H_LOADED_ROM_BANK, saved_a)
        memory.store(R_ROMB, saved_a)
        self.jump(self.next_address)


class DelayFrameBoundary(angr.SimProcedure):
    """Acknowledged-VBlank terminal of the independently proved callee."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["delay_frame_calls"] += 1
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x50, 8)
        self.jump(self.next_address)


class NativeDelayFrameBoundary(angr.SimProcedure):
    """Same proved terminal while the real DelayFrames loop stays active."""

    def run(
        self, state: claripy.ast.BV, _observations: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        self.state.globals["delay_frame_calls"] += 1
        self.state.memory.store(state, claripy.BVV(0, 8))
        self.state.memory.store(state + 1, claripy.BVV(0xA0, 8))
        self.state.memory.store(state + 8, claripy.BVV(0, 8))
        self.state.memory.store(state + 9, claripy.BVV(0, 8))


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    handler = symbol_location(SYMBOLS, "TextCommand_PAUSE")
    next_handler = symbol_location(SYMBOLS, "TextCommand_SOUND")
    delay_frames = symbol_location(SYMBOLS, "DelayFrames")
    next_text = symbol_location(SYMBOLS, "NextTextCommand")
    assert handler.bank == delay_frames.bank == next_text.bank == 0
    assert next_handler.address - handler.address == len(HANDLER_EXPECTED)
    assert next_text.address == CONTINUATION
    assert linked_bytes(ROM, handler, len(HANDLER_EXPECTED)) == HANDLER_EXPECTED
    assert (
        linked_bytes(ROM, delay_frames, len(DELAY_FRAMES_EXPECTED))
        == DELAY_FRAMES_EXPECTED
    )

    project = angr.Project(
        rom_window(ROM, handler.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": handler.address,
        },
    )
    base = handler.address
    delay = delay_frames.address
    project.hook(base, PushBC(base + 1), length=1)
    project.hook(base + 1, JoypadBoundary(base + 4), length=3)
    project.hook(
        base + 4, Sm83LoadAHighImmediate(0xB4, base + 6), length=2
    )
    project.hook(
        base + 6, Sm83AndImmediateCorrect(0x03, base + 8), length=2
    )
    project.hook(
        base + 8,
        ForkOnZ(base + 15, base + 10, taken_when_set=False),
        length=2,
    )
    project.hook(base + 10, LoadCImmediate(30, base + 12), length=2)
    project.hook(base + 12, Jump(delay), length=3)
    project.hook(base + 15, PopBC(base + 16), length=1)
    project.hook(base + 16, PopHL(base + 17), length=1)
    project.hook(base + 17, Jump(CONTINUATION), length=3)

    # Execute the complete real DelayFrames recurrence. Only its proved
    # DelayFrame callee transition and the CALL/RET plumbing are boundaries.
    project.hook(delay, DelayFrameBoundary(delay + 3), length=3)
    project.hook(delay + 3, Sm83DecRegister("c", delay + 4), length=1)
    project.hook(delay + 6, Jump(base + 15), length=1)

    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _setup(state, values, native=False)
    state.globals["delay_frame_calls"] = claripy.BVV(0, 8)
    state.regs.sp = STACK - 2
    state.memory.store(STACK - 2, values["pushed_hl"][7:0])
    state.memory.store(STACK - 1, values["pushed_hl"][15:8])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=CONTINUATION, num_find=16)
    assert not manager.errored
    assert len(manager.found) == 2
    return [_endpoint(final, native=False) for final in manager.found]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_text_command_pause")
    delay_frame = project.loader.find_symbol("port_delay_frame")
    assert function is not None and delay_frame is not None
    project.hook(delay_frame.rebased_addr, NativeDelayFrameBoundary())
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, values, native=True)
    state.globals["delay_frame_calls"] = claripy.BVV(0, 8)
    state.memory.store(NATIVE_STATE + 6, values["pushed_hl"][15:8])
    state.memory.store(NATIVE_STATE + 7, values["pushed_hl"][7:0])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 7
    return [_endpoint(final, native=True) for final in manager.deadended]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(
    not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`"
)
def test_text_command_pause_pathwise_equivalence() -> None:
    values = _inputs("text_command_pause")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (
            *REGISTERS,
            "joy_input",
            "joy_last",
            "joy_released",
            "joy_pressed",
            "joy_held",
            "bank",
            "romb",
            "status",
            "ignore",
            "delay_frame_calls",
        ),
    )
