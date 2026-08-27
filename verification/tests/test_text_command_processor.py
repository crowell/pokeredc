from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
    set_assembly_registers,
    store_native_registers,
    symbolic_registers,
)
from verification.harness.rom import linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import (
    Sm83AddHlRegisterPair,
    Sm83AddRegister,
    Sm83CpImmediate,
    Sm83LoadAAtHlIncrement,
    Sm83LoadAHighImmediate,
    Sm83LoadAImmediate,
    Sm83StoreAImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
SENTINEL = 0xFFFF

TX_END = 0x50
TX_FAR = 0x17
TX_SOUND_POKEDEX_RATING = 0x0E
H_LOADED_ROM_BANK = 0xFFB8
R_ROMB = 0x2000
W_LETTER_PRINTING_DELAY_FLAGS = 0xD358
H_CLEAR_LETTER_PRINTING_DELAY_FLAGS = 0xFFF4
W_TEXT_DEST = 0xCC3A
TEXT_PTR = 0xD360

HANDLER_TARGETS = {
    0x00: 0x1B8A,  # TextCommand_START
    0x01: 0x1B97,  # TextCommand_RAM
    0x02: 0x1BA5,  # TextCommand_BCD
    0x03: 0x1BB7,  # TextCommand_MOVE
    0x04: 0x1B78,  # TextCommand_BOX
    0x05: 0x1BC5,  # TextCommand_LOW
    0x06: 0x1BCC,  # TextCommand_PROMPT_BUTTON
    0x07: 0x1BE7,  # TextCommand_SCROLL
    0x08: 0x1BF9,  # TextCommand_START_ASM
    0x09: 0x1BFF,  # TextCommand_NUM
    0x0A: 0x1C1D,  # TextCommand_PAUSE
    0x0B: 0x1C31,  # TextCommand_SOUND
    0x0C: 0x1C78,  # TextCommand_DOTS
    0x0D: 0x1C9A,  # TextCommand_WAIT_BUTTON
}

HANDLER_SYMBOLS = {
    0x00: "port_text_command_start",
    0x01: "port_text_command_ram",
    0x02: "port_text_command_bcd",
    0x03: "port_text_command_move",
    0x04: "port_text_command_box",
    0x05: "port_text_command_low",
    0x06: "port_text_command_prompt_button",
    0x07: "port_text_command_scroll",
    0x08: "port_text_command_start_asm",
    0x09: "port_text_command_num",
    0x0A: "port_text_command_pause",
    0x0B: "port_text_command_sound",
    0x0C: "port_text_command_dots",
    0x0D: "port_text_command_wait_button",
}

HANDLER_EXPECTED = bytes.fromhex(
    "fa58d3f5cbcf5ff0f4abea58d379ea3acc78ea3bcc2afe502005f1ea58d3c9"
    "e5fe17caa31cfe0ed2311c21c11cc58706004f09c12a666fe9"
)


@dataclass(frozen=True)
class Endpoint:
    dispatch_target: claripy.ast.BV
    ldf: claripy.ast.BV
    clear: claripy.ast.BV
    text_dest: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["h"] = claripy.BVV(TEXT_PTR >> 8, 8)
    values["l"] = claripy.BVV(TEXT_PTR & 0xFF, 8)
    values["ldf"] = claripy.BVS(f"{prefix}_ldf", 8)
    values["clear"] = claripy.BVS(f"{prefix}_clear", 8)
    return values


def _setup(
    state: angr.SimState,
    values: dict[str, claripy.ast.BV],
    native: bool,
    command: int,
) -> None:
    base = NATIVE_MEMORY if native else 0
    state.memory.store(base + TEXT_PTR, claripy.BVV(command, 8))
    state.memory.store(
        base + W_LETTER_PRINTING_DELAY_FLAGS,
        values["ldf"],
    )
    state.memory.store(
        base + H_CLEAR_LETTER_PRINTING_DELAY_FLAGS,
        values["clear"],
    )


def _endpoint(state: angr.SimState, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    return Endpoint(
        dispatch_target=state.globals["dispatch_target"],
        ldf=state.memory.load(base + W_LETTER_PRINTING_DELAY_FLAGS, 1),
        clear=state.memory.load(base + H_CLEAR_LETTER_PRINTING_DELAY_FLAGS, 1),
        text_dest=claripy.Concat(
            state.memory.load(base + W_TEXT_DEST + 1, 1),
            state.memory.load(base + W_TEXT_DEST, 1),
        ),
        constraints=tuple(state.solver.constraints),
    )


class PushPair(angr.SimProcedure):
    def __init__(self, high: str, low: str, next_address: int) -> None:
        super().__init__()
        self.high = high
        self.low = low
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        sp = self.state.solver.eval(self.state.regs.sp)
        self.state.memory.store(sp - 1, getattr(self.state.regs, self.high))
        self.state.memory.store(sp - 2, getattr(self.state.regs, self.low))
        self.state.regs.sp = claripy.BVV(sp - 2, 16)
        self.jump(self.next_address)


class PopPair(angr.SimProcedure):
    def __init__(self, high: str, low: str, next_address: int) -> None:
        super().__init__()
        self.high = high
        self.low = low
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        sp = self.state.solver.eval(self.state.regs.sp)
        setattr(self.state.regs, self.low, self.state.memory.load(sp, 1))
        setattr(self.state.regs, self.high, self.state.memory.load(sp + 1, 1))
        self.state.regs.sp = claripy.BVV(sp + 2, 16)
        self.jump(self.next_address)


class SetBitA(angr.SimProcedure):
    def __init__(self, bit: int, next_address: int) -> None:
        super().__init__()
        self.bit = bit
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.regs.a | (1 << self.bit)
        self.jump(self.next_address)


class CopyRegister(angr.SimProcedure):
    def __init__(self, destination: str, source: str, next_address: int) -> None:
        super().__init__()
        self.destination = destination
        self.source = source
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        setattr(
            self.state.regs,
            self.destination,
            getattr(self.state.regs, self.source),
        )
        self.jump(self.next_address)


class XorRegister(angr.SimProcedure):
    def __init__(self, register: str, next_address: int) -> None:
        super().__init__()
        self.register = register
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        result = self.state.regs.a ^ getattr(self.state.regs, self.register)
        self.state.regs.a = result
        self.state.regs.f = claripy.If(
            result == 0,
            claripy.BVV(0x40, 8),
            claripy.BVV(0, 8),
        )
        self.jump(self.next_address)


class LoadRegisterImmediate(angr.SimProcedure):
    def __init__(self, register: str, value: int, next_address: int) -> None:
        super().__init__()
        self.register = register
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.register, claripy.BVV(self.value, 8))
        self.jump(self.next_address)


class LoadHLImmediate(angr.SimProcedure):
    def __init__(self, value: int, next_address: int) -> None:
        super().__init__()
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.hl = claripy.BVV(self.value, 16)
        self.jump(self.next_address)


class LoadHFromHL(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = self.state.memory.load(self.state.regs.hl, 1)
        self.jump(self.next_address)


class ForkOnZ(angr.SimProcedure):
    def __init__(
        self,
        taken: int,
        fallthrough: int,
        taken_when_set: bool,
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
        self.successors.add_successor(taken, self.taken, condition, "Ijk_Boring")
        self.successors.add_successor(
            fallthrough,
            self.fallthrough,
            claripy.Not(condition),
            "Ijk_Boring",
        )


class JpZRecordTarget(angr.SimProcedure):
    def __init__(self, target: int, fallthrough: int, terminal: int) -> None:
        super().__init__()
        self.target = target
        self.fallthrough = fallthrough
        self.terminal = terminal

    def run(self) -> None:  # type: ignore[override]
        z_set = ((self.state.regs.f >> 6) & 1) == 1
        taken = self.state.copy()
        fallthrough = self.state.copy()
        taken.solver.add(z_set)
        fallthrough.solver.add(claripy.Not(z_set))
        taken.globals["dispatch_target"] = claripy.BVV(self.target, 16)
        taken.regs.ip = claripy.BVV(self.terminal, 16)
        fallthrough.regs.ip = claripy.BVV(self.fallthrough, 16)
        self.inhibit_autoret = True
        self.successors.add_successor(taken, self.terminal, z_set, "Ijk_Boring")
        self.successors.add_successor(
            fallthrough,
            self.fallthrough,
            claripy.Not(z_set),
            "Ijk_Boring",
        )


class JpNcRecordTarget(angr.SimProcedure):
    def __init__(self, target: int, fallthrough: int, terminal: int) -> None:
        super().__init__()
        self.target = target
        self.fallthrough = fallthrough
        self.terminal = terminal

    def run(self) -> None:  # type: ignore[override]
        nc = ((self.state.regs.f >> 0) & 1) == 0
        taken = self.state.copy()
        fallthrough = self.state.copy()
        taken.solver.add(nc)
        fallthrough.solver.add(claripy.Not(nc))
        taken.globals["dispatch_target"] = claripy.BVV(self.target, 16)
        taken.regs.ip = claripy.BVV(self.terminal, 16)
        fallthrough.regs.ip = claripy.BVV(self.fallthrough, 16)
        self.inhibit_autoret = True
        self.successors.add_successor(taken, self.terminal, nc, "Ijk_Boring")
        self.successors.add_successor(
            fallthrough,
            self.fallthrough,
            claripy.Not(nc),
            "Ijk_Boring",
        )


class JpHLRecordTarget(angr.SimProcedure):
    def __init__(self, terminal: int) -> None:
        super().__init__()
        self.terminal = terminal

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["dispatch_target"] = self.state.regs.hl
        self.jump(self.terminal)


class RetTerminal(angr.SimProcedure):
    def __init__(self, terminal: int) -> None:
        super().__init__()
        self.terminal = terminal

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["dispatch_target"] = claripy.BVV(0, 16)
        self.jump(self.terminal)


class NativeBoundary(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__()
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["dispatch_target"] = claripy.BVV(self.target, 16)
        self.jump(SENTINEL)


def _assembly(values: dict[str, claripy.ast.BV], command: int) -> list[Endpoint]:
    handler = symbol_location(SYMBOLS, "TextCommandProcessor")
    assert handler.bank == 0
    assert handler.address == 0x1B40
    assert linked_bytes(ROM, handler, len(HANDLER_EXPECTED)) == HANDLER_EXPECTED

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
    project.hook(base + 0x00, Sm83LoadAImmediate(W_LETTER_PRINTING_DELAY_FLAGS, base + 0x03), length=3)
    project.hook(base + 0x03, PushPair("a", "f", base + 0x04), length=1)
    project.hook(base + 0x04, SetBitA(1, base + 0x06), length=2)
    project.hook(base + 0x06, CopyRegister("e", "a", base + 0x07), length=1)
    project.hook(base + 0x07, Sm83LoadAHighImmediate(0xF4, base + 0x09), length=2)
    project.hook(base + 0x09, XorRegister("e", base + 0x0A), length=1)
    project.hook(base + 0x0A, Sm83StoreAImmediate(W_LETTER_PRINTING_DELAY_FLAGS, base + 0x0D), length=3)
    project.hook(base + 0x0D, CopyRegister("a", "c", base + 0x0E), length=1)
    project.hook(base + 0x0E, Sm83StoreAImmediate(W_TEXT_DEST, base + 0x11), length=3)
    project.hook(base + 0x11, CopyRegister("a", "b", base + 0x12), length=1)
    project.hook(base + 0x12, Sm83StoreAImmediate(W_TEXT_DEST + 1, base + 0x15), length=3)
    project.hook(base + 0x15, Sm83LoadAAtHlIncrement(base + 0x16), length=1)
    project.hook(base + 0x16, Sm83CpImmediate(TX_END, base + 0x18), length=2)
    project.hook(base + 0x18, ForkOnZ(base + 0x1F, base + 0x1A, taken_when_set=False), length=2)
    project.hook(base + 0x1A, PopPair("a", "f", base + 0x1B), length=1)
    project.hook(base + 0x1B, Sm83StoreAImmediate(W_LETTER_PRINTING_DELAY_FLAGS, base + 0x1E), length=3)
    project.hook(base + 0x1E, RetTerminal(SENTINEL), length=1)
    project.hook(base + 0x1F, PushPair("h", "l", base + 0x20), length=1)
    project.hook(base + 0x20, Sm83CpImmediate(TX_FAR, base + 0x22), length=2)
    project.hook(base + 0x22, JpZRecordTarget(0x1CA3, base + 0x25, SENTINEL), length=3)
    project.hook(base + 0x25, Sm83CpImmediate(TX_SOUND_POKEDEX_RATING, base + 0x27), length=2)
    project.hook(base + 0x27, JpNcRecordTarget(0x1C31, base + 0x2A, SENTINEL), length=3)
    project.hook(base + 0x2A, LoadHLImmediate(0x1CC1, base + 0x2D), length=3)
    project.hook(base + 0x2D, PushPair("b", "c", base + 0x2E), length=1)
    project.hook(base + 0x2E, Sm83AddRegister("a", base + 0x2F), length=1)
    project.hook(base + 0x2F, LoadRegisterImmediate("b", 0, base + 0x31), length=2)
    project.hook(base + 0x31, CopyRegister("c", "a", base + 0x32), length=1)
    project.hook(base + 0x32, Sm83AddHlRegisterPair("bc", base + 0x33), length=1)
    project.hook(base + 0x33, PopPair("b", "c", base + 0x34), length=1)
    project.hook(base + 0x34, Sm83LoadAAtHlIncrement(base + 0x35), length=1)
    project.hook(base + 0x35, LoadHFromHL(base + 0x36), length=1)
    project.hook(base + 0x36, CopyRegister("l", "a", base + 0x37), length=1)
    project.hook(base + 0x37, JpHLRecordTarget(SENTINEL), length=1)

    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _setup(state, values, native=False, command=command)
    state.globals["dispatch_target"] = claripy.BVV(0, 16)
    state.regs.sp = STACK
    manager = project.factory.simulation_manager(state)
    manager.explore(find=SENTINEL, num_find=1)
    assert not manager.errored, manager.errored
    assert len(manager.found) == 1, len(manager.found)
    return [_endpoint(final, native=False) for final in manager.found]


def _native(values: dict[str, claripy.ast.BV], command: int) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_text_command_processor")
    assert function is not None
    for command_value, symbol_name in HANDLER_SYMBOLS.items():
        target = HANDLER_TARGETS[command_value]
        symbol = project.loader.find_symbol(symbol_name)
        assert symbol is not None
        project.hook(symbol.rebased_addr, NativeBoundary(target))
    far = project.loader.find_symbol("port_text_command_far")
    sound = project.loader.find_symbol("port_text_command_sound")
    assert far is not None and sound is not None
    project.hook(far.rebased_addr, NativeBoundary(0x1CA3))
    project.hook(sound.rebased_addr, NativeBoundary(0x1C31))

    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, values, native=True, command=command)
    state.memory.store(NATIVE_STATE + 6, values["h"])
    state.memory.store(NATIVE_STATE + 7, values["l"])
    state.globals["dispatch_target"] = claripy.BVV(0, 16)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=SENTINEL, num_find=1)
    terminals = [*manager.found, *manager.deadended]
    assert not manager.errored, manager.errored
    assert len(terminals) == 1, len(terminals)
    return [_endpoint(final, native=True) for final in terminals]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(
    not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`"
)
@pytest.mark.parametrize(
    "command",
    (TX_END, TX_FAR, TX_SOUND_POKEDEX_RATING, *HANDLER_TARGETS),
    ids=lambda value: f"{value:#04x}",
)
def test_text_command_processor_pathwise_equivalence(command: int) -> None:
    values = _inputs(f"text_command_processor_{command:#04x}")
    assert_pathwise_equivalent(
        _assembly(values, command),
        _native(values, command),
        ("dispatch_target", "ldf", "clear", "text_dest"),
    )
