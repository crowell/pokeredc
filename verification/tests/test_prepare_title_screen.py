"""Path-equivalence proof for the deterministic title-screen preparation leaf."""

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
from verification.harness.rom import collect_returns, linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import (
    Sm83StoreAAtHlIncrement,
    Sm83StoreAHighImmediate,
    Sm83StoreAImmediate,
    Sm83XorA,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xFFFF
NAME_LENGTH = 11
DEBUG_PLAYER = 0x45AA
DEBUG_RIVAL = 0x45B1
PLAYER_NAME = 0xD158
RIVAL_NAME = 0xD34A
H_WY = 0xFFB0
LETTER_DELAY = 0xD358
STATUS_FLAGS6 = 0xD732
AUDIO_BANK = 0xC0EF
AUDIO_SAVED_BANK = 0xC0F0
TITLE_BANK = 0x1F
EXPECTED = bytes.fromhex(
    "21aa451158d1cdb14221b145114ad3cdb142afe0b0ea58d3"
    "2132d72222773e1feaefc0eaf0c0"
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
    memory: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class CopyDebugNameCall(angr.SimProcedure):
    """Model the proven CopyDebugName body and return through the call stack."""

    def run(self) -> None:  # type: ignore[override]
        source = self.state.regs.hl
        destination = self.state.regs.de
        for offset in range(NAME_LENGTH):
            self.state.memory.store(
                destination + offset,
                self.state.memory.load(source + offset, 1),
            )
        self.state.regs.hl = source + NAME_LENGTH
        self.state.regs.de = destination + NAME_LENGTH
        target = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp += 2
        self.jump(target)


class PrepareTitleBoundary(angr.SimProcedure):
    """The routine falls through into DisplayTitleScreen after its setup."""

    def run(self) -> None:  # type: ignore[override]
        self.jump(RETURN)

def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        state.memory.load(base + PLAYER_NAME, NAME_LENGTH),
        state.memory.load(base + RIVAL_NAME, NAME_LENGTH),
        state.memory.load(base + H_WY, 1),
        state.memory.load(base + LETTER_DELAY, 1),
        state.memory.load(base + STATUS_FLAGS6, 3),
        state.memory.load(base + AUDIO_BANK, 1),
        state.memory.load(base + AUDIO_SAVED_BANK, 1),
    )


def _assembly(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    loc = symbol_location(SYMBOLS, "PrepareTitleScreen")
    base = loc.address
    project = angr.Project(
        rom_window(ROM, loc.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": base,
        },
    )
    project.hook(base + 0x26, PrepareTitleBoundary(), length=1)
    project.hook(base - 6, CopyDebugNameCall(), length=6)
    project.hook(base + 0x12, Sm83XorA(base + 0x13), length=1)
    project.hook(base + 0x13, Sm83StoreAHighImmediate(0xB0, base + 0x15), length=2)
    project.hook(base + 0x15, Sm83StoreAImmediate(LETTER_DELAY, base + 0x18), length=3)
    project.hook(base + 0x1B, Sm83StoreAAtHlIncrement(base + 0x1C), length=1)
    project.hook(base + 0x1C, Sm83StoreAAtHlIncrement(base + 0x1D), length=1)
    project.hook(base + 0x20, Sm83StoreAImmediate(AUDIO_BANK, base + 0x23), length=3)
    project.hook(base + 0x23, Sm83StoreAImmediate(AUDIO_SAVED_BANK, base + 0x26), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, inputs)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    state.memory.store(DEBUG_PLAYER, claripy.Concat(*inputs["player_bytes"]))
    state.memory.store(DEBUG_RIVAL, claripy.Concat(*inputs["rival_bytes"]))
    returned = collect_returns(project, state, RETURN)
    return [
        Endpoint(
            **assembly_registers(end),
            memory=_memory(end, 0),
            constraints=tuple(end.solver.constraints),
        )
        for end in returned
    ]


def _native(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_prepare_title_screen")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_MEMORY + DEBUG_PLAYER, claripy.Concat(*inputs["player_bytes"]))
    state.memory.store(NATIVE_MEMORY + DEBUG_RIVAL, claripy.Concat(*inputs["rival_bytes"]))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=_memory(end, NATIVE_MEMORY),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


def _inputs() -> dict[str, claripy.ast.BV | list[claripy.ast.BV]]:
    values = symbolic_registers("prepare_title_screen")
    values["player_bytes"] = [claripy.BVS(f"prepare_player_{i}", 8) for i in range(NAME_LENGTH)]
    values["rival_bytes"] = [claripy.BVS(f"prepare_rival_{i}", 8) for i in range(NAME_LENGTH)]
    return values


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_prepare_title_screen_pathwise_equivalence() -> None:
    inputs = _inputs()
    assert_pathwise_equivalent(
        _assembly(inputs),
        _native(inputs),
        ("a", "f", "b", "c", "d", "e", "h", "l", "memory"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_prepare_title_screen_exact_linked_body() -> None:
    loc = symbol_location(SYMBOLS, "PrepareTitleScreen")
    assert linked_bytes(ROM, loc, len(EXPECTED)) == EXPECTED
