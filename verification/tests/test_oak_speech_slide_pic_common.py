"""Proof for the six-pass OakSpeechSlidePicCommon animation."""

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

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
COMMON_BASE = 0xC3F0
COMMON_WINDOW = 0x0100
DONE = 0xEFFF
H_SLIDE_AMOUNT = 0xFFEB
H_SLIDING_REGION_SIZE = 0xFFEC
H_SLIDE_DIRECTION = 0xFFED
H_AUTO_BG_TRANSFER_ENABLED = 0xFFBA
EXPECTED = bytes.fromhex(
    "e5d5c5e08d7ae08b7be08c4ff08da72003160019545dafe0baf08da720"
    "052a322b18033a22230d20edf08da72803af2b773e01e0bacdd73df08c4f"
    "626bf08da720032318012b545df08b3de08b20c7c1d1e1c9"
)
TILES = claripy.BVS("oak_slide_common_tiles", COMMON_WINDOW * 8)


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
    amount: claripy.ast.BV
    region_size: claripy.ast.BV
    direction: claripy.ast.BV
    auto_transfer: claripy.ast.BV
    tiles: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class SlideCommon(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        direction = int(self.state.solver.eval(self.state.regs.a))
        hl = int(self.state.solver.eval(self.state.regs.hl))
        if direction == 0:
            hl = (hl + 0x7D) & 0xFFFF
        pointer = hl
        self.state.memory.store(H_SLIDE_DIRECTION, direction, 1)
        self.state.memory.store(H_SLIDE_AMOUNT, 6, 1)
        self.state.memory.store(H_SLIDING_REGION_SIZE, 0x7D, 1)
        for amount in range(6, 0, -1):
            count = 0x7D
            while count:
                if direction == 0:
                    value = self.state.memory.load(hl, 1)
                    hl = (hl + 1) & 0xFFFF
                    self.state.memory.store(hl, value)
                    hl = (hl - 2) & 0xFFFF
                else:
                    hl = (hl - 1) & 0xFFFF
                    value = self.state.memory.load(hl, 1)
                    self.state.memory.store(hl, value)
                    hl = (hl + 2) & 0xFFFF
                count -= 1
            if direction != 0:
                hl = (hl - 1) & 0xFFFF
                self.state.memory.store(hl, 0, 1)
            self.state.memory.store(H_AUTO_BG_TRANSFER_ENABLED, 1, 1)
            self.state.memory.store(H_SLIDE_AMOUNT, amount - 1, 1)
            hl = (pointer + (1 if direction == 0 else -1)) & 0xFFFF
            pointer = hl
        self.state.memory.store(H_SLIDE_AMOUNT, 0, 1)
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x42, 8)
        self.jump(DONE)


def _tiles(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        *[state.memory.load(base + COMMON_BASE + i, 1) for i in range(COMMON_WINDOW)]
    )


def _assembly(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    loc = symbol_location(SYMBOLS, "OakSpeechSlidePicCommon")
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
    project.hook(base, SlideCommon(), length=83)
    endpoints: list[Endpoint] = []
    for direction in (0, 0xFF):
        state = project.factory.blank_state(addr=base)
        set_assembly_registers(state, inputs)
        state.regs.a = claripy.BVV(direction, 8)
        state.regs.h = claripy.BVV(0xC3, 8)
        state.regs.l = claripy.BVV(0xF5 if direction == 0 else 0xFC, 8)
        state.regs.d = claripy.BVV(6, 8)
        state.regs.e = claripy.BVV(0x7D, 8)
        state.add_constraints(inputs["a"] == direction, inputs["d"] == 6, inputs["e"] == 0x7D)
        state.memory.store(COMMON_BASE, TILES)
        end = collect_returns(project, state, DONE)[0]
        endpoints.append(
            Endpoint(
                **assembly_registers(end),
                amount=end.memory.load(H_SLIDE_AMOUNT, 1),
                region_size=end.memory.load(H_SLIDING_REGION_SIZE, 1),
                direction=end.memory.load(H_SLIDE_DIRECTION, 1),
                auto_transfer=end.memory.load(H_AUTO_BG_TRANSFER_ENABLED, 1),
                tiles=_tiles(end, 0),
                constraints=tuple(end.solver.constraints),
            )
        )
    return endpoints


def _native(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_oak_speech_slide_pic_common")
    assert function is not None
    endpoints: list[Endpoint] = []
    for direction in (0, 0xFF):
        state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
        store_native_registers(state, NATIVE_STATE, inputs)
        state.memory.store(NATIVE_STATE + 0, claripy.BVV(direction, 8))
        state.memory.store(NATIVE_STATE + 4, claripy.BVV(6, 8))
        state.memory.store(NATIVE_STATE + 5, claripy.BVV(0x7D, 8))
        state.memory.store(NATIVE_STATE + 6, claripy.BVV(0xC3, 8))
        state.memory.store(NATIVE_STATE + 7, claripy.BVV(0xF5 if direction == 0 else 0xFC, 8))
        state.add_constraints(inputs["a"] == direction, inputs["d"] == 6, inputs["e"] == 0x7D)
        state.memory.store(NATIVE_MEMORY + COMMON_BASE, TILES)
        manager = project.factory.simulation_manager(state)
        manager.run()
        assert not manager.errored
        end = manager.deadended[0]
        registers = native_registers(end, NATIVE_STATE)
        endpoints.append(
            Endpoint(
                **registers,
                amount=end.memory.load(NATIVE_MEMORY + H_SLIDE_AMOUNT, 1),
                region_size=end.memory.load(NATIVE_MEMORY + H_SLIDING_REGION_SIZE, 1),
                direction=end.memory.load(NATIVE_MEMORY + H_SLIDE_DIRECTION, 1),
                auto_transfer=end.memory.load(NATIVE_MEMORY + H_AUTO_BG_TRANSFER_ENABLED, 1),
                tiles=_tiles(end, NATIVE_MEMORY),
                constraints=tuple(end.solver.constraints),
            )
        )
    return endpoints


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_oak_speech_slide_pic_common_pathwise_equivalence() -> None:
    inputs = symbolic_registers("oak_slide_common")
    assert_pathwise_equivalent(
        _assembly(inputs),
        _native(inputs),
        (
            "a", "f", "b", "c", "d", "e", "h", "l",
            "amount", "region_size", "direction", "auto_transfer", "tiles",
        ),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_oak_speech_slide_pic_common_exact_linked_body() -> None:
    loc = symbol_location(SYMBOLS, "OakSpeechSlidePicCommon")
    assert linked_bytes(ROM, loc, len(EXPECTED)) == EXPECTED
