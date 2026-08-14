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
    Sm83StoreAAtHlIncrement,
    Sm83StoreAHighImmediate,
    Sm83StoreAImmediate,
)


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification" / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
GB_STACK = 0xD000
GB_RETURN = 0xFFFF
NATIVE_STATE = 0x100000

# Absolute addresses (verified against pokered.sym).
H_WY = 0xFFB0
R_WY = 0xFF4A
H_AUTO_BG = 0xFFBA
H_JOY_PRESSED = 0xFFB3
H_JOY_RELEASED = 0xFFB2
H_JOY_HELD = 0xFFB4
W_STEP_COUNTER = 0xD13B
W_LONE_ATTACK_NO = 0xD05C
W_ACTION_RESULT = 0xCD6A
W_UNUSED_MAP = 0xD5A3
W_CARD_KEY_DOOR_Y = 0xD73F
W_WHICH_TRADE = 0xCD3D
W_STANDING_ON_WARP = 0xCD5B
FILL_LEN = W_STANDING_ON_WARP - W_WHICH_TRADE  # 0x1e


class StoreAAtHl(angr.SimProcedure):
    """Model SM83 ``LD [HL], A`` (opcode 77)."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(self.state.regs.hl, self.state.regs.a)
        self.jump(self._next_address)


class FillMemoryInline(angr.SimProcedure):
    """Model ``call FillMemory``: zero ``BC`` bytes at ``[HL]`` and leave
    A=0, F=Z, BC=0 and HL advanced; DE is preserved (mirrors port_fill_memory)."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        st = self.state
        hl = (int(st.solver.eval(st.regs.h)) << 8) | int(st.solver.eval(st.regs.l))
        bc = (int(st.solver.eval(st.regs.b)) << 8) | int(st.solver.eval(st.regs.c))
        fill = int(st.solver.eval(st.regs.a))
        for i in range(bc):
            st.memory.store(hl + i, claripy.BVV(fill, 8))
        hl = (hl + bc) & 0xFFFF
        st.regs.h = claripy.BVV((hl >> 8) & 0xFF, 8)
        st.regs.l = claripy.BVV(hl & 0xFF, 8)
        st.regs.b = claripy.BVV(0, 8)
        st.regs.c = claripy.BVV(0, 8)
        st.regs.a = claripy.BVV(0, 8)
        st.regs.f = claripy.BVV(0x40, 8)  # Z80-layout Z
        self.jump(self._next_address)


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
    h_wy: claripy.ast.BV
    r_wy: claripy.ast.BV
    h_auto_bg: claripy.ast.BV
    w_step_counter: claripy.ast.BV
    w_lone_attack_no: claripy.ast.BV
    h_joy_pressed: claripy.ast.BV
    h_joy_released: claripy.ast.BV
    h_joy_held: claripy.ast.BV
    w_action_result: claripy.ast.BV
    w_unused_map: claripy.ast.BV
    w_card_key_door_y: claripy.ast.BV
    fill_region: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _assembly_endpoint(
    inputs: dict[str, claripy.ast.BV],
) -> Endpoint:
    location = symbol_location(SYMBOLS, "ClearVariablesOnEnterMap")
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
    base = location.address
    # Store hooks (SM83-specific opcodes only); offsets verified from the asm.
    project.hook(base + 0x02, Sm83StoreAHighImmediate(0xB0, base + 0x04), length=2)  # hWY
    project.hook(base + 0x04, Sm83StoreAHighImmediate(0x4A, base + 0x06), length=2)  # rWY
    project.hook(base + 0x07, Sm83StoreAHighImmediate(0xBA, base + 0x09), length=2)  # hAutoBG
    project.hook(base + 0x09, Sm83StoreAImmediate(W_STEP_COUNTER, base + 0x0C), length=3)
    project.hook(base + 0x0C, Sm83StoreAImmediate(W_LONE_ATTACK_NO, base + 0x0F), length=3)
    project.hook(base + 0x0F, Sm83StoreAHighImmediate(0xB3, base + 0x11), length=2)  # hJoyPressed
    project.hook(base + 0x11, Sm83StoreAHighImmediate(0xB2, base + 0x13), length=2)  # hJoyReleased
    project.hook(base + 0x13, Sm83StoreAHighImmediate(0xB4, base + 0x15), length=2)  # hJoyHeld
    project.hook(base + 0x15, Sm83StoreAImmediate(W_ACTION_RESULT, base + 0x18), length=3)
    project.hook(base + 0x18, Sm83StoreAImmediate(W_UNUSED_MAP, base + 0x1B), length=3)
    project.hook(base + 0x1E, Sm83StoreAAtHlIncrement(base + 0x1F), length=1)  # ld [hli],a
    project.hook(base + 0x1F, StoreAAtHl(base + 0x20), length=1)  # ld [hl],a
    project.hook(base + 0x26, FillMemoryInline(base + 0x29), length=3)  # call FillMemory
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, inputs)
    state.regs.sp = claripy.BVV(GB_STACK, 16)
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    assert len(returned) == 1
    end = returned[0]
    return Endpoint(
        **assembly_registers(end),
        h_wy=end.memory.load(H_WY, 1),
        r_wy=end.memory.load(R_WY, 1),
        h_auto_bg=end.memory.load(H_AUTO_BG, 1),
        w_step_counter=end.memory.load(W_STEP_COUNTER, 1),
        w_lone_attack_no=end.memory.load(W_LONE_ATTACK_NO, 1),
        h_joy_pressed=end.memory.load(H_JOY_PRESSED, 1),
        h_joy_released=end.memory.load(H_JOY_RELEASED, 1),
        h_joy_held=end.memory.load(H_JOY_HELD, 1),
        w_action_result=end.memory.load(W_ACTION_RESULT, 1),
        w_unused_map=end.memory.load(W_UNUSED_MAP, 1),
        w_card_key_door_y=end.memory.load(W_CARD_KEY_DOOR_Y, 2),
        fill_region=end.memory.load(W_WHICH_TRADE, FILL_LEN),
        constraints=tuple(end.solver.constraints),
    )


def _native_endpoint(
    inputs: dict[str, claripy.ast.BV],
) -> Endpoint:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_clear_variables_on_enter_map")
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, claripy.BVV(0, 64)
    )
    store_native_registers(state, NATIVE_STATE, inputs)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    end = manager.deadended[0]
    return Endpoint(
        **native_registers(end, NATIVE_STATE),
        h_wy=end.memory.load(H_WY, 1),
        r_wy=end.memory.load(R_WY, 1),
        h_auto_bg=end.memory.load(H_AUTO_BG, 1),
        w_step_counter=end.memory.load(W_STEP_COUNTER, 1),
        w_lone_attack_no=end.memory.load(W_LONE_ATTACK_NO, 1),
        h_joy_pressed=end.memory.load(H_JOY_PRESSED, 1),
        h_joy_released=end.memory.load(H_JOY_RELEASED, 1),
        h_joy_held=end.memory.load(H_JOY_HELD, 1),
        w_action_result=end.memory.load(W_ACTION_RESULT, 1),
        w_unused_map=end.memory.load(W_UNUSED_MAP, 1),
        w_card_key_door_y=end.memory.load(W_CARD_KEY_DOOR_Y, 2),
        fill_region=end.memory.load(W_WHICH_TRADE, FILL_LEN),
        constraints=tuple(end.solver.constraints),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_clear_variables_on_enter_map_symbolic_equivalence() -> None:
    inputs = symbolic_registers("cv")
    assembly = _assembly_endpoint(inputs)
    native = _native_endpoint(inputs)
    assert_pathwise_equivalent(
        [assembly],
        [native],
        (
            "a",
            "f",
            "b",
            "c",
            "d",
            "e",
            "h",
            "l",
            "h_wy",
            "r_wy",
            "h_auto_bg",
            "w_step_counter",
            "w_lone_attack_no",
            "h_joy_pressed",
            "h_joy_released",
            "h_joy_held",
            "w_action_result",
            "w_unused_map",
            "w_card_key_door_y",
            "fill_region",
        ),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_clear_variables_on_enter_map_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "ClearVariablesOnEnterMap")
    expected = bytes.fromhex(
        "3e90e0b0e04aafe0baea3bd1ea5cd0e0b3e0b2e0b4ea6acdeaa3d5213fd72277213dcd011e00cde036c9"
    )
    assert linked_bytes(ROM, location, len(expected)) == expected
