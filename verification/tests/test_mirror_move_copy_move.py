from __future__ import annotations

from dataclasses import dataclass
from functools import cache
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
    sm83_flags_to_z80,
    symbol_location,
)
from verification.harness.sm83_shims import (
    Sm83CpImmediate,
    Sm83LoadAHighImmediate,
    Sm83LoadAImmediate,
)


ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xE000
RETURN = 0xFFFF
H_WHOSE_TURN = 0xFFF3
W_PLAYER_SELECTED_MOVE = 0xCCDC
W_ENEMY_SELECTED_MOVE = 0xCCDD
W_PLAYER_USED_MOVE = 0xCCF1
W_ENEMY_USED_MOVE = 0xCCF2
W_TEXT_BOX_ID = 0xD125
MEMORY_MARKER = 0xD300
EXPECTED = bytes.fromhex(
    "f0f3a7faf2cc21dccc11d2cf2809faf1cc11cccf21ddcc77fe772803a7200d"
    "212463cd493cafc9"
)
TOP_FIELDS = (
    "requested_bank",
    "loaded_bank",
    "rom_bank",
    "name_list_index",
    "name_list_type",
    "predef_bank",
    "named_object_index",
    "swap_temp",
    "swap_temp_plus1",
    "unused_pointer_low",
    "unused_pointer_high",
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
    state: claripy.ast.BV
    memory: claripy.ast.BV
    print_call: claripy.ast.BV
    reload_call: claripy.ast.BV
    trace: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _capture_assembly_registers(state: angr.SimState) -> claripy.ast.BV:
    registers = assembly_registers(state)
    return claripy.Concat(*(registers[name] for name in REGISTERS))


def _assembly_top_state(state: angr.SimState) -> claripy.ast.BV:
    return claripy.Concat(
        _capture_assembly_registers(state),
        *(state.globals[field] for field in TOP_FIELDS),
        *(state.globals[f"saved_{name}"] for name in REGISTERS),
        state.globals["saved_bank"],
    )


class AndA(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x50, 8),
            claripy.BVV(0x10, 8),
        )
        self.jump(self._continuation)


class StoreAtHl(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(self.state.regs.hl, self.state.regs.a)
        self.jump(self._continuation)


class XorA(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = 0
        self.state.regs.f = 0x40
        self.jump(self._continuation)


class AssemblyPrintText(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["print_call"] = _capture_assembly_registers(self.state)
        self.state.globals["trace"] = claripy.BVV(2, 8)
        self.state.memory.store(W_TEXT_BOX_ID, claripy.BVV(1, 8))
        self.state.regs.b = 0xC4
        self.state.regs.c = 0xB9
        self.jump(self._continuation)


class NativePrintText(angr.SimProcedure):
    def run(
        self, registers: claripy.ast.BV, memory: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        assert not memory.symbolic and self.state.solver.eval(memory) == NATIVE_MEMORY
        self.state.globals["print_call"] = self.state.memory.load(registers, 8)
        self.state.globals["trace"] = claripy.BVV(2, 8)
        self.state.memory.store(memory + W_TEXT_BOX_ID, claripy.BVV(1, 8))
        self.state.memory.store(registers + 2, claripy.BVV(0xC4B9, 16))


class AssemblyReloadMoveData(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.globals["reload_call"] = _assembly_top_state(self.state)
        self.state.globals["trace"] = claripy.BVV(1, 8)
        for offset, name in enumerate(REGISTERS):
            value = self.state.globals[f"reload_out_{offset}"]
            if name == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, name, value)
        for offset, field in enumerate(TOP_FIELDS, 8):
            self.state.globals[field] = self.state.globals[f"reload_out_{offset}"]
        for offset, name in enumerate(REGISTERS, 19):
            self.state.globals[f"saved_{name}"] = self.state.globals[
                f"reload_out_{offset}"
            ]
        self.state.globals["saved_bank"] = self.state.globals["reload_out_27"]
        self.state.memory.store(
            MEMORY_MARKER, self.state.globals["reload_memory_out"]
        )
        self.jump(RETURN)


class NativeReloadMoveData(angr.SimProcedure):
    def run(
        self, state_address: claripy.ast.BV, memory: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        assert not memory.symbolic and self.state.solver.eval(memory) == NATIVE_MEMORY
        self.state.globals["reload_call"] = self.state.memory.load(state_address, 28)
        self.state.globals["trace"] = claripy.BVV(1, 8)
        for offset in range(28):
            self.state.memory.store(
                state_address + offset, self.state.globals[f"reload_out_{offset}"]
            )
        self.state.memory.store(
            memory + MEMORY_MARKER, self.state.globals["reload_memory_out"]
        )


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for field in TOP_FIELDS:
        values[field] = claripy.BVS(f"{prefix}_{field}", 8)
    saved = symbolic_registers(f"{prefix}_saved")
    for name in REGISTERS:
        values[f"saved_{name}"] = saved[name]
    values["saved_bank"] = claripy.BVS(f"{prefix}_saved_bank", 8)
    for offset in range(28):
        values[f"reload_out_{offset}"] = claripy.BVS(
            f"{prefix}_reload_out_{offset}", 8
        )
    values["reload_out_1"] = claripy.Concat(
        claripy.BVS(f"{prefix}_reload_out_flags", 4), claripy.BVV(0, 4)
    )
    for name in (
        "used_move",
        "other_used_move",
        "player_selected",
        "enemy_selected",
        "text_box",
        "memory_marker",
        "reload_memory_out",
    ):
        values[name] = claripy.BVS(f"{prefix}_{name}", 8)
    return values


def _setup(
    state: angr.SimState,
    values: dict[str, claripy.ast.BV],
    turn: int,
    native: bool,
) -> None:
    memory_base = NATIVE_MEMORY if native else 0
    for field in TOP_FIELDS:
        state.globals[field] = values[field]
    for name in REGISTERS:
        state.globals[f"saved_{name}"] = values[f"saved_{name}"]
    state.globals["saved_bank"] = values["saved_bank"]
    for offset in range(28):
        state.globals[f"reload_out_{offset}"] = values[f"reload_out_{offset}"]
    state.globals["reload_memory_out"] = values["reload_memory_out"]
    state.globals["print_call"] = claripy.BVV(0, 64)
    state.globals["reload_call"] = claripy.BVV(0, 224)
    state.globals["trace"] = claripy.BVV(0, 8)
    state.memory.store(memory_base + H_WHOSE_TURN, claripy.BVV(turn, 8))
    if turn == 0:
        state.memory.store(memory_base + W_ENEMY_USED_MOVE, values["used_move"])
        state.memory.store(
            memory_base + W_PLAYER_USED_MOVE, values["other_used_move"]
        )
    else:
        state.memory.store(memory_base + W_PLAYER_USED_MOVE, values["used_move"])
        state.memory.store(
            memory_base + W_ENEMY_USED_MOVE, values["other_used_move"]
        )
    state.memory.store(
        memory_base + W_PLAYER_SELECTED_MOVE, values["player_selected"]
    )
    state.memory.store(
        memory_base + W_ENEMY_SELECTED_MOVE, values["enemy_selected"]
    )
    state.memory.store(memory_base + W_TEXT_BOX_ID, values["text_box"])
    state.memory.store(memory_base + MEMORY_MARKER, values["memory_marker"])


def _endpoint(state: angr.SimState, native: bool) -> Endpoint:
    memory_base = NATIVE_MEMORY if native else 0
    registers = (
        native_registers(state, NATIVE_STATE)
        if native
        else assembly_registers(state)
    )
    top_state = (
        state.memory.load(NATIVE_STATE + 8, 20)
        if native
        else _assembly_top_state(state)[159:0]
    )
    return Endpoint(
        **registers,
        state=top_state,
        memory=claripy.Concat(
            state.memory.load(memory_base + W_PLAYER_SELECTED_MOVE, 1),
            state.memory.load(memory_base + W_ENEMY_SELECTED_MOVE, 1),
            state.memory.load(memory_base + W_TEXT_BOX_ID, 1),
            state.memory.load(memory_base + MEMORY_MARKER, 1),
        ),
        print_call=state.globals["print_call"],
        reload_call=state.globals["reload_call"],
        trace=state.globals["trace"],
        constraints=tuple(state.solver.constraints),
    )


@cache
def _assembly_project() -> tuple[angr.Project, int]:
    location = symbol_location(SYMS, "MirrorMoveCopyMove")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
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
    project.hook(base, Sm83LoadAHighImmediate(0xF3, base + 2), length=2)
    project.hook(base + 2, AndA(base + 3), length=1)
    project.hook(
        base + 3, Sm83LoadAImmediate(W_ENEMY_USED_MOVE, base + 6), length=3
    )
    project.hook(
        base + 14, Sm83LoadAImmediate(W_PLAYER_USED_MOVE, base + 17), length=3
    )
    project.hook(base + 23, StoreAtHl(base + 24), length=1)
    project.hook(base + 24, Sm83CpImmediate(0x77, base + 26), length=2)
    project.hook(base + 28, AndA(base + 29), length=1)
    project.hook(base + 34, AssemblyPrintText(base + 37), length=3)
    project.hook(base + 37, XorA(base + 38), length=1)
    project.hook(base + 44, AssemblyReloadMoveData(), length=1)
    return project, base


@cache
def _native_project() -> tuple[angr.Project, int]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_mirror_move_copy_move")
    print_text = project.loader.find_symbol("port_print_text")
    reload_move = project.loader.find_symbol("port_reload_move_data")
    assert function is not None and print_text is not None and reload_move is not None
    project.hook(print_text.rebased_addr, NativePrintText())
    project.hook(reload_move.rebased_addr, NativeReloadMoveData())
    return project, function.rebased_addr


def _assembly(values: dict[str, claripy.ast.BV], turn: int) -> list[Endpoint]:
    project, base = _assembly_project()
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _setup(state, values, turn, False)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    return [_endpoint(end, False) for end in collect_returns(project, state, RETURN)]


def _native(values: dict[str, claripy.ast.BV], turn: int) -> list[Endpoint]:
    project, function = _native_project()
    state = project.factory.call_state(function, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    for offset, field in enumerate(TOP_FIELDS, 8):
        state.memory.store(NATIVE_STATE + offset, values[field])
    for offset, name in enumerate(REGISTERS, 19):
        state.memory.store(NATIVE_STATE + offset, values[f"saved_{name}"])
    state.memory.store(NATIVE_STATE + 27, values["saved_bank"])
    _setup(state, values, turn, True)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [_endpoint(end, True) for end in manager.deadended]


@pytest.mark.skipif(
    not ELF.exists() or not ROM.exists() or not SYMS.exists(), reason="build"
)
@pytest.mark.parametrize("turn", (0, 1), ids=("player", "enemy"))
def test_mirror_move_copy_move_pathwise_equivalence(turn: int) -> None:
    values = _inputs(f"mirror_move_{turn}")
    assert_pathwise_equivalent(
        _assembly(values, turn),
        _native(values, turn),
        (
            *REGISTERS,
            "state",
            "memory",
            "print_call",
            "reload_call",
            "trace",
        ),
    )
