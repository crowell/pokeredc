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


ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xE000
RETURN = 0xFFFF
W_IS_IN_BATTLE = 0xD057
W_CUR_MAP = 0xD35E
W_NUM_BAG_ITEMS = 0xD31D
H_WHOSE_TURN = 0xFFF3
W_BATTLE_MON_STATUS = 0xD018
W_TEXT_BOX_ID = 0xD125
BAG_SIZE = 17
EXPECTED = bytes.fromhex(
    "cd3a58c0f0f3a7200efa18d0e627c0213058cd493cafc9213558cd493cafc9"
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
    ghost_call: claripy.ast.BV
    print_call: claripy.ast.BV
    trace: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _register_bytes(state: angr.SimState) -> claripy.ast.BV:
    registers = assembly_registers(state)
    return claripy.Concat(*(registers[name] for name in REGISTERS))


def _ghost_memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        state.memory.load(base + W_IS_IN_BATTLE, 1),
        state.memory.load(base + W_CUR_MAP, 1),
        state.memory.load(base + W_NUM_BAG_ITEMS, BAG_SIZE),
    )


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        _ghost_memory(state, base),
        state.memory.load(base + H_WHOSE_TURN, 1),
        state.memory.load(base + W_BATTLE_MON_STATUS, 1),
        state.memory.load(base + W_TEXT_BOX_ID, 1),
    )


class AssemblyGhost(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["ghost_call"] = claripy.Concat(
            _register_bytes(self.state), _ghost_memory(self.state, 0)
        )
        self.state.globals["trace"] = self.state.globals["trace"] * 16 + 1
        for offset, name in enumerate(REGISTERS):
            value = self.state.globals[f"ghost_out_{offset}"]
            if name == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, name, value)
        for offset in range(19):
            self.state.memory.store(
                self.state.globals[f"ghost_address_{offset}"],
                self.state.globals[f"ghost_memory_out_{offset}"],
            )
        self.jump(self._continuation)


class NativeGhost(angr.SimProcedure):
    def run(
        self, address: claripy.ast.BV, memory: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        assert not memory.symbolic and self.state.solver.eval(memory) == NATIVE_MEMORY
        self.state.globals["ghost_call"] = claripy.Concat(
            self.state.memory.load(address, 8),
            _ghost_memory(self.state, NATIVE_MEMORY),
        )
        self.state.globals["trace"] = self.state.globals["trace"] * 16 + 1
        for offset in range(8):
            self.state.memory.store(
                address + offset, self.state.globals[f"ghost_out_{offset}"]
            )
        for offset in range(19):
            relative = self.state.globals[f"ghost_address_{offset}"]
            self.state.memory.store(
                memory + relative,
                self.state.globals[f"ghost_memory_out_{offset}"],
            )


class LoadAbsolute(angr.SimProcedure):
    def __init__(self, address: int, continuation: int) -> None:
        super().__init__()
        self._address = address
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self._address, 1)
        self.jump(self._continuation)


class AndImmediate(angr.SimProcedure):
    def __init__(self, value: int, continuation: int) -> None:
        super().__init__()
        self._value = value
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a &= self._value
        self.state.regs.f = claripy.BVV(0x10, 8) | claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x40, 8),
            claripy.BVV(0, 8),
        )
        self.jump(self._continuation)


class AssemblyPrint(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["print_call"] = _register_bytes(self.state)
        self.state.globals["trace"] = self.state.globals["trace"] * 16 + 2
        self.state.memory.store(W_TEXT_BOX_ID, claripy.BVV(1, 8))
        self.state.regs.b = 0xC4
        self.state.regs.c = 0xB9
        self.jump(self._continuation)


class NativePrint(angr.SimProcedure):
    def run(
        self, address: claripy.ast.BV, memory: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        assert not memory.symbolic and self.state.solver.eval(memory) == NATIVE_MEMORY
        self.state.globals["print_call"] = self.state.memory.load(address, 8)
        self.state.globals["trace"] = self.state.globals["trace"] * 16 + 2
        self.state.memory.store(address + 2, claripy.BVV(0xC4B9, 16))
        self.state.memory.store(memory + W_TEXT_BOX_ID, claripy.BVV(1, 8))


class XorA(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = 0
        self.state.regs.f = 0x40
        self.jump(self._continuation)


def _ghost_addresses() -> tuple[int, ...]:
    return (
        W_IS_IN_BATTLE,
        W_CUR_MAP,
        *(W_NUM_BAG_ITEMS + offset for offset in range(BAG_SIZE)),
    )


def _inputs() -> dict[str, claripy.ast.BV]:
    values = symbolic_registers("print_ghost_text")
    for name in ("is_in_battle", "cur_map", "whose_turn", "status", "textbox"):
        values[name] = claripy.BVS(f"print_ghost_text_{name}", 8)
    for offset in range(BAG_SIZE):
        values[f"bag_{offset}"] = claripy.BVS(
            f"print_ghost_text_bag_{offset}", 8
        )
    values["bag_15"] = claripy.BVV(0xFF, 8)
    for offset in range(8):
        values[f"ghost_out_{offset}"] = claripy.BVS(
            f"print_ghost_text_ghost_out_{offset}", 8
        )
    values["ghost_out_1"] = claripy.Concat(
        claripy.BVS("print_ghost_text_ghost_flags", 4), claripy.BVV(0, 4)
    )
    for offset in range(19):
        values[f"ghost_memory_out_{offset}"] = claripy.BVS(
            f"print_ghost_text_ghost_memory_out_{offset}", 8
        )
    return values


def _setup(
    state: angr.SimState, values: dict[str, claripy.ast.BV], native: bool
) -> None:
    base = NATIVE_MEMORY if native else 0
    state.memory.store(base + W_IS_IN_BATTLE, values["is_in_battle"])
    state.memory.store(base + W_CUR_MAP, values["cur_map"])
    for offset in range(BAG_SIZE):
        state.memory.store(
            base + W_NUM_BAG_ITEMS + offset, values[f"bag_{offset}"]
        )
    state.memory.store(base + H_WHOSE_TURN, values["whose_turn"])
    state.memory.store(base + W_BATTLE_MON_STATUS, values["status"])
    state.memory.store(base + W_TEXT_BOX_ID, values["textbox"])
    for offset in range(8):
        state.globals[f"ghost_out_{offset}"] = values[f"ghost_out_{offset}"]
    for offset, address in enumerate(_ghost_addresses()):
        state.globals[f"ghost_address_{offset}"] = address
        state.globals[f"ghost_memory_out_{offset}"] = values[
            f"ghost_memory_out_{offset}"
        ]
    state.globals["ghost_call"] = claripy.BVV(0, 216)
    state.globals["print_call"] = claripy.BVV(0, 64)
    state.globals["trace"] = claripy.BVV(0, 16)


def _endpoint(state: angr.SimState, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    registers = (
        native_registers(state, NATIVE_STATE)
        if native
        else assembly_registers(state)
    )
    return Endpoint(
        **registers,
        memory=_memory(state, base),
        ghost_call=state.globals["ghost_call"],
        print_call=state.globals["print_call"],
        trace=state.globals["trace"],
        constraints=tuple(state.solver.constraints),
    )


@cache
def _assembly_project() -> tuple[angr.Project, int]:
    location = symbol_location(SYMS, "PrintGhostText")
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
    project.hook(base, AssemblyGhost(base + 3), length=3)
    project.hook(base + 4, LoadAbsolute(H_WHOSE_TURN, base + 6), length=2)
    project.hook(base + 6, AndImmediate(0xFF, base + 7), length=1)
    project.hook(base + 9, LoadAbsolute(W_BATTLE_MON_STATUS, base + 12), length=3)
    project.hook(base + 12, AndImmediate(0x47, base + 14), length=2)
    project.hook(base + 18, AssemblyPrint(base + 21), length=3)
    project.hook(base + 21, XorA(base + 22), length=1)
    project.hook(base + 26, AssemblyPrint(base + 29), length=3)
    project.hook(base + 29, XorA(base + 30), length=1)
    return project, base


@cache
def _native_project() -> tuple[angr.Project, int]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_print_ghost_text")
    ghost = project.loader.find_symbol("port_is_ghost_battle_complete")
    print_text = project.loader.find_symbol("port_print_text")
    assert function is not None and ghost is not None and print_text is not None
    project.hook(ghost.rebased_addr, NativeGhost())
    project.hook(print_text.rebased_addr, NativePrint())
    return project, function.rebased_addr


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, base = _assembly_project()
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _setup(state, values, False)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    return [_endpoint(end, False) for end in collect_returns(project, state, RETURN)]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, function = _native_project()
    state = project.factory.call_state(function, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, values, True)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [_endpoint(end, True) for end in manager.deadended]


@pytest.mark.skipif(
    not ELF.exists() or not ROM.exists() or not SYMS.exists(), reason="build"
)
def test_print_ghost_text_pathwise_equivalence() -> None:
    location = symbol_location(SYMS, "PrintGhostText")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    values = _inputs()
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "memory", "ghost_call", "print_call", "trace"),
    )
