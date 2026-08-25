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
from verification.harness.sm83_shims import Sm83CpImmediate, Sm83DecRegister


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
BAG_SIZE = 17
EXPECTED = bytes.fromhex(
    "fa57d03dc0fa5ed3fe8e380afe9530060648cd9334c83e01a7c9"
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
    item_call: claripy.ast.BV
    trace: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _register_bytes(state: angr.SimState) -> claripy.ast.BV:
    registers = assembly_registers(state)
    return claripy.Concat(*(registers[name] for name in REGISTERS))


def _bag(state: angr.SimState, base: int) -> claripy.ast.BV:
    return state.memory.load(base + W_NUM_BAG_ITEMS, BAG_SIZE)


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        state.memory.load(base + W_IS_IN_BATTLE, 1),
        state.memory.load(base + W_CUR_MAP, 1),
        _bag(state, base),
    )


class LoadAbsolute(angr.SimProcedure):
    def __init__(self, address: int, continuation: int) -> None:
        super().__init__()
        self._address = address
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self._address, 1)
        self.jump(self._continuation)


class AssemblyItemInBag(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["item_call"] = claripy.Concat(
            _register_bytes(self.state), _bag(self.state, 0)
        )
        self.state.globals["trace"] = self.state.globals["trace"] * 16 + 1
        for offset, name in enumerate(REGISTERS):
            value = self.state.globals[f"item_out_{offset}"]
            if name == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, name, value)
        for offset in range(BAG_SIZE):
            self.state.memory.store(
                W_NUM_BAG_ITEMS + offset,
                self.state.globals[f"bag_out_{offset}"],
            )
        self.jump(self._continuation)


class NativeItemInBag(angr.SimProcedure):
    def run(
        self, address: claripy.ast.BV, memory: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        assert not memory.symbolic and self.state.solver.eval(memory) == NATIVE_MEMORY
        self.state.globals["item_call"] = claripy.Concat(
            self.state.memory.load(address, 8), _bag(self.state, NATIVE_MEMORY)
        )
        self.state.globals["trace"] = self.state.globals["trace"] * 16 + 1
        for offset in range(8):
            self.state.memory.store(
                address + offset, self.state.globals[f"item_out_{offset}"]
            )
        for offset in range(BAG_SIZE):
            self.state.memory.store(
                memory + W_NUM_BAG_ITEMS + offset,
                self.state.globals[f"bag_out_{offset}"],
            )


class AndA(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.f = claripy.BVV(0x10, 8) | claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x40, 8),
            claripy.BVV(0, 8),
        )
        self.jump(self._continuation)


def _inputs() -> dict[str, claripy.ast.BV]:
    values = symbolic_registers("is_ghost_battle")
    values["is_in_battle"] = claripy.BVS("is_ghost_battle_mode", 8)
    values["cur_map"] = claripy.BVS("is_ghost_battle_map", 8)
    for offset in range(BAG_SIZE):
        values[f"bag_{offset}"] = claripy.BVS(
            f"is_ghost_battle_bag_{offset}", 8
        )
        values[f"bag_out_{offset}"] = claripy.BVS(
            f"is_ghost_battle_bag_out_{offset}", 8
        )
    values["bag_15"] = claripy.BVV(0xFF, 8)
    for offset in range(8):
        values[f"item_out_{offset}"] = claripy.BVS(
            f"is_ghost_battle_item_out_{offset}", 8
        )
    values["item_out_1"] = claripy.Concat(
        claripy.BVS("is_ghost_battle_item_out_flags", 4),
        claripy.BVV(0, 4),
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
        state.globals[f"bag_out_{offset}"] = values[f"bag_out_{offset}"]
    for offset in range(8):
        state.globals[f"item_out_{offset}"] = values[f"item_out_{offset}"]
    state.globals["item_call"] = claripy.BVV(0, 200)
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
        item_call=state.globals["item_call"],
        trace=state.globals["trace"],
        constraints=tuple(state.solver.constraints),
    )


@cache
def _assembly_project() -> tuple[angr.Project, int]:
    location = symbol_location(SYMS, "IsGhostBattle")
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
    project.hook(base, LoadAbsolute(W_IS_IN_BATTLE, base + 3), length=3)
    project.hook(base + 3, Sm83DecRegister("a", base + 4), length=1)
    project.hook(base + 5, LoadAbsolute(W_CUR_MAP, base + 8), length=3)
    project.hook(base + 8, Sm83CpImmediate(0x8E, base + 10), length=2)
    project.hook(base + 12, Sm83CpImmediate(0x95, base + 14), length=2)
    project.hook(base + 18, AssemblyItemInBag(base + 21), length=3)
    project.hook(base + 24, AndA(base + 25), length=1)
    return project, base


@cache
def _native_project() -> tuple[angr.Project, int]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_is_ghost_battle_complete")
    item = project.loader.find_symbol("port_is_item_in_bag")
    assert function is not None and item is not None
    project.hook(item.rebased_addr, NativeItemInBag())
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
def test_is_ghost_battle_pathwise_equivalence() -> None:
    location = symbol_location(SYMS, "IsGhostBattle")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    values = _inputs()
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "memory", "item_call", "trace"),
    )
