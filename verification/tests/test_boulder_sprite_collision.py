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
from verification.harness.sm83_shims import (
    Sm83AddHlRegisterPair,
    Sm83AndImmediate,
    Sm83BitRegister,
    Sm83CpRegister,
    Sm83DecRegister,
    Sm83IncRegister,
    Sm83Rrca,
    Sm83SwapRegister,
)


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
VERTICAL = 0xEFFC
HORIZONTAL = 0xEFFD
REPEAT = 0xEFFE
SUCCESS = 0xEFFF
FAILURE = 0xF000
NAMES = (
    "boulder_index",
    "boulder_y",
    "boulder_x",
    "num_sprites",
    "facing",
    "player_y",
    "player_x",
    "sprite_y",
    "sprite_x",
)


class Load(angr.SimProcedure):
    def __init__(self, key: str, next_address: int) -> None:
        super().__init__()
        self.key = key
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals[self.key]
        self.jump(self.next_address)


class LoadHli(Load):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals[self.key]
        self.state.regs.hl = self.state.regs.hl + 1
        self.jump(self.next_address)


class LoadRegister(Load):
    def __init__(self, register: str, key: str, next_address: int) -> None:
        super().__init__(key, next_address)
        self.register = register

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.register, self.state.globals[self.key])
        self.jump(self.next_address)


class Store(angr.SimProcedure):
    def __init__(self, key: str, next_address: int) -> None:
        super().__init__()
        self.key = key
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.globals[self.key] = self.state.regs.a
        self.jump(self.next_address)


class CpGlobal(angr.SimProcedure):
    def __init__(self, key: str, next_address: int) -> None:
        super().__init__()
        self.key = key
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        left = self.state.regs.a
        right = self.state.globals[self.key]
        flags = claripy.BVV(0x02, 8)
        flags |= claripy.If(left == right, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        flags |= claripy.If(
            (left & 0x0F).ULT(right & 0x0F),
            claripy.BVV(0x10, 8),
            claripy.BVV(0, 8),
        )
        flags |= claripy.If(left.ULT(right), claripy.BVV(1, 8), claripy.BVV(0, 8))
        self.state.regs.f = flags
        self.jump(self.next_address)


class LoopVertical(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        if self.state.globals.get("entered", False):
            self.jump(REPEAT)
        else:
            self.state.globals["entered"] = True
            self.state.regs.hl = self.state.regs.hl + 1
            self.jump(self.next_address)


class LoopHorizontal(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        if self.state.globals.get("entered", False):
            self.jump(REPEAT)
        else:
            self.state.globals["entered"] = True
            self.state.regs.a = self.state.globals["sprite_y"]
            self.state.regs.hl = self.state.regs.hl + 1
            self.jump(self.next_address)


class ZeroA(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = 0
        self.state.regs.f = 0x40
        self.jump(self.next_address)


class Boundary(angr.SimProcedure):
    def __init__(self, address: int) -> None:
        super().__init__()
        self.address = address

    def run(self) -> None:  # type: ignore[override]
        self.jump(self.address)


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
    continuation: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for name in NAMES:
        values[name] = claripy.BVS(f"{prefix}_{name}", 8)
    return values


def project() -> tuple[angr.Project, int]:
    location = symbol_location(SYMBOLS, "CheckForBoulderCollisionWithSprites")
    result = angr.Project(
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
    return result, location.address


def setup(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    set_assembly_registers(state, values)
    for name in NAMES:
        state.globals[name] = values[name]


def endpoint(state: angr.SimState, continuation: int) -> Endpoint:
    return Endpoint(
        **assembly_registers(state),
        memory=claripy.Concat(*(state.globals[name] for name in NAMES)),
        continuation=claripy.BVV(continuation, 8),
        constraints=tuple(state.solver.constraints),
    )


def collect(manager: angr.SimulationManager, targets: set[int]) -> list[angr.SimState]:
    manager.stashes["found"] = []
    while manager.active:
        manager.move(
            from_stash="active",
            to_stash="found",
            filter_func=lambda state: state.addr in targets,
        )
        if manager.active:
            manager.step()
    return manager.found


def assembly_setup(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    p, q = project()
    p.hook(q + 3, Sm83DecRegister("a", q + 4), length=1)
    p.hook(q + 4, Sm83SwapRegister("a", q + 6), length=2)
    p.hook(q + 12, Sm83AddHlRegisterPair("de", q + 13), length=1)
    p.hook(q + 13, LoadHli("boulder_y", q + 14), length=1)
    p.hook(q + 14, Store("player_y", q + 16), length=2)
    p.hook(q + 16, Load("boulder_x", q + 17), length=1)
    p.hook(q + 17, Store("player_x", q + 19), length=2)
    p.hook(q + 19, Load("num_sprites", q + 22), length=3)
    p.hook(q + 29, Load("facing", q + 31), length=2)
    p.hook(q + 31, Sm83AndImmediate(3, q + 33), length=2)
    p.hook(q + 35, Boundary(VERTICAL), length=1)
    p.hook(q + 66, Boundary(HORIZONTAL), length=1)
    state = p.factory.blank_state(addr=q)
    setup(state, values)
    ends = collect(p.factory.simulation_manager(state), {VERTICAL, HORIZONTAL})
    return [endpoint(end, 1 if end.addr == VERTICAL else 2) for end in ends]


def hook_returns(p: angr.Project, q: int) -> None:
    p.hook(q + 99, Boundary(FAILURE), length=1)
    p.hook(q + 100, ZeroA(SUCCESS), length=1)


def assembly_vertical(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    p, q = project()
    p.hook(q + 35, LoopVertical(q + 36), length=1)
    p.hook(q + 36, Load("player_x", q + 38), length=2)
    p.hook(q + 38, CpGlobal("sprite_x", q + 39), length=1)
    p.hook(q + 42, LoadHli("sprite_y", q + 43), length=1)
    p.hook(q + 44, Load("facing", q + 46), length=2)
    p.hook(q + 46, Sm83Rrca(q + 47), length=1)
    p.hook(q + 49, Load("player_y", q + 51), length=2)
    p.hook(q + 51, Sm83DecRegister("a", q + 52), length=1)
    p.hook(q + 54, Load("player_y", q + 56), length=2)
    p.hook(q + 56, Sm83IncRegister("a", q + 57), length=1)
    p.hook(q + 57, Sm83CpRegister("b", q + 58), length=1)
    p.hook(q + 60, Sm83DecRegister("c", q + 61), length=1)
    p.hook(q + 63, Sm83AddHlRegisterPair("de", q + 64), length=1)
    hook_returns(p, q)
    state = p.factory.blank_state(addr=q + 35)
    setup(state, values)
    ends = collect(p.factory.simulation_manager(state), {REPEAT, SUCCESS, FAILURE})
    codes = {REPEAT: 1, SUCCESS: 0, FAILURE: 2}
    return [endpoint(end, codes[end.addr]) for end in ends]


def assembly_horizontal(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    p, q = project()
    p.hook(q + 66, LoopHorizontal(q + 67), length=1)
    p.hook(q + 68, Load("player_y", q + 70), length=2)
    p.hook(q + 70, Sm83CpRegister("b", q + 71), length=1)
    p.hook(q + 73, LoadRegister("b", "sprite_x", q + 74), length=1)
    p.hook(q + 74, Load("facing", q + 76), length=2)
    p.hook(q + 76, Sm83BitRegister(2, "a", q + 78), length=2)
    p.hook(q + 80, Load("player_x", q + 82), length=2)
    p.hook(q + 82, Sm83IncRegister("a", q + 83), length=1)
    p.hook(q + 85, Load("player_x", q + 87), length=2)
    p.hook(q + 87, Sm83DecRegister("a", q + 88), length=1)
    p.hook(q + 88, Sm83CpRegister("b", q + 89), length=1)
    p.hook(q + 91, Sm83DecRegister("c", q + 92), length=1)
    p.hook(q + 94, Sm83AddHlRegisterPair("de", q + 95), length=1)
    hook_returns(p, q)
    state = p.factory.blank_state(addr=q + 66)
    setup(state, values)
    ends = collect(p.factory.simulation_manager(state), {REPEAT, SUCCESS, FAILURE})
    codes = {REPEAT: 1, SUCCESS: 0, FAILURE: 2}
    return [endpoint(end, codes[end.addr]) for end in ends]


def native(symbol: str, values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    p = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = p.loader.find_symbol(symbol)
    assert function is not None
    state = p.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(
        NATIVE_STATE + 8,
        claripy.Concat(*(values[name] for name in NAMES)),
    )
    manager = p.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=end.memory.load(NATIVE_STATE + 8, len(NAMES)),
            continuation=end.regs.rax[7:0],
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


CASES = (
    (assembly_setup, "port_check_boulder_collision_setup"),
    (assembly_vertical, "port_check_boulder_collision_vertical_step"),
    (assembly_horizontal, "port_check_boulder_collision_horizontal_step"),
)


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native verification ELF missing")
@pytest.mark.parametrize("assembly,symbol", CASES)
def test_equivalence(assembly, symbol: str) -> None:
    values = inputs(symbol)
    assert_pathwise_equivalent(
        assembly(values),
        native(symbol, values),
        (*REGISTERS, "memory", "continuation"),
    )


def test_exact_body() -> None:
    location = symbol_location(SYMBOLS, "CheckForBoulderCollisionWithSprites")
    assert linked_bytes(ROM, location, 102) == bytes.fromhex(
        "fa18d73dcb3716005f2114c2192ae0dc7ee0ddfae1d44f110f002114c2f0db"
        "e603281f23f0ddbe20132b2a47f0db0f3805f0dc3d1803f0dc3cb828250d28"
        "251918e12a47f0dcb8201246f0dbcb572005f0dd3c1803f0dd3db828060d280"
        "61918e13effc9afc9"
    )
