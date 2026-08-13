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
    Sm83DecRegister,
)


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
ROW = 0xEFFD
TILE = 0xEFFE
RETURN = 0xEFFF
FIELDS = ("saved_h", "saved_l", "saved_b", "saved_c", "written")


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
    result: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class Boundary(angr.SimProcedure):
    def __init__(self, address: int) -> None:
        super().__init__()
        self._address = address

    def run(self) -> None:  # type: ignore[override]
        self.jump(self._address)


class SaveHl(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["saved_h"] = self.state.regs.h
        self.state.globals["saved_l"] = self.state.regs.l
        self.jump(self._next_address)


class SaveBc(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["saved_b"] = self.state.regs.b
        self.state.globals["saved_c"] = self.state.regs.c
        self.jump(self._next_address)


class RestoreBc(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.b = self.state.globals["saved_b"]
        self.state.regs.c = self.state.globals["saved_c"]
        self.jump(self._next_address)


class RestoreHl(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = self.state.globals["saved_h"]
        self.state.regs.l = self.state.globals["saved_l"]
        self.jump(self._next_address)


class StoreHli(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        if self.state.globals.get("entered", False):
            self.jump(TILE)
            return
        self.state.globals["entered"] = True
        self.state.globals["written"] = self.state.regs.a
        self.state.regs.hl = self.state.regs.hl + 1
        self.jump(self._next_address)


def project() -> tuple[angr.Project, int]:
    location = symbol_location(SYMBOLS, "ClearScreenArea")
    loaded = angr.Project(
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
    return loaded, location.address


def inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for name in FIELDS:
        values[name] = claripy.BVS(f"{prefix}_{name}", 8)
    return values


def initial_state(
    loaded: angr.Project, address: int, values: dict[str, claripy.ast.BV]
) -> angr.SimState:
    state = loaded.factory.blank_state(addr=address)
    set_assembly_registers(state, values)
    for name in FIELDS:
        state.globals[name] = values[name]
    return state


def endpoint(state: angr.SimState, result: int) -> Endpoint:
    return Endpoint(
        **assembly_registers(state),
        memory=claripy.Concat(*(state.globals[name] for name in FIELDS)),
        result=claripy.BVV(result, 8),
        constraints=tuple(state.solver.constraints),
    )


def collect(
    manager: angr.SimulationManager, boundaries: set[int]
) -> list[angr.SimState]:
    manager.stashes["found"] = []
    while manager.active:
        manager.move(
            from_stash="active",
            to_stash="found",
            filter_func=lambda state: state.addr in boundaries,
        )
        if manager.active:
            manager.step()
    return manager.found


def assembly_begin(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    loaded, base = project()
    loaded.hook(base + 5, Boundary(ROW), length=1)
    state = initial_state(loaded, base, values)
    manager = loaded.factory.simulation_manager(state)
    manager.explore(find=ROW)
    assert not manager.errored and len(manager.found) == 1
    return [endpoint(manager.found[0], 0)]


def assembly_row_begin(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    loaded, base = project()
    loaded.hook(base + 5, SaveHl(base + 6), length=1)
    loaded.hook(base + 6, SaveBc(TILE), length=1)
    state = initial_state(loaded, base + 5, values)
    manager = loaded.factory.simulation_manager(state)
    manager.explore(find=TILE)
    assert not manager.errored and len(manager.found) == 1
    return [endpoint(manager.found[0], 0)]


def assembly_tile_step(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    loaded, base = project()
    loaded.hook(base + 7, StoreHli(base + 8), length=1)
    loaded.hook(base + 8, Sm83DecRegister("c", base + 9), length=1)
    state = initial_state(loaded, base + 7, values)
    manager = loaded.factory.simulation_manager(state)
    ends = collect(manager, {TILE, base + 11})
    assert not manager.errored and len(ends) == 2
    return [endpoint(end, 0 if end.addr == TILE else 1) for end in ends]


def assembly_row_finish(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    loaded, base = project()
    loaded.hook(base + 11, RestoreBc(base + 12), length=1)
    loaded.hook(base + 12, RestoreHl(base + 13), length=1)
    loaded.hook(
        base + 13, Sm83AddHlRegisterPair("de", base + 14), length=1
    )
    loaded.hook(base + 14, Sm83DecRegister("b", base + 15), length=1)
    loaded.hook(base + 17, Boundary(RETURN), length=1)
    state = initial_state(loaded, base + 11, values)
    manager = loaded.factory.simulation_manager(state)
    ends = collect(manager, {base + 5, RETURN})
    assert not manager.errored and len(ends) == 2
    return [endpoint(end, 0 if end.addr == base + 5 else 1) for end in ends]


def native(
    symbol: str, values: dict[str, claripy.ast.BV], returns: bool
) -> list[Endpoint]:
    loaded = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = loaded.loader.find_symbol(symbol)
    assert function is not None
    state = loaded.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(
        NATIVE_STATE + 8,
        claripy.Concat(*(values[name] for name in FIELDS)),
    )
    manager = loaded.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=end.memory.load(NATIVE_STATE + 8, len(FIELDS)),
            result=end.regs.rax[7:0] if returns else claripy.BVV(0, 8),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native port not built")
@pytest.mark.parametrize(
    "assembly_phase,c_symbol,returns",
    [
        (assembly_begin, "port_clear_screen_area_begin", False),
        (assembly_row_begin, "port_clear_screen_area_row_begin", False),
        (assembly_tile_step, "port_clear_screen_area_tile_step", True),
        (assembly_row_finish, "port_clear_screen_area_row_finish", True),
    ],
)
def test_phase_equivalence(assembly_phase, c_symbol: str, returns: bool) -> None:
    values = inputs(c_symbol)
    assert_pathwise_equivalent(
        assembly_phase(values),
        native(c_symbol, values, returns),
        (*REGISTERS, "memory", "result"),
    )


def test_exact_body() -> None:
    location = symbol_location(SYMBOLS, "ClearScreenArea")
    assert linked_bytes(ROM, location, 18) == bytes.fromhex(
        "3e7f111400e5c5220d20fcc1e1190520f4c9"
    )
