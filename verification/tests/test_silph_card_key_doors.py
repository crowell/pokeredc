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
    Sm83CpImmediate,
    Sm83CpRegister,
)


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
CONTINUE = 0xEFFE
DONE = 0xEFFF
FIELDS = ("card_y", "card_x", "unlocked", "fetched_y", "fetched_x")
BODY = "e5213fd72a477e4fafe0e0e12afeff2817e521e0ff34e1b828032318ef2ab920eb213fd7af2277c9afe0e0c9"
PORTS = (
    ("SilphCo2F_SetCardKeyDoorYScript", "port_silph_co_2f_set_card_key_door_y"),
    ("SilphCo4F_SetCardKeyDoorYScript", "port_silph_co_4f_set_card_key_door_y"),
    ("SilphCo7F_SetCardKeyDoorYScript", "port_silph_co_7f_set_card_key_door_y"),
    ("SilphCo8F_SetCardKeyDoorYScript", "port_silph_co_8f_set_card_key_door_y"),
    ("SilphCo9F_SetCardKeyDoorYScript", "port_silph_co_9f_set_card_key_door_y"),
    ("SilphCo11F_SetCardKeyDoorYScript", "port_silph_co_11f_set_card_key_door_y"),
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
    result: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class SaveHl(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["saved_h"] = self.state.regs.h
        self.state.globals["saved_l"] = self.state.regs.l
        self.jump(self._next_address)


class RestoreHl(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = self.state.globals["saved_h"]
        self.state.regs.l = self.state.globals["saved_l"]
        self.jump(self._next_address)


class LoadCard(angr.SimProcedure):
    def __init__(self, key: str, increment: bool, next_address: int) -> None:
        super().__init__()
        self._key = key
        self._increment = increment
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals[self._key]
        if self._increment:
            self.state.regs.hl = self.state.regs.hl + 1
        self.jump(self._next_address)


class XorA(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = 0
        self.state.regs.f = 0x40
        self.jump(self._next_address)


class StoreUnlocked(angr.SimProcedure):
    def __init__(self, next_address: int, result: int | None = None) -> None:
        super().__init__()
        self._next_address = next_address
        self._result = result

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["unlocked"] = self.state.regs.a
        if self._result is not None:
            self.state.globals["result"] = self._result
        self.jump(self._next_address)


class Fetch(angr.SimProcedure):
    def __init__(self, key: str, next_address: int) -> None:
        super().__init__()
        self._key = key
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        if self._key == "fetched_y" and self.state.globals.get("entered", False):
            self.jump(CONTINUE)
            return
        if self._key == "fetched_y":
            self.state.globals["entered"] = True
        self.state.regs.a = self.state.globals[self._key]
        self.state.regs.hl = self.state.regs.hl + 1
        self.jump(self._next_address)


class IncUnlocked(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        old = self.state.globals["unlocked"]
        result = old + 1
        self.state.globals["unlocked"] = result
        self.state.regs.f = (self.state.regs.f & 1) | claripy.If(
            result == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)
        ) | claripy.If(
            (old & 0x0F) == 0x0F, claripy.BVV(0x10, 8), claripy.BVV(0, 8)
        )
        self.jump(self._next_address)


class StoreCardY(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["card_y"] = self.state.regs.a
        self.state.regs.hl = self.state.regs.hl + 1
        self.jump(self._next_address)


class StoreCardXDone(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.globals["card_x"] = self.state.regs.a
        self.state.globals["result"] = 1
        self.jump(DONE)


class Done(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(DONE)


def project(symbol: str) -> tuple[angr.Project, int]:
    location = symbol_location(SYMBOLS, symbol)
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
    for key in FIELDS:
        values[key] = claripy.BVS(f"{prefix}_{key}", 8)
    return values


def initial_state(
    loaded: angr.Project, address: int, values: dict[str, claripy.ast.BV]
) -> angr.SimState:
    state = loaded.factory.blank_state(addr=address)
    set_assembly_registers(state, values)
    for key in FIELDS:
        state.globals[key] = values[key]
    state.globals["result"] = 0
    return state


def endpoint(state: angr.SimState, result: int | None = None) -> Endpoint:
    return Endpoint(
        **assembly_registers(state),
        memory=claripy.Concat(*(state.globals[key] for key in FIELDS)),
        result=(
            claripy.BVV(result, 8)
            if result is not None
            else claripy.BVV(state.globals["result"], 8)
        ),
        constraints=tuple(state.solver.constraints),
    )


def assembly_begin(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    loaded, base = project(PORTS[0][0])
    loaded.hook(base, SaveHl(base + 1), length=1)
    loaded.hook(base + 4, LoadCard("card_y", True, base + 5), length=1)
    loaded.hook(base + 6, LoadCard("card_x", False, base + 7), length=1)
    loaded.hook(base + 8, XorA(base + 9), length=1)
    loaded.hook(base + 9, StoreUnlocked(base + 11), length=2)
    loaded.hook(base + 11, RestoreHl(DONE), length=1)
    state = initial_state(loaded, base, values)
    manager = loaded.factory.simulation_manager(state)
    manager.explore(find=DONE)
    assert not manager.errored and len(manager.found) == 1
    return [endpoint(manager.found[0], 0)]


def assembly_step(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    loaded, base = project(PORTS[0][0])
    loaded.hook(base + 12, Fetch("fetched_y", base + 13), length=1)
    loaded.hook(base + 13, Sm83CpImmediate(0xFF, base + 15), length=2)
    loaded.hook(base + 17, SaveHl(base + 18), length=1)
    loaded.hook(base + 21, IncUnlocked(base + 22), length=1)
    loaded.hook(base + 22, RestoreHl(base + 23), length=1)
    loaded.hook(base + 23, Sm83CpRegister("b", base + 24), length=1)
    loaded.hook(base + 29, Fetch("fetched_x", base + 30), length=1)
    loaded.hook(base + 30, Sm83CpRegister("c", base + 31), length=1)
    loaded.hook(base + 36, XorA(base + 37), length=1)
    loaded.hook(base + 37, StoreCardY(base + 38), length=1)
    loaded.hook(base + 38, StoreCardXDone(), length=1)
    loaded.hook(base + 40, XorA(base + 41), length=1)
    loaded.hook(base + 41, StoreUnlocked(DONE, 2), length=2)
    state = initial_state(loaded, base + 12, values)
    manager = loaded.factory.simulation_manager(state)
    manager.stashes["found"] = []
    while manager.active:
        manager.move(
            from_stash="active",
            to_stash="found",
            filter_func=lambda item: item.addr in {CONTINUE, DONE},
        )
        if manager.active:
            manager.step()
    assert not manager.errored
    return [endpoint(end, 0 if end.addr == CONTINUE else None) for end in manager.found]


def native(
    symbol: str, values: dict[str, claripy.ast.BV], returns: bool
) -> list[Endpoint]:
    loaded = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = loaded.loader.find_symbol(symbol)
    assert function is not None
    state = loaded.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(
        NATIVE_STATE + 8, claripy.Concat(*(values[key] for key in FIELDS))
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
        (assembly_begin, "port_silph_card_key_door_begin", False),
        (assembly_step, "port_silph_card_key_door_step", True),
    ],
)
def test_phase_equivalence(assembly_phase, c_symbol: str, returns: bool) -> None:
    values = inputs(c_symbol)
    assert_pathwise_equivalent(
        assembly_phase(values),
        native(c_symbol, values, returns),
        (*REGISTERS, "memory", "result"),
    )


@pytest.mark.parametrize("symbol,_c_symbol", PORTS)
def test_exact_body(symbol: str, _c_symbol: str) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, 44) == bytes.fromhex(BODY)
