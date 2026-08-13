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
from verification.harness.sm83_shims import Sm83AddHlRegisterPair, Sm83DecRegister


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
LOOP = 0xEFFE
RETURN = 0xEFFF


class Boundary(angr.SimProcedure):
    def __init__(self, address: int) -> None:
        super().__init__()
        self._address = address

    def run(self) -> None:  # type: ignore[override]
        self.jump(self._address)


class Fetch(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        if self.state.globals.get("entered", False):
            self.jump(LOOP)
            return
        self.state.globals["entered"] = True
        self.state.regs.a = self.state.globals["fetched"]
        self.state.regs.hl = self.state.regs.hl + 1
        self.jump(self._next_address)


class Store(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["written"] = self.state.regs.a
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
    memory: claripy.ast.BV
    result: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def project() -> tuple[angr.Project, int]:
    location = symbol_location(SYMBOLS, "SlotMachine_GetWheelTiles")
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
    values["fetched"] = claripy.BVS(f"{prefix}_fetched", 8)
    values["written"] = claripy.BVS(f"{prefix}_written", 8)
    return values


def assembly_begin(values: dict[str, claripy.ast.BV]) -> Endpoint:
    loaded, base = project()
    loaded.hook(base + 3, Sm83AddHlRegisterPair("bc", base + 4), length=1)
    loaded.hook(base + 6, Boundary(LOOP), length=1)
    state = loaded.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    manager = loaded.factory.simulation_manager(state)
    manager.explore(find=LOOP)
    assert not manager.errored and len(manager.found) == 1
    end = manager.found[0]
    return Endpoint(
        **assembly_registers(end),
        memory=claripy.Concat(values["fetched"], values["written"]),
        result=claripy.BVV(0, 8),
        constraints=tuple(end.solver.constraints),
    )


def assembly_step(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    loaded, base = project()
    loop = base + 6
    loaded.hook(loop, Fetch(loop + 1), length=1)
    loaded.hook(loop + 1, Store(loop + 2), length=1)
    loaded.hook(loop + 4, Sm83DecRegister("c", loop + 5), length=1)
    loaded.hook(loop + 7, Boundary(RETURN), length=1)
    state = loaded.factory.blank_state(addr=loop)
    set_assembly_registers(state, values)
    state.globals["fetched"] = values["fetched"]
    state.globals["written"] = values["written"]
    manager = loaded.factory.simulation_manager(state)
    manager.stashes["found"] = []
    while manager.active:
        manager.move(
            from_stash="active",
            to_stash="found",
            filter_func=lambda item: item.addr in {LOOP, RETURN},
        )
        if manager.active:
            manager.step()
    return [
        Endpoint(
            **assembly_registers(end),
            memory=claripy.Concat(values["fetched"], end.globals["written"]),
            result=claripy.BVV(1 if end.addr == RETURN else 0, 8),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def native(
    symbol: str, values: dict[str, claripy.ast.BV], returns: bool
) -> list[Endpoint]:
    loaded = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = loaded.loader.find_symbol(symbol)
    assert function is not None
    state = loaded.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, values["fetched"])
    state.memory.store(NATIVE_STATE + 9, values["written"])
    manager = loaded.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=end.memory.load(NATIVE_STATE + 8, 2),
            result=end.regs.rax[7:0] if returns else claripy.BVV(0, 8),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native port not built")
def test_begin_equivalence() -> None:
    values = inputs("slot_machine_get_wheel_tiles_begin")
    assert_pathwise_equivalent(
        [assembly_begin(values)],
        native("port_slot_machine_get_wheel_tiles_begin", values, False),
        (*REGISTERS, "memory", "result"),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native port not built")
def test_step_equivalence() -> None:
    values = inputs("slot_machine_get_wheel_tiles_step")
    assert_pathwise_equivalent(
        assembly_step(values),
        native("port_slot_machine_get_wheel_tiles_step", values, True),
        (*REGISTERS, "memory", "result"),
    )


def test_exact_body() -> None:
    location = symbol_location(SYMBOLS, "SlotMachine_GetWheelTiles")
    assert linked_bytes(ROM, location, 14) == bytes.fromhex(
        "4f0600090e032a1213230d20f9c9"
    )
