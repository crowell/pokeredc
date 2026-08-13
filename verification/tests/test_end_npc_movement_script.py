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
from verification.harness.rom import collect_returns, linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import Sm83ResAtHl, Sm83StoreAImmediate

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
STACK = 0xD000
RETURN = 0xFFFF
NATIVE_STATE = 0x100000
NAMES = (
    "wStatusFlags5",
    "wStatusFlags4",
    "wMovementFlags",
    "wNPCMovementScriptSpriteOffset",
    "wNPCMovementScriptPointerTableNum",
    "wNPCMovementScriptFunctionNum",
    "wUnusedOverrideSimulatedJoypadStatesIndex",
    "wSimulatedJoypadStatesIndex",
    "wSimulatedJoypadStatesEnd",
)


class XorA(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = 0
        self.state.regs.f = 0x40
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
    constraints: tuple[claripy.ast.Bool, ...]


def assembly(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "_EndNPCMovementScript")
    addresses = tuple(symbol_location(SYMBOLS, name).address for name in NAMES)
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
    project.hook(location.address + 3, Sm83ResAtHl(7, location.address + 5), length=2)
    project.hook(location.address + 8, Sm83ResAtHl(7, location.address + 10), length=2)
    project.hook(location.address + 13, Sm83ResAtHl(0, location.address + 15), length=2)
    project.hook(location.address + 15, Sm83ResAtHl(1, location.address + 17), length=2)
    project.hook(location.address + 17, XorA(location.address + 18), length=1)
    for offset, address in zip((18, 21, 24, 27, 30, 33), addresses[3:]):
        project.hook(
            location.address + offset,
            Sm83StoreAImmediate(address, location.address + offset + 3),
            length=3,
        )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    for index, address in enumerate(addresses):
        state.memory.store(address, inputs[f"memory{index}"])
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    ends = collect_returns(project, state, RETURN)
    return [
        Endpoint(
            **assembly_registers(end),
            memory=claripy.Concat(*(end.memory.load(address, 1) for address in addresses)),
            constraints=tuple(end.solver.constraints),
        )
        for end in ends
    ]


def native(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_end_npc_movement_script")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    for index in range(len(NAMES)):
        state.memory.store(NATIVE_STATE + 8 + index, inputs[f"memory{index}"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=claripy.Concat(
                *(end.memory.load(NATIVE_STATE + 8 + index, 1)
                  for index in range(len(NAMES)))
            ),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native port not built")
def test_equivalence() -> None:
    inputs = symbolic_registers("end_npc_movement")
    for index, name in enumerate(NAMES):
        inputs[f"memory{index}"] = claripy.BVS(f"end_npc_movement_{name}", 8)
    assert_pathwise_equivalent(
        assembly(inputs), native(inputs), (*REGISTERS, "memory")
    )


def test_body() -> None:
    location = symbol_location(SYMBOLS, "_EndNPCMovementScript")
    assert linked_bytes(ROM, location, 37) == bytes.fromhex(
        "2130d7cbbe212ed7cbbe2136d7cb86cb8eaf"
        "ea17cfea57ccea10cfea3acdea38cdead3ccc9"
    )
