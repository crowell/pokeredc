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
    Sm83AndImmediate,
    Sm83BitRegister,
    Sm83LoadAImmediate,
)


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
GB_STACK = 0xD000
GB_RETURN = 0xFFFF
NAMES = (
    "wNPCMovementScriptPointerTableNum",
    "wMovementFlags",
    "wStatusFlags5",
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
    constraints: tuple[claripy.ast.Bool, ...]


class AndA(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.f = 0x10 | claripy.If(
            self.state.regs.a == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)
        )
        self.jump(self._next_address)


def addresses() -> tuple[int, int, int]:
    return tuple(symbol_location(SYMBOLS, name).address for name in NAMES)


def inputs() -> dict[str, claripy.ast.BV]:
    values = symbolic_registers("player_character_controlled")
    for name in ("npc_script", "movement_flags", "status_flags5"):
        values[name] = claripy.BVS(name, 8)
    return values


def assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(
        SYMBOLS, "IsPlayerCharacterBeingControlledByGame"
    )
    npc_script, movement_flags, status_flags5 = addresses()
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
    project.hook(base, Sm83LoadAImmediate(npc_script, base + 3), length=3)
    project.hook(base + 3, AndA(base + 4), length=1)
    project.hook(
        base + 5, Sm83LoadAImmediate(movement_flags, base + 8), length=3
    )
    project.hook(base + 8, Sm83BitRegister(1, "a", base + 10), length=2)
    project.hook(
        base + 11, Sm83LoadAImmediate(status_flags5, base + 14), length=3
    )
    project.hook(base + 14, Sm83AndImmediate(0x80, base + 16), length=2)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    for address, key in zip(
        addresses(), ("npc_script", "movement_flags", "status_flags5")
    ):
        state.memory.store(address, values[key])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    return [
        Endpoint(
            **assembly_registers(end),
            memory=claripy.Concat(
                *(end.memory.load(address, 1) for address in addresses())
            ),
            constraints=tuple(end.solver.constraints),
        )
        for end in returned
    ]


def native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(
        "port_is_player_character_being_controlled_by_game"
    )
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(
        NATIVE_STATE + 8,
        claripy.Concat(
            values["npc_script"],
            values["movement_flags"],
            values["status_flags5"],
        ),
    )
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=end.memory.load(NATIVE_STATE + 8, 3),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native port not built")
def test_symbolic_equivalence() -> None:
    values = inputs()
    assert_pathwise_equivalent(
        assembly(values), native(values), (*REGISTERS, "memory")
    )


def test_exact_body_and_addresses() -> None:
    location = symbol_location(
        SYMBOLS, "IsPlayerCharacterBeingControlledByGame"
    )
    assert addresses() == (0xCC57, 0xD736, 0xD730)
    assert linked_bytes(ROM, location, 17) == bytes.fromhex(
        "fa57cca7c0fa36d7cb4fc0fa30d7e680c9"
    )
