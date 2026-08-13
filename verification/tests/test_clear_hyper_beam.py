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
from verification.harness.sm83_shims import Sm83LoadAHighImmediate


ROOT = Path(__file__).resolve().parents[2]
VERIFY = ROOT / "verification"
NATIVE_ELF = VERIFY / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
GB_STACK = 0xD000
GB_RETURN = 0xFFFF
NATIVE_STATE = 0x100000
MEMORY_NAMES = ("whose_turn", "player_status2", "enemy_status2")


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
    whose_turn: claripy.ast.BV
    player_status2: claripy.ast.BV
    enemy_status2: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _addresses() -> dict[str, int]:
    return {
        "whose_turn": symbol_location(SYMBOLS, "hWhoseTurn").address,
        "player_status2": symbol_location(SYMBOLS, "wPlayerBattleStatus2").address,
        "enemy_status2": symbol_location(SYMBOLS, "wEnemyBattleStatus2").address,
    }


def _assembly_endpoints(
    symbol: str, inputs: dict[str, claripy.ast.BV]
) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, symbol)
    addresses = _addresses()
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
    load_offset = 4 if symbol == "ClearHyperBeam" else 3
    project.hook(
        location.address + load_offset,
        Sm83LoadAHighImmediate(0xF3, location.address + load_offset + 2),
        length=2,
    )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    for name, address in addresses.items():
        state.memory.store(address, inputs[name])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    return [
        Endpoint(
            **assembly_registers(end),
            **{
                name: end.memory.load(address, 1)
                for name, address in addresses.items()
            },
            constraints=tuple(end.solver.constraints),
        )
        for end in returned
    ]


def _native_endpoints(
    c_symbol: str, inputs: dict[str, claripy.ast.BV]
) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(c_symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    for offset, name in enumerate(MEMORY_NAMES, 8):
        state.memory.store(NATIVE_STATE + offset, inputs[name])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            **{
                name: end.memory.load(NATIVE_STATE + offset, 1)
                for offset, name in enumerate(MEMORY_NAMES, 8)
            },
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("assembly_symbol", "c_symbol"),
    [
        ("HyperBeamEffect", "port_hyper_beam_effect"),
        ("ClearHyperBeam", "port_clear_hyper_beam"),
    ],
)
def test_hyper_beam_status_symbolic_equivalence(
    assembly_symbol: str, c_symbol: str
) -> None:
    inputs = symbolic_registers(assembly_symbol)
    for name in MEMORY_NAMES:
        inputs[name] = claripy.BVS(f"{assembly_symbol}_{name}", 8)
    assert_pathwise_equivalent(
        _assembly_endpoints(assembly_symbol, inputs),
        _native_endpoints(c_symbol, inputs),
        (*REGISTERS, *MEMORY_NAMES),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize(
    ("symbol", "size", "expected"),
    [
        ("HyperBeamEffect", 14, "2163d0f0f3a728032168d0cbeec9"),
        ("ClearHyperBeam", 16, "e52168d0f0f3a728032163d0cbaee1c9"),
    ],
)
def test_hyper_beam_status_machine_code_is_accounted_for(
    symbol: str, size: int, expected: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, size) == bytes.fromhex(expected)
