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
    linked_bytes,
    rom_window,
    sm83_flags_to_z80,
    symbol_location,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
DONE = 0xEFFF
EXPECTED = bytes.fromhex("c35a4d")


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
    call: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class AssemblyCallee(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        registers = assembly_registers(self.state)
        self.state.globals["call"] = claripy.Concat(
            *(registers[register] for register in REGISTERS)
        )
        for register in REGISTERS:
            value = self.state.globals[f"out_{register}"]
            if register == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, register, value)
        self.jump(DONE)


class NativeCallee(angr.SimProcedure):
    def run(self, state: claripy.ast.BV) -> None:  # type: ignore[override]
        self.state.globals["call"] = self.state.memory.load(state, 8)
        self.state.memory.store(
            state,
            claripy.Concat(
                *(self.state.globals[f"out_{register}"]
                  for register in REGISTERS)
            ),
        )


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for register in REGISTERS:
        values[f"out_{register}"] = (
            claripy.Concat(
                claripy.BVS(f"{prefix}_out_flags", 4), claripy.BVV(0, 4)
            )
            if register == "f"
            else claripy.BVS(f"{prefix}_out_{register}", 8)
        )
    return values


def _setup(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    for register in REGISTERS:
        state.globals[f"out_{register}"] = values[f"out_{register}"]


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "ApplyAttackToPlayerPokemonDone")
    target = symbol_location(SYMBOLS, "DrawHUDsAndHPBars")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    project.hook(target.address, AssemblyCallee())
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    _setup(state, values)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE)
    assert not manager.errored
    return [
        Endpoint(
            **assembly_registers(end), call=end.globals["call"],
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_apply_attack_to_player_pokemon_done")
    callee = project.loader.find_symbol("port_draw_huds_and_hp_bars")
    assert function is not None and callee is not None
    project.hook(callee.rebased_addr, NativeCallee())
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE), call=end.globals["call"],
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run red")
def test_apply_attack_to_player_pokemon_done_pathwise_equivalence() -> None:
    values = _inputs("apply_attack_to_player_pokemon_done")
    assert_pathwise_equivalent(
        _assembly(values), _native(values), (*REGISTERS, "call")
    )
