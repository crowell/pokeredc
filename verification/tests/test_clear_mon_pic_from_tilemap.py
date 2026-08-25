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
    sm83_flags_to_z80,
    symbol_location,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
STACK = 0xD000
RETURN = 0xFFFF
REGION_START = 0xC3A0
REGION_SIZE = 0xC51E - REGION_START
EXPECTED = bytes.fromhex("e5d5c55f160021a0c319010707cdc418c1d1e1c9")


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
    clear_call: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class AssemblyClearSummary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.globals["clear_call"] = claripy.Concat(
            *(assembly_registers(self.state)[name] for name in REGISTERS),
            self.state.memory.load(REGION_START, REGION_SIZE),
        )
        for register in REGISTERS:
            value = self.state.globals[f"clear_out_{register}"]
            if register == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, register, value)
        self.state.memory.store(
            REGION_START, self.state.globals["clear_out_memory"]
        )
        return_address = self.state.memory.load(
            self.state.regs.sp, 2, endness="Iend_LE"
        )
        self.state.regs.sp += 2
        self.jump(return_address)


class NativeClearSummary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        address = self.state.regs.rdi
        memory = self.state.regs.rsi
        self.state.globals["clear_call"] = claripy.Concat(
            self.state.memory.load(address, 8),
            self.state.memory.load(memory + REGION_START, REGION_SIZE),
        )
        for index, register in enumerate(REGISTERS):
            self.state.memory.store(
                address + index, self.state.globals[f"clear_out_{register}"]
            )
        self.state.memory.store(
            memory + REGION_START, self.state.globals["clear_out_memory"]
        )


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["memory"] = claripy.BVS(f"{prefix}_memory", REGION_SIZE * 8)
    for register in REGISTERS:
        if register == "f":
            values["clear_out_f"] = claripy.Concat(
                claripy.BVS(f"{prefix}_clear_out_flags", 4),
                claripy.BVV(0, 4),
            )
        else:
            values[f"clear_out_{register}"] = claripy.BVS(
                f"{prefix}_clear_out_{register}", 8
            )
    values["clear_out_memory"] = claripy.BVS(
        f"{prefix}_clear_out_memory", REGION_SIZE * 8
    )
    return values


def _setup_outputs(
    state: angr.SimState, values: dict[str, claripy.ast.BV]
) -> None:
    for register in REGISTERS:
        state.globals[f"clear_out_{register}"] = values[
            f"clear_out_{register}"
        ]
    state.globals["clear_out_memory"] = values["clear_out_memory"]


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "ClearMonPicFromTileMap")
    clear = symbol_location(SYMBOLS, "ClearScreenArea")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
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
    project.hook(clear.address, AssemblyClearSummary())
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.regs.sp = claripy.BVV(STACK, 16)
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    state.memory.store(REGION_START, values["memory"])
    _setup_outputs(state, values)
    return [
        Endpoint(
            **assembly_registers(end),
            memory=end.memory.load(REGION_START, REGION_SIZE),
            clear_call=end.globals["clear_call"],
            constraints=tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, RETURN)
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_clear_mon_pic_from_tilemap")
    clear = project.loader.find_symbol("port_clear_screen_area")
    assert function is not None and clear is not None
    project.hook(clear.rebased_addr, NativeClearSummary())
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(
        NATIVE_STATE + 8 + REGION_START, values["memory"]
    )
    _setup_outputs(state, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=end.memory.load(
                NATIVE_STATE + 8 + REGION_START, REGION_SIZE
            ),
            clear_call=end.globals["clear_call"],
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_clear_mon_pic_from_tilemap_pathwise_equivalence() -> None:
    values = _inputs("clear_mon_pic_from_tilemap")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "memory", "clear_call"),
    )
