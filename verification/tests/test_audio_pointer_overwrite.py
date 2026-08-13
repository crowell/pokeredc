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


ROOT = Path(__file__).resolve().parents[2]
VERIFY = ROOT / "verification"
NATIVE_ELF = VERIFY / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
BOUNDARY = 0xEFFF
NATIVE_STATE = 0x100000
PORTS = (
    ("Audio1_OverwriteChannelPointer", "port_audio1_overwrite_channel_pointer"),
    ("Audio2_OverwriteChannelPointer", "port_audio2_overwrite_channel_pointer"),
)


class StoreIncrementBoundary(angr.SimProcedure):
    def __init__(self, output: str, next_address: int) -> None:
        super().__init__()
        self._output = output
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.globals[self._output] = self.state.regs.a
        self.state.regs.hl = self.state.regs.hl + 1
        self.jump(self._next_address)


class ReturnBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(BOUNDARY)


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
    first: claripy.ast.BV
    second: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _assembly(symbol: str, inputs: dict[str, claripy.ast.BV]) -> Endpoint:
    location = symbol_location(SYMBOLS, symbol)
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
    project.hook(
        location.address + 1,
        StoreIncrementBoundary("first_output", location.address + 2),
        length=1,
    )
    project.hook(
        location.address + 3,
        StoreIncrementBoundary("second_output", location.address + 4),
        length=1,
    )
    project.hook(location.address + 4, ReturnBoundary(), length=1)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, inputs)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=BOUNDARY)
    assert not manager.errored
    assert len(manager.found) == 1
    end = manager.found[0]
    return Endpoint(
        **assembly_registers(end),
        first=end.globals["first_output"],
        second=end.globals["second_output"],
        constraints=tuple(end.solver.constraints),
    )


def _native(c_symbol: str, inputs: dict[str, claripy.ast.BV]) -> Endpoint:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(c_symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, inputs["first"])
    state.memory.store(NATIVE_STATE + 9, inputs["second"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    end = manager.deadended[0]
    return Endpoint(
        **native_registers(end, NATIVE_STATE),
        first=end.memory.load(NATIVE_STATE + 8, 1),
        second=end.memory.load(NATIVE_STATE + 9, 1),
        constraints=tuple(end.solver.constraints),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("symbol,c_symbol", PORTS)
def test_audio_overwrite_channel_pointer_symbolic_equivalence(
    symbol: str, c_symbol: str
) -> None:
    inputs = symbolic_registers(symbol.lower())
    inputs["first"] = claripy.BVS(f"{symbol.lower()}_first", 8)
    inputs["second"] = claripy.BVS(f"{symbol.lower()}_second", 8)
    assert_pathwise_equivalent(
        [_assembly(symbol, inputs)],
        [_native(c_symbol, inputs)],
        (*REGISTERS, "first", "second"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("symbol,_c_symbol", PORTS)
def test_audio_overwrite_channel_pointer_exact_linked_body(
    symbol: str, _c_symbol: str
) -> None:
    location = symbol_location(SYMBOLS, symbol)
    assert linked_bytes(ROM, location, 5) == bytes.fromhex("7b227a22c9")
