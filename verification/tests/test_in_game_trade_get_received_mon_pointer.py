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
from verification.harness.sm83_shims import Sm83DecRegister, Sm83LoadAImmediate


ROOT = Path(__file__).resolve().parents[2]
VERIFY = ROOT / "verification"
NATIVE_ELF = VERIFY / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
LOOP_BOUNDARY = 0xEFFE
RETURN_BOUNDARY = 0xEFFF
NATIVE_STATE = 0x100000
W_PARTY_COUNT = 0xD163


class Boundary(angr.SimProcedure):
    def __init__(self, address: int) -> None:
        super().__init__()
        self._address = address

    def run(self) -> None:  # type: ignore[override]
        self.jump(self._address)


class AddOnce(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        if self.state.globals.get("add_n_entered", False):
            self.jump(LOOP_BOUNDARY)
            return
        self.state.globals["add_n_entered"] = True
        left = self.state.regs.hl
        right = self.state.regs.bc
        wide = claripy.ZeroExt(1, left) + claripy.ZeroExt(1, right)
        low = claripy.ZeroExt(1, left & 0x0FFF) + claripy.ZeroExt(1, right & 0x0FFF)
        flags = self.state.regs.f & 0x40
        flags |= claripy.If(low > 0x0FFF, claripy.BVV(0x10, 8), claripy.BVV(0, 8))
        flags |= claripy.ZeroExt(7, wide[16])
        self.state.regs.hl = wide[15:0]
        self.state.regs.f = flags
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
    w_party_count: claripy.ast.BV
    continuation: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _inputs(tag: str) -> dict[str, claripy.ast.BV]:
    regs = symbolic_registers(tag)
    regs["w_party_count"] = claripy.BVS(f"{tag}_wparty", 8)
    return regs


def _collect_boundaries(manager: angr.SimulationManager) -> list[angr.SimState]:
    manager.stashes["found"] = []
    while manager.active:
        manager.move(
            from_stash="active",
            to_stash="found",
            filter_func=lambda state: state.addr in {LOOP_BOUNDARY, RETURN_BOUNDARY},
        )
        if manager.active:
            manager.step()
    assert not manager.errored
    return manager.found


def _assembly_begin(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    wrapper = symbol_location(SYMBOLS, "InGameTrade_GetReceivedMonPointer")
    addntimes = symbol_location(SYMBOLS, "AddNTimes")
    loop = addntimes.address + 2
    project = angr.Project(
        rom_window(ROM, wrapper.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": wrapper.address,
        },
    )
    # `ld a, [wPartyCount]` is the Game Boy LD A,[a16] (opcode FA), which the
    # Z80 P-code engine does not decode; shim it to load from the RAM address.
    w_party_count_addr = symbol_location(SYMBOLS, "wPartyCount").address
    project.hook(
        wrapper.address,
        Sm83LoadAImmediate(w_party_count_addr, wrapper.address + 3),
        length=3,
    )
    project.hook(loop, Boundary(LOOP_BOUNDARY), length=1)
    state = project.factory.blank_state(addr=wrapper.address)
    set_assembly_registers(state, {k: inputs[k] for k in REGISTERS})
    state.regs.sp = 0xD000
    state.memory.store(0xD000, claripy.BVV(RETURN_BOUNDARY, 16), endness="Iend_LE")
    state.memory.store(
        W_PARTY_COUNT, inputs["w_party_count"], 1, endness="Iend_LE"
    )
    manager = project.factory.simulation_manager(state)
    found = _collect_boundaries(manager)
    return [
        Endpoint(
            **assembly_registers(end),
            w_party_count=end.memory.load(W_PARTY_COUNT, 1, endness="Iend_LE"),
            continuation=claripy.BVV(
                1 if end.addr == LOOP_BOUNDARY else 0, 8
            ),
            constraints=tuple(end.solver.constraints),
        )
        for end in found
    ]


def _assembly_step(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    wrapper = symbol_location(SYMBOLS, "InGameTrade_GetReceivedMonPointer")
    addntimes = symbol_location(SYMBOLS, "AddNTimes")
    loop = addntimes.address + 2
    wrapper_ret = wrapper.address + 9
    project = angr.Project(
        rom_window(ROM, wrapper.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": loop,
        },
    )
    project.hook(loop, AddOnce(loop + 1), length=1)
    project.hook(loop + 1, Sm83DecRegister("a", loop + 2), length=1)
    project.hook(loop + 4, Boundary(RETURN_BOUNDARY), length=1)
    state = project.factory.blank_state(addr=loop)
    set_assembly_registers(state, {k: inputs[k] for k in REGISTERS})
    state.regs.sp = 0xD000
    state.memory.store(0xD000, claripy.BVV(RETURN_BOUNDARY, 16), endness="Iend_LE")
    state.memory.store(
        W_PARTY_COUNT, inputs["w_party_count"], 1, endness="Iend_LE"
    )
    manager = project.factory.simulation_manager(state)
    found = _collect_boundaries(manager)
    return [
        Endpoint(
            **assembly_registers(end),
            w_party_count=end.memory.load(W_PARTY_COUNT, 1, endness="Iend_LE"),
            continuation=claripy.BVV(
                1 if end.addr == LOOP_BOUNDARY else 0, 8
            ),
            constraints=tuple(end.solver.constraints),
        )
        for end in found
    ]


def _native(c_symbol: str, inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(c_symbol)
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, {k: inputs[k] for k in REGISTERS})
    state.memory.store(
        NATIVE_STATE + 8, inputs["w_party_count"], 1, endness="Iend_LE"
    )
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            w_party_count=end.memory.load(NATIVE_STATE + 8, 1, endness="Iend_LE"),
            continuation=claripy.If(
                end.regs.rax[7:0] == 0, claripy.BVV(1, 8), claripy.BVV(0, 8)
            ),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_in_game_trade_get_received_mon_pointer_begin_symbolic_equivalence() -> None:
    inputs = _inputs("in_game_trade_begin")
    assert_pathwise_equivalent(
        _assembly_begin(inputs),
        _native("port_in_game_trade_get_received_mon_pointer_begin", inputs),
        (*REGISTERS, "w_party_count", "continuation"),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_in_game_trade_get_received_mon_pointer_step_inductive_equivalence() -> None:
    inputs = _inputs("in_game_trade_step")
    assert_pathwise_equivalent(
        _assembly_step(inputs),
        _native("port_in_game_trade_get_received_mon_pointer_step", inputs),
        (*REGISTERS, "w_party_count", "continuation"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_in_game_trade_get_received_mon_pointer_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "InGameTrade_GetReceivedMonPointer")
    assert linked_bytes(ROM, location, 10) == bytes.fromhex("fa63d13dcd873a5d54c9")
