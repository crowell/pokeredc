from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
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
    Sm83LoadAImmediate,
    Sm83StoreAImmediate,
)


class CopyDataSim(angr.SimProcedure):
    """Inline ``call CopyData``: copy BC bytes from [HL] to [DE], then return."""

    def __init__(self, next_address: int, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        state = self.state
        hl = int(state.solver.eval(state.regs.hl))
        de = int(state.solver.eval(state.regs.de))
        bc = int(state.solver.eval(state.regs.bc))
        data = state.memory.load(hl, bc)
        state.memory.store(de, data)
        state.regs.hl = (hl + bc) & 0xFFFF
        state.regs.de = (de + bc) & 0xFFFF
        state.regs.bc = 0
        state.regs.a = 0
        self.jump(self._next_address)


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification" / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
GB_RETURN = 0xFFFF
NATIVE_STATE = 0x100000

W_NAMED_OBJECT_INDEX = 0xD11E
W_NAME_BUFFER = 0xCD6D
HIDDEN_PREFIX = 0x303E
TECHNICAL_PREFIX = 0x303C

# Concrete machine ids spanning TM and HM ranges.
MACHINE_IDS = [0xC9, 0xE1, 0xFA, 0xC4, 0xC8]

EXPECTED_BODY = bytes.fromhex(
    "e5d5c5fa1ed1f5fec9300dc605ea1ed1213e300102001806213c30010200116dcd"
    "cdb500fa1ed1d6c806f6d60a38030418f9c60af5781213f106f68012133e5012f1"
    "ea1ed1c1d1e1c9"
)


@dataclass(frozen=True)
class Endpoint:
    m_name: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _store_inputs(state: angr.SimState, machine_id: int) -> None:
    state.memory.store(W_NAMED_OBJECT_INDEX, claripy.BVV(machine_id, 8))
    hp = linked_bytes(ROM, symbol_location(SYMBOLS, "HiddenPrefix"), 2)
    tp = linked_bytes(ROM, symbol_location(SYMBOLS, "TechnicalPrefix"), 2)
    for i, byte in enumerate(hp):
        state.memory.store(HIDDEN_PREFIX + i, claripy.BVV(byte, 8))
    for i, byte in enumerate(tp):
        state.memory.store(TECHNICAL_PREFIX + i, claripy.BVV(byte, 8))
    for i in range(5):
        state.memory.store(W_NAME_BUFFER + i, claripy.BVV(0, 8))


def _load(end: angr.SimState) -> Endpoint:
    return Endpoint(
        m_name=claripy.Concat(
            *[end.memory.load(W_NAME_BUFFER + i, 1) for i in range(5)]
        ),
        constraints=tuple(end.solver.constraints),
    )


def _assembly_endpoint(machine_id: int) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "GetMachineName")
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
    project.hook(base + 0x03, Sm83LoadAImmediate(0xD11E, base + 0x06), length=3)
    project.hook(base + 0x0D, Sm83StoreAImmediate(0xD11E, base + 0x10), length=3)
    project.hook(base + 0x21, CopyDataSim(base + 0x24), length=3)
    project.hook(base + 0x24, Sm83LoadAImmediate(0xD11E, base + 0x27), length=3)
    project.hook(base + 0x42, Sm83StoreAImmediate(0xD11E, base + 0x45), length=3)
    state = project.factory.blank_state(addr=base)
    _store_inputs(state, machine_id)
    set_assembly_registers(state, symbolic_registers("gm"))
    state.regs.sp = claripy.BVV(0xE000, 16)
    state.memory.store(0xE000, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    return [_load(end) for end in returned]


def _native_endpoint(machine_id: int) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_get_machine_name")
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, claripy.BVV(0, 64)
    )
    store_native_registers(state, NATIVE_STATE, symbolic_registers("gm"))
    _store_inputs(state, machine_id)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [_load(end) for end in manager.deadended]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("machine_id", MACHINE_IDS, ids=[hex(i) for i in MACHINE_IDS])
def test_get_machine_name_equivalence(machine_id: int) -> None:
    assembly = _assembly_endpoint(machine_id)
    native = _native_endpoint(machine_id)
    assert_pathwise_equivalent(assembly, native, ("m_name",))


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_get_machine_name_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "GetMachineName")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY
