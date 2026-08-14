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


class FillMemorySim(angr.SimProcedure):
    """Inline FillMemory: fill BC bytes at HL with A."""

    def __init__(self, next_address: int, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        state = self.state
        hl = int(state.solver.eval(state.regs.hl))
        bc = int(state.solver.eval(state.regs.bc))
        a = int(state.solver.eval(state.regs.a))
        for i in range(bc):
            state.memory.store(hl + i, claripy.BVV(a, 8))
        state.regs.hl = (hl + bc) & 0xFFFF
        state.regs.bc = 0
        state.regs.a = 0
        self.jump(self._next_address)


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification" / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
GB_RETURN = 0xFFFF
NATIVE_STATE = 0x100000

VRAM_START = 0x8000
VRAM_SIZE = 0x2000
# Observe a few representative bytes: start, middle, end
VRAM_SAMPLE_OFFSETS = (0, VRAM_SIZE // 2, VRAM_SIZE - 1)
FILLMEMORY_ADDR = 0x36E0  # FillMemory address in bank 0

EXPECTED_BODY = bytes.fromhex(
    "210080010020afc3e0363e02eaefc0eaf0c0afea"
)


@dataclass(frozen=True)
class Endpoint:
    m_vram: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _store_inputs(state: angr.SimState) -> None:
    # VRAM should be readable/writable. The test just observes it gets zeroed.
    # Initialize VRAM to non-zero so we can verify it gets cleared.
    for i in range(VRAM_SIZE):
        state.memory.store(VRAM_START + i, claripy.BVV(0xFF, 8))


def _load(end: angr.SimState) -> Endpoint:
    # Read sample VRAM bytes and concatenate
    vram_bytes = claripy.Concat(
        *[end.memory.load(VRAM_START + i, 1) for i in VRAM_SAMPLE_OFFSETS]
    )
    return Endpoint(
        m_vram=vram_bytes,
        constraints=tuple(end.solver.constraints),
    )


def _assembly_endpoint() -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "ClearVram")
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
    # Hook FillMemory which ClearVram tail-calls
    project.hook(FILLMEMORY_ADDR, FillMemorySim(GB_RETURN), length=3)
    state = project.factory.blank_state(addr=location.address)
    _store_inputs(state)
    set_assembly_registers(state, symbolic_registers("cv"))
    state.regs.sp = claripy.BVV(0xE000, 16)
    state.memory.store(0xE000, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    return [_load(end) for end in returned]


def _native_endpoint() -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_clear_vram")
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, claripy.BVV(0, 64)
    )
    store_native_registers(state, NATIVE_STATE, symbolic_registers("cv"))
    _store_inputs(state)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [_load(end) for end in manager.deadended]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_clear_vram_equivalence() -> None:
    assembly = _assembly_endpoint()
    native = _native_endpoint()
    assert_pathwise_equivalent(assembly, native, ("m_vram",))


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_clear_vram_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "ClearVram")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY