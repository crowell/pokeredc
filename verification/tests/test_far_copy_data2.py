from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
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
    Sm83StoreAImmediate,
    Sm83LoadAImmediate,
    Sm83StoreAHighImmediate,
    Sm83LoadAHighImmediate,
)


class CopyDataSim(angr.SimProcedure):
    """Inline ``call CopyData``: copy BC bytes from [HL] to [DE], then return."""

    def __init__(self, next_address: int, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        state = self.state
        h = int(state.solver.eval(state.regs.h))
        l = int(state.solver.eval(state.regs.l))
        d = int(state.solver.eval(state.regs.d))
        e = int(state.solver.eval(state.regs.e))
        b = int(state.solver.eval(state.regs.b))
        c = int(state.solver.eval(state.regs.c))
        hl = (h << 8) | l
        de = (d << 8) | e
        bc = (b << 8) | c
        for _ in range(bc):
            byte = state.memory.load(hl, 1)
            state.memory.store(de, byte)
            hl = (hl + 1) & 0xFFFF
            de = (de + 1) & 0xFFFF
        state.regs.h = claripy.BVV((hl >> 8) & 0xFF, 8)
        state.regs.l = claripy.BVV(hl & 0xFF, 8)
        state.regs.d = claripy.BVV((de >> 8) & 0xFF, 8)
        state.regs.e = claripy.BVV(de & 0xFF, 8)
        state.regs.b = claripy.BVV(0, 8)
        state.regs.c = claripy.BVV(0, 8)
        state.regs.a = claripy.BVV(0, 8)
        self.jump(self._next_address)


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification" / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
GB_RETURN = 0xFFFF
NATIVE_STATE = 0x100000

FAR_COPY_LEN = 0x60  # 96 bytes copied from [HL] to [DE]
SRC_BASE = 0xC400  # concrete source slot
DEST_BASE = 0xCC00  # concrete destination (high-RAM/bank registers are elsewhere)


@lru_cache(maxsize=None)
def _pp_inputs() -> tuple[claripy.ast.BV, ...]:
    # Symbolic source bytes shared between the asm and native endpoints.
    return tuple(claripy.BVS(f"fcd2_src{i}", 8) for i in range(FAR_COPY_LEN))


def _store_inputs(state: angr.SimState) -> None:
    for i, bv in enumerate(_pp_inputs()):
        state.memory.store(SRC_BASE + i, bv)


@dataclass(frozen=True)
class Endpoint:
    m_copy: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _load(end: angr.SimState) -> Endpoint:
    return Endpoint(
        m_copy=claripy.Concat(
            *[end.memory.load(DEST_BASE + i, 1) for i in range(FAR_COPY_LEN)]
        ),
        constraints=tuple(end.solver.constraints),
    )


def _assembly_endpoint(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "FarCopyData2")
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
    # ldh [hROMBankTemp], a (0xE0); ldh a,[hLoadedROMBank] (0xF0); ldh a,
    # [hROMBankTemp] (0xF0); ldh [hLoadedROMBank], a (0xE0); ld [rROMB], a
    # (0xEA) — the bank switch is a no-op for the observable in flat memory.
    project.hook(base + 0x00, Sm83StoreAHighImmediate(0x8B, base + 0x02), length=2)
    project.hook(base + 0x02, Sm83LoadAHighImmediate(0xB8, base + 0x04), length=2)
    project.hook(base + 0x05, Sm83LoadAHighImmediate(0x8B, base + 0x07), length=2)
    project.hook(base + 0x07, Sm83StoreAHighImmediate(0xB8, base + 0x09), length=2)
    project.hook(base + 0x09, Sm83StoreAImmediate(0x2000, base + 0x0C), length=3)
    # call CopyData is modeled as a BC-byte forward copy from [HL] to [DE].
    project.hook(base + 0x0C, CopyDataSim(base + 0x0F), length=3)
    # pop af; ldh [hLoadedROMBank], a (0xE0); ld [rROMB], a (0xEA) restore bank.
    project.hook(base + 0x10, Sm83StoreAHighImmediate(0xB8, base + 0x12), length=2)
    project.hook(base + 0x12, Sm83StoreAImmediate(0x2000, base + 0x15), length=3)
    state = project.factory.blank_state(addr=base)
    _store_inputs(state)
    set_assembly_registers(state, inputs)
    state.regs.sp = claripy.BVV(0xE000, 16)
    state.memory.store(0xE000, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    return [_load(end) for end in returned]


def _native_endpoint(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_far_copy_data2")
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, claripy.BVV(0, 64)
    )
    store_native_registers(state, NATIVE_STATE, inputs)
    _store_inputs(state)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [_load(end) for end in manager.deadended]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_far_copy_data2_symbolic_equivalence() -> None:
    inputs = symbolic_registers("fcd2")
    # Caller-set pointers/length: HL=source, DE=dest, BC=length.
    inputs["h"] = claripy.BVV((SRC_BASE >> 8) & 0xFF, 8)
    inputs["l"] = claripy.BVV(SRC_BASE & 0xFF, 8)
    inputs["d"] = claripy.BVV((DEST_BASE >> 8) & 0xFF, 8)
    inputs["e"] = claripy.BVV(DEST_BASE & 0xFF, 8)
    inputs["b"] = claripy.BVV((FAR_COPY_LEN >> 8) & 0xFF, 8)
    inputs["c"] = claripy.BVV(FAR_COPY_LEN & 0xFF, 8)
    assembly = _assembly_endpoint(inputs)
    native = _native_endpoint(inputs)
    assert_pathwise_equivalent(assembly, native, ("m_copy",))


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_far_copy_data2_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "FarCopyData2")
    # 22-byte body; the trailing e08b belongs to FarCopyData3.
    expected = bytes.fromhex("e08bf0b8f5f08be0b8ea0020cdb500f1e0b8ea0020c9")
    assert linked_bytes(ROM, location, len(expected)) == expected
