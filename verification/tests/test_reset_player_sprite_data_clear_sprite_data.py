from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
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


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification" / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
GB_STACK = 0xD000
GB_RETURN = 0xFFFF
NATIVE_STATE = 0x100000


class FillMemoryInline(angr.SimProcedure):
    """Model the tail ``jp FillMemory``.

    The fill is delegated to the proven ``port_fill_memory`` on the native
    side, so here we only need to reproduce FillMemory's *register* contract:
    advance HL by BC, zero A, set F=Z, zero BC, and preserve DE. HL stays
    symbolic so the equivalence is pathwise over the input HL. (Symbolic
    memory stores cannot be read back reliably under the pcode engine, so the
    actual zero-fill is covered by the exact-linked-body test plus the proven
    ``port_fill_memory``.)
    """

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        st = self.state
        hl = claripy.ZeroExt(8, st.regs.l) | (claripy.ZeroExt(8, st.regs.h) << 8)
        bc = claripy.ZeroExt(8, st.regs.c) | (claripy.ZeroExt(8, st.regs.b) << 8)
        final_hl = (hl + bc) & claripy.BVV(0xFFFF, 16)
        st.regs.h = claripy.Extract(15, 8, final_hl)
        st.regs.l = claripy.Extract(7, 0, final_hl)
        st.regs.b = claripy.BVV(0, 8)
        st.regs.c = claripy.BVV(0, 8)
        st.regs.a = claripy.BVV(0, 8)
        st.regs.f = claripy.BVV(0x40, 8)  # Z80-layout Z
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
    constraints: tuple[claripy.ast.Bool, ...]


def _assembly_endpoint(
    inputs: dict[str, claripy.ast.BV],
) -> Endpoint:
    location = symbol_location(SYMBOLS, "ResetPlayerSpriteData_ClearSpriteData")
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
    # ld bc,nn and xor a run natively; the tail jp FillMemory is the only hook.
    project.hook(base + 0x04, FillMemoryInline(GB_RETURN), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, inputs)
    state.regs.sp = claripy.BVV(GB_STACK, 16)
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    assert len(returned) == 1
    end = returned[0]
    regs = assembly_registers(end)
    return Endpoint(**regs, constraints=tuple(end.solver.constraints))


def _native_endpoint(
    inputs: dict[str, claripy.ast.BV],
) -> Endpoint:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(
        "port_reset_player_sprite_data_clear_sprite_data"
    )
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, claripy.BVV(0, 64)
    )
    store_native_registers(state, NATIVE_STATE, inputs)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    end = manager.deadended[0]
    regs = native_registers(end, NATIVE_STATE)
    return Endpoint(**regs, constraints=tuple(end.solver.constraints))


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_reset_player_sprite_data_clear_sprite_data_symbolic_equivalence() -> None:
    inputs = symbolic_registers("rps")
    assembly = _assembly_endpoint(inputs)
    native = _native_endpoint(inputs)
    assert_pathwise_equivalent(
        [assembly],
        [native],
        ("a", "f", "b", "c", "d", "e", "h", "l"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_reset_player_sprite_data_clear_sprite_data_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "ResetPlayerSpriteData_ClearSpriteData")
    expected = bytes.fromhex("011000afc3e036")
    assert linked_bytes(ROM, location, len(expected)) == expected
