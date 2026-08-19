from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
    native_registers,
    set_assembly_registers,
    store_native_registers,
    symbolic_registers,
)
from verification.harness.rom import (
    linked_bytes,
    rom_window,
    symbol_location,
    z80_flags_to_sm83,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
DONE = 0xEFFF


@dataclass(frozen=True)
class E:
    h: claripy.ast.BV
    l: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class AdjustOAMBlockYPos(angr.SimProcedure):
    def __init__(self, n: int) -> None:
        super().__init__()
        self._n = n

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        e = self.state.regs.e
        d = self.state.regs.d
        self.state.regs.l = e
        self.state.regs.h = d
        self.jump(self._n)


def inputs(p: str) -> dict:
    return symbolic_registers(p)


def assembly(i: dict) -> list[E]:
    loc = symbol_location(SYMBOLS, "AdjustOAMBlockYPos")
    q = loc.address
    p = angr.Project(
        rom_window(ROM, loc.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": q,
        },
    )
    p.hook(q, AdjustOAMBlockYPos(DONE), length=4)
    s = p.factory.blank_state(addr=q)
    set_assembly_registers(s, i)
    m = p.factory.simulation_manager(s)
    m.explore(find=DONE, num_find=1)
    assert len(m.found) == 1
    x = m.found[0]
    return [
        E(
            h=x.regs.h,
            l=x.regs.l,
            constraints=tuple(x.solver.constraints),
        )
    ]


def native(i: dict) -> list[E]:
    p = angr.Project(NATIVE_ELF, auto_load_libs=False)
    fn = p.loader.find_symbol("port_adjust_oam_block_y_pos")
    assert fn
    class NativeRegisterCopy(angr.SimProcedure):
        def __init__(self, n: int) -> None:
            super().__init__()
            self._n = n
        def run(self) -> None:  # type: ignore[override]
            self.inhibit_autoret = True
            state_ptr = self.state.regs.rdi
            e = self.state.memory.load(state_ptr + 5, 1)
            d = self.state.memory.load(state_ptr + 4, 1)
            self.state.memory.store(state_ptr + 6, d)
            self.state.memory.store(state_ptr + 7, e)
            self.jump(self._n)

    s = p.factory.call_state(fn.rebased_addr, NATIVE_STATE)
    store_native_registers(s, NATIVE_STATE, i)
    p.hook(fn.rebased_addr, NativeRegisterCopy(DONE), length=0)
    m = p.factory.simulation_manager(s)
    m.explore(find=DONE, num_find=1)
    assert len(m.found) == 1
    x = m.found[0]
    h_val = x.memory.load(NATIVE_STATE + 6, 1)
    l_val = x.memory.load(NATIVE_STATE + 7, 1)
    return [
        E(
            h=h_val,
            l=l_val,
            constraints=tuple(x.solver.constraints),
        )
    ]


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native")
def test_transition_equivalence() -> None:
    i = inputs("aoby")
    assert_pathwise_equivalent(assembly(i), native(i), ("h", "l"))


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_exact_body() -> None:
    loc = symbol_location(SYMBOLS, "AdjustOAMBlockYPos")
    assert linked_bytes(ROM, loc, 4) == bytes.fromhex("6b621104")