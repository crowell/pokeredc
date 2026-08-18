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
    a: claripy.ast.BV
    d: claripy.ast.BV
    value: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class GetHealthBarColor(angr.SimProcedure):
    def __init__(self, n: int) -> None:
        super().__init__()
        self._n = n

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        # Model the whole GetHealthBarColor (bank 0) as one SimProcedure:
        #   a = e
        #   d = (e < 27) ? (e < 10 ? 2 : 1) : 0
        #   ld (hl), d   ; callers point hl at the color destination
        # Flags are a side-effect (out of contract) so they are not modeled.
        e = self.state.regs.e
        a = e
        c27 = claripy.ULT(e, claripy.BVV(27, 8))
        c10 = claripy.ULT(e, claripy.BVV(10, 8))
        d = claripy.If(
            c27, claripy.If(c10, claripy.BVV(2, 8), claripy.BVV(1, 8)), claripy.BVV(0, 8)
        )
        self.state.regs.a = a
        self.state.regs.d = d
        self.state.memory.store(self.state.regs.hl, d)
        self.jump(self._n)


def inputs(p: str) -> dict:
    return symbolic_registers(p)


def assembly(i: dict) -> list[E]:
    loc = symbol_location(SYMBOLS, "GetHealthBarColor")
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
    p.hook(q, GetHealthBarColor(DONE), length=15)
    s = p.factory.blank_state(addr=q)
    set_assembly_registers(s, i)
    m = p.factory.simulation_manager(s)
    m.explore(find=DONE, num_find=1)
    assert len(m.found) == 1
    x = m.found[0]
    return [
        E(
            a=x.regs.a,
            d=x.regs.d,
            value=x.memory.load(x.regs.hl, 1),
            constraints=tuple(x.solver.constraints),
        )
    ]


def native(i: dict) -> list[E]:
    p = angr.Project(NATIVE_ELF, auto_load_libs=False)
    fn = p.loader.find_symbol("port_get_health_bar_color")
    assert fn
    s = p.factory.call_state(fn.rebased_addr, NATIVE_STATE)
    store_native_registers(s, NATIVE_STATE, i)
    m = p.factory.simulation_manager(s)
    m.run()
    assert not m.errored
    x = m.deadended[0]
    nr = native_registers(x, NATIVE_STATE)
    return [
        E(
            a=nr["a"],
            d=nr["d"],
            value=x.memory.load(NATIVE_STATE + 8, 1),
            constraints=tuple(x.solver.constraints),
        )
    ]


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native")
def test_transition_equivalence() -> None:
    i = inputs("ghb")
    assert_pathwise_equivalent(assembly(i), native(i), ("a", "d", "value"))


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_exact_body() -> None:
    loc = symbol_location(SYMBOLS, "GetHealthBarColor")
    assert linked_bytes(ROM, loc, 15) == bytes.fromhex("7bfe1b16003006fe0a1430011472c9")
