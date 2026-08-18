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
    f: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class Sub5ClampTo0(angr.SimProcedure):
    def __init__(self, n: int) -> None:
        super().__init__()
        self._n = n

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        a = self.state.regs.a
        sub = a - 5
        # cp $f0; ret c: return when sub < $f0 (no underflow from sub 5).
        taken = sub < claripy.BVV(0xF0, 8)
        # Taken: a = a - 5, f = N | C (cp $f0 subtract flags).
        # Not taken: a = 0, f = Z.
        self.state.regs.a = claripy.If(taken, sub, claripy.BVV(0, 8))
        f_z80 = claripy.If(taken, claripy.BVV(0x03, 8), claripy.BVV(0x40, 8))
        self.state.regs.f = f_z80
        self.jump(self._n)


def inputs() -> dict:
    return symbolic_registers("s5")


def assembly(i: dict) -> list[E]:
    loc = symbol_location(SYMBOLS, "Sub5ClampTo0")
    # sub a,5 / cp $f0 / ret c / xor a / ret  (7 bytes, bank 29).
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
    p.hook(q, Sub5ClampTo0(DONE), length=7)
    s = p.factory.blank_state(addr=q)
    set_assembly_registers(s, i)
    m = p.factory.simulation_manager(s)
    m.explore(find=DONE, num_find=1)
    assert len(m.found) == 1
    x = m.found[0]
    return [
        E(
            a=x.regs.a,
            f=z80_flags_to_sm83(x.regs.f),
            constraints=tuple(x.solver.constraints),
        )
    ]


def native(i: dict) -> list[E]:
    p = angr.Project(NATIVE_ELF, auto_load_libs=False)
    fn = p.loader.find_symbol("port_sub5_clamp_to0")
    assert fn is not None
    s = p.factory.call_state(fn.rebased_addr, NATIVE_STATE)
    store_native_registers(s, NATIVE_STATE, i)
    m = p.factory.simulation_manager(s)
    m.run()
    assert not m.errored
    return [
        E(
            a=x.memory.load(NATIVE_STATE + 0, 1),
            f=x.memory.load(NATIVE_STATE + 1, 1),
            constraints=tuple(x.solver.constraints),
        )
        for x in m.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_transition_equivalence() -> None:
    i = inputs()
    assert_pathwise_equivalent(assembly(i), native(i), ("a", "f"))


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_exact_body() -> None:
    loc = symbol_location(SYMBOLS, "Sub5ClampTo0")
    assert linked_bytes(ROM, loc, 7) == bytes.fromhex("d605fef0d8afc9")
