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
    sm83_flags_to_z80,
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


def sm83_compare(a: claripy.ast.BV, b: claripy.ast.BV) -> claripy.ast.BV:
    """SM83 compare flag byte (Z@7 N@6 H@5 C@4) for ``a - b``."""

    z = claripy.If(a == b, claripy.BVV(1, 1), claripy.BVV(0, 1))
    n = claripy.BVV(1, 1)
    h = claripy.If((a & 0xF) < (b & 0xF), claripy.BVV(1, 1), claripy.BVV(0, 1))
    c = claripy.If(a < b, claripy.BVV(1, 1), claripy.BVV(0, 1))
    return claripy.Concat(z, n, h, c, claripy.BVV(0, 4))


class IsItemHM(angr.SimProcedure):
    def __init__(self, n: int) -> None:
        super().__init__()
        self._n = n

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        a = self.state.regs.a
        # cp $c4; jr c, +3: branch when a < $c4.
        taken = a < claripy.BVV(0xC4, 8)
        # Taken: and a  -> f = H, plus Z when a == 0; a unchanged.
        f_and = claripy.BVV(0x10, 8) | claripy.If(
            a == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)
        )
        # Not taken: cp $c9 -> comparison flags (N always).
        f_cp = sm83_flags_to_z80(sm83_compare(a, claripy.BVV(0xC9, 8)))
        self.state.regs.a = a
        self.state.regs.f = claripy.If(taken, f_and, f_cp)
        self.jump(self._n)


def inputs() -> dict:
    return symbolic_registers("ih")


def assembly(i: dict) -> list[E]:
    loc = symbol_location(SYMBOLS, "IsItemHM")
    # cp $c4 / jr c,+3 / cp $c9 / ret / and a / ret  (9 bytes, bank 0).
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
    p.hook(q, IsItemHM(DONE), length=9)
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
    fn = p.loader.find_symbol("port_is_item_hm")
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
    loc = symbol_location(SYMBOLS, "IsItemHM")
    assert linked_bytes(ROM, loc, 9) == bytes.fromhex("fec43803fec9c9a7c9")
