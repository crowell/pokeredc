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
from verification.harness.sm83_shims import (
    Sm83LoadAHighImmediate,
    Sm83LoadAImmediate,
    Sm83StoreAHighImmediate,
    Sm83StoreAImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
DONE = 0xEFFF

W_BUFFER = 0xCEE9
H_LOADED_ROM_BANK = 0xFFB8
R_ROMB = 0x2000


@dataclass(frozen=True)
class E:
    a: claripy.ast.BV
    f: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    memory: claripy.ast.BV
    result: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class CopyDataStep(angr.SimProcedure):
    """One iteration of CopyData, invoked for FarCopyData's `call CopyData`.

    Models `ld a,[hli]; ld [de],a; inc de; dec bc; ld a,c; or b`. The bank
    switch around the call is abstracted by the surrounding hooks, and the
    source byte (captured as `fetched`) is written to [de].
    """

    def __init__(self, done: int) -> None:
        super().__init__()
        self._done = done

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        a = self.state.globals["fetched"]
        self.state.regs.hl = self.state.regs.hl + 1
        self.state.globals["written"] = a
        self.state.regs.de = self.state.regs.de + 1
        self.state.regs.bc = self.state.regs.bc - 1
        # `ld a,c; or b` overwrites a with the new b|c (mirrors port_copy_data_step).
        self.state.regs.a = self.state.regs.c | self.state.regs.b
        new_bc = self.state.regs.bc
        self.state.regs.f = claripy.If(new_bc == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        self.state.globals["result"] = claripy.If(new_bc == 0, claripy.BVV(1, 8), claripy.BVV(0, 8))
        self.jump(self._done)


def inputs(tag: str) -> dict:
    i = symbolic_registers(tag)
    i["fetched"] = claripy.BVS(f"{tag}_fetched", 8)
    i["written"] = claripy.BVS(f"{tag}_written", 8)
    return i


def assembly(i: dict) -> list[E]:
    loc = symbol_location(SYMBOLS, "FarCopyData")
    p = angr.Project(
        rom_window(ROM, loc.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": loc.address,
        },
    )
    q = loc.address
    p.hook(q, Sm83StoreAImmediate(W_BUFFER, q + 3), length=3)        # ld [wBuffer], a
    p.hook(q + 3, Sm83LoadAHighImmediate(0xB8, q + 5), length=2)    # ldh a, [hLoadedROMBank]
    # q+5 push af (native)
    p.hook(q + 6, Sm83LoadAImmediate(W_BUFFER, q + 9), length=3)    # ld a, [wBuffer]
    p.hook(q + 9, Sm83StoreAHighImmediate(0xB8, q + 11), length=2)  # ldh [hLoadedROMBank], a
    p.hook(q + 11, Sm83StoreAImmediate(R_ROMB, q + 14), length=3)   # ld [rROMB], a
    p.hook(q + 14, CopyDataStep(DONE), length=3)                    # call CopyData -> one step
    s = p.factory.blank_state(addr=q)
    set_assembly_registers(s, i)
    s.globals["fetched"] = i["fetched"]
    s.globals["written"] = i["written"]
    m = p.factory.simulation_manager(s)
    m.explore(find=DONE)
    assert len(m.found) == 1
    x = m.found[0]
    return [
        E(
            **assembly_registers(x),
            memory=claripy.Concat(x.globals["fetched"], x.globals["written"]),
            result=x.globals["result"],
            constraints=tuple(x.solver.constraints),
        )
    ]


def native(i: dict) -> list[E]:
    p = angr.Project(NATIVE_ELF, auto_load_libs=False)
    fn = p.loader.find_symbol("port_copy_data_step")
    assert fn is not None
    s = p.factory.call_state(fn.rebased_addr, NATIVE_STATE)
    store_native_registers(s, NATIVE_STATE, i)
    s.memory.store(NATIVE_STATE + 8, i["fetched"])
    s.memory.store(NATIVE_STATE + 9, i["written"])
    m = p.factory.simulation_manager(s)
    m.run()
    assert not m.errored
    return [
        E(
            **native_registers(x, NATIVE_STATE),
            memory=x.memory.load(NATIVE_STATE + 8, 2),
            result=x.regs.rax[7:0],
            constraints=tuple(x.solver.constraints),
        )
        for x in m.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_transition_equivalence() -> None:
    i = inputs("far_copy_data")
    assert_pathwise_equivalent(assembly(i), native(i), (*REGISTERS, "memory", "result"))


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_exact_body() -> None:
    loc = symbol_location(SYMBOLS, "FarCopyData")
    assert linked_bytes(ROM, loc, 24) == bytes.fromhex("eae9cef0b8f5fae9cee0b8ea0020cdb500f1e0b8ea0020c9")
