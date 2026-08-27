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
from verification.harness.sm83_shims import Sm83LoadAImmediate

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF
W_UPDATE = 0xCFCB
H_BANK = 0xFFB8
R_ROMB = 0x2000
EXPECTED = bytes.fromhex(
    "facbcf3dc0f0b8f53e01e0b8ea0020cd344cf1e0b8ea0020c9"
)


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
    memory: claripy.ast.BV
    call: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _inputs(prefix: str) -> dict[str, object]:
    values = symbolic_registers(prefix)
    values["update"] = claripy.BVS(f"{prefix}_update", 8)
    values["bank"] = claripy.BVS(f"{prefix}_bank", 8)
    values["romb"] = claripy.BVS(f"{prefix}_romb", 8)
    values["post"] = [claripy.BVS(f"{prefix}_post_{r}", 8) for r in REGISTERS]
    values["post_update"] = claripy.BVS(f"{prefix}_post_update", 8)
    values["post_bank"] = claripy.BVS(f"{prefix}_post_bank", 8)
    values["post_romb"] = claripy.BVS(f"{prefix}_post_romb", 8)
    return values


def _setup(state: angr.SimState, values: dict[str, object], base: int) -> None:
    state.memory.store(base + W_UPDATE, values["update"])
    state.memory.store(base + H_BANK, values["bank"])
    state.memory.store(base + R_ROMB, values["romb"])


class DecA(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__(); self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        before = self.state.regs.a
        value = before - 1
        carry = (self.state.regs.f & 1) == 1
        self.state.regs.a = value
        self.state.regs.f = claripy.Concat(
            claripy.BVV(0, 1),
            value == 0,
            claripy.BVV(0, 1),
            (before & 0x0F) == 0,
            claripy.BVV(0, 2),
            claripy.BVV(1, 1),
            carry,
        )
        self.jump(self.next_address)


class RetNz(angr.SimProcedure):
    def __init__(self, taken: int, fallthrough: int) -> None:
        super().__init__(); self.taken = taken; self.fallthrough = fallthrough

    def run(self) -> None:  # type: ignore[override]
        cond = ((self.state.regs.f >> 6) & 1) == 0
        taken = self.state.copy(); fallthrough = self.state.copy()
        taken.solver.add(cond); fallthrough.solver.add(claripy.Not(cond))
        self.inhibit_autoret = True
        self.successors.add_successor(taken, self.taken, cond, "Ijk_Boring")
        self.successors.add_successor(
            fallthrough, self.fallthrough, claripy.Not(cond), "Ijk_Boring"
        )


class Boundary(angr.SimProcedure):
    def __init__(self, values: dict[str, object], native: bool) -> None:
        super().__init__(); self.values = values; self.native = native

    def run(self, ptr: claripy.ast.BV, memory: claripy.ast.BV) -> None:  # type: ignore[override]
        base = NATIVE_MEMORY if self.native else 0
        saved_bank = self.state.memory.load(base + H_BANK, 1)
        saved_f = self.state.regs.f if not self.native else None
        if not self.native:
            self.state.regs.a = 1
            self.state.memory.store(H_BANK, claripy.BVV(1, 8))
            self.state.memory.store(R_ROMB, claripy.BVV(1, 8))
        regs = native_registers(self.state, ptr) if self.native else assembly_registers(self.state)
        snapshot = claripy.Concat(
            *(regs[name] for name in REGISTERS),
            self.state.memory.load(base + W_UPDATE, 1),
            self.state.memory.load(base + H_BANK, 1),
            self.state.memory.load(base + R_ROMB, 1),
        )
        self.state.globals["call"] = snapshot
        post = self.values["post"]
        if self.native:
            for offset, value in enumerate(post):
                self.state.memory.store(ptr + offset, value)
        else:
            for name, value in zip(REGISTERS, post, strict=True):
                setattr(self.state.regs, name, value)
        self.state.memory.store(base + W_UPDATE, self.values["post_update"])
        self.state.memory.store(base + H_BANK, self.values["post_bank"])
        self.state.memory.store(base + R_ROMB, self.values["post_romb"])
        if not self.native:
            # homecall's pop af restores the bank byte loaded before the call.
            self.state.regs.a = saved_bank
            self.state.regs.f = saved_f
            self.state.memory.store(H_BANK, self.state.regs.a)
            self.state.memory.store(R_ROMB, self.state.regs.a)
            self.jump(DONE)


def _endpoint(state: angr.SimState, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    regs = native_registers(state, NATIVE_STATE) if native else assembly_registers(state)
    return Endpoint(
        **regs,
        memory=claripy.Concat(
            state.memory.load(base + W_UPDATE, 1),
            state.memory.load(base + H_BANK, 1),
            state.memory.load(base + R_ROMB, 1),
        ),
        call=state.globals.get("call", claripy.BVV(0, 88)),
        constraints=tuple(state.solver.constraints),
    )


def _assembly(values: dict[str, object]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "UpdateSprites")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    b = location.address
    project.hook(b, Sm83LoadAImmediate(W_UPDATE, b + 3), length=3)
    project.hook(b + 3, DecA(b + 4), length=1)
    project.hook(b + 4, RetNz(DONE, b + 5), length=1)
    project.hook(b + 5, Boundary(values, False), length=19)
    state = project.factory.blank_state(addr=b)
    set_assembly_registers(state, values); _setup(state, values, 0)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=4)
    assert not manager.errored and len(manager.found) == 2
    return [_endpoint(x, False) for x in manager.found]


def _native(values: dict[str, object]) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_update_sprites")
    private = project.loader.find_symbol("port_update_sprites_private")
    assert function is not None and private is not None
    project.hook(private.rebased_addr, Boundary(values, True))
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values); _setup(state, values, NATIVE_MEMORY)
    manager = project.factory.simulation_manager(state); manager.run()
    assert not manager.errored and len(manager.deadended) == 2
    return [_endpoint(x, True) for x in manager.deadended]


@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_update_sprites_pathwise_equivalence() -> None:
    values = _inputs("update_sprites")
    assert_pathwise_equivalent(_assembly(values), _native(values), (*REGISTERS, "memory", "call"))
