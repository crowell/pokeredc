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
    Sm83CpImmediate,
    Sm83LoadAAtHlDecrement,
    Sm83LoadAAtHlIncrement,
    Sm83LoadAImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
DONE = 0xEFFF

PARTY_COUNT_ADDR = 0xD89C
AISEM_MON_OT = 0xD8A5
AISEM_STRIDE = 0x2C
# wEnemyMonPartyCount is bounded by the maximum party size.
MAX_PARTY = 6


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


class Boundary(angr.SimProcedure):
    """The external tail `jp nc` is the explicit path boundary."""

    def run(self) -> None:  # type: ignore[override]
        self.jump(DONE)


class BranchNC(angr.SimProcedure):
    """SM83 ``JP NC, a16``: take `taken` when the carry flag is clear."""

    def __init__(self, taken: int, n: int) -> None:
        super().__init__()
        self._taken = taken
        self._n = n

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        carry = (self.state.regs.f & 1) != 0
        self.successors.add_successor(
            self.state.copy(), self._taken, claripy.Not(carry), "Ijk_Boring"
        )
        self.successors.add_successor(
            self.state.copy(), self._n, carry, "Ijk_Boring"
        )


def _collect(manager: angr.sim_manager.SimulationManager, targets: set[int]) -> list:
    manager.stashes["found"] = []
    while manager.active:
        manager.move(
            from_stash="active",
            to_stash="found",
            filter_func=lambda x: x.addr in targets,
        )
        if manager.active:
            manager.step()
    return manager.found


def _make_struct(count: int) -> list[claripy.ast.BV]:
    """Shared symbolic bytes for the party structs (2 bytes per slot)."""
    return [claripy.BVS(f"ai_struct_{i}", 8) for i in range(count * 2)]


def _store_struct(state, struct: list[claripy.ast.BV]) -> None:
    for i, bv in enumerate(struct):
        k = i // 2
        off = i % 2
        state.memory.store(AISEM_MON_OT + AISEM_STRIDE * k + off, bv)


def _assembly(
    inputs: dict[str, claripy.ast.BV],
    count: claripy.ast.BV,
    struct: list[claripy.ast.BV],
) -> list[Endpoint]:
    loc = symbol_location(SYMBOLS, "AISwitchIfEnoughMons")
    base = loc.address
    project = angr.Project(
        rom_window(ROM, loc.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": base,
        },
    )
    # ld a, [wEnemyMonPartyCount] ; ld c, a   ; c = loop count
    # ld hl, wEnemyMonOT          ; ld d, 0   ; HL = struct base, D = 0
    # .loop:
    #   ld a, [hli]  ; ld b, a   ; ld a, [hld]  ; or b
    #   jr z, .next  ; inc d
    # .next: push bc ; ld bc, $2c ; add hl, bc ; pop bc ; dec c ; jr nz, .loop
    #   ld a, d ; cp 2 ; jp nc, switch (boundary) ; and a ; ret
    project.hook(base + 0x00, Sm83LoadAImmediate(PARTY_COUNT_ADDR, base + 0x03), length=3)
    project.hook(base + 0x09, Sm83LoadAAtHlIncrement(base + 0x0A), length=1)
    project.hook(base + 0x0B, Sm83LoadAAtHlDecrement(base + 0x0C), length=1)
    project.hook(base + 0x1A, Sm83CpImmediate(2, base + 0x1C), length=2)
    project.hook(base + 0x1C, BranchNC(DONE, base + 0x1F), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, inputs)
    state.memory.store(PARTY_COUNT_ADDR, count)
    _store_struct(state, struct)
    state.regs.sp = 0xD000
    state.memory.store(0xD000, claripy.BVV(DONE, 16), endness="Iend_LE")
    manager = project.factory.simulation_manager(state)
    ends = _collect(manager, {DONE})
    return [
        Endpoint(**assembly_registers(end), constraints=tuple(end.solver.constraints))
        for end in ends
    ]


def _native(
    inputs: dict[str, claripy.ast.BV],
    count: claripy.ast.BV,
    struct: list[claripy.ast.BV],
) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_ai_switch_if_enough_mons")
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, claripy.BVV(0, 64)
    )
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(PARTY_COUNT_ADDR, count)
    _store_struct(state, struct)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("c", range(1, MAX_PARTY + 1))
def test_ai_switch_if_enough_mons_symbolic_equivalence(c: int) -> None:
    inputs = symbolic_registers("ab cdehl")
    count = claripy.BVV(c, 8)
    struct = _make_struct(c)
    assert_pathwise_equivalent(
        _assembly(inputs, count, struct),
        _native(inputs, count, struct),
        ("a", "c", "d", "e", "h", "l"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_ai_switch_if_enough_mons_exact_linked_body() -> None:
    loc = symbol_location(SYMBOLS, "AISwitchIfEnoughMons")
    assert linked_bytes(ROM, loc, 33) == bytes.fromhex(
        "fa9cd84f21a5d816002a473ab0280114c5012c0009c10d20f07afe02d24b67a7c9"
    )
