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
    Sm83AndImmediate,
    Sm83LoadAImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
DONE = 0xEFFF
SP_ADDR = 0xD000
MON_ADDR = 0xD7F6


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
    def run(self) -> None:  # type: ignore[override]
        self.jump(DONE)


class BranchZ(angr.SimProcedure):
    """Model `JP Z, a16`: take the target when the Z flag is set."""

    def __init__(self, taken: int, n: int) -> None:
        super().__init__()
        self._taken = taken
        self._n = n

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        z = (self.state.regs.f & 0x40) != 0
        self.successors.add_successor(
            self.state.copy(), self._taken, z, "Ijk_Boring"
        )
        self.successors.add_successor(
            self.state.copy(), self._n, claripy.Not(z), "Ijk_Boring"
        )


def _collect(manager: angr.SimulationManager, targets: set[int]) -> list:
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


def _assembly(
    inputs: dict[str, claripy.ast.BV], mem: claripy.ast.BV
) -> list[Endpoint]:
    loc = symbol_location(SYMBOLS, "MtMoonB2FCheckGotAFossil")
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
    # ld a, [0xd7f6] ; and $c0 ; jp z, CheckFightingMapTrainers ; ret
    project.hook(base + 0x00, Sm83LoadAImmediate(MON_ADDR, base + 0x03), length=3)
    project.hook(base + 0x03, Sm83AndImmediate(0xC0, base + 0x05), length=2)
    project.hook(base + 0x05, BranchZ(DONE, base + 0x08), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, inputs)
    state.memory.store(MON_ADDR, mem)
    state.regs.sp = SP_ADDR
    state.memory.store(SP_ADDR, claripy.BVV(DONE, 16), endness="Iend_LE")
    manager = project.factory.simulation_manager(state)
    ends = _collect(manager, {DONE})
    assert ends, "assembly produced no terminal paths"
    return [
        Endpoint(
            **assembly_registers(end), constraints=tuple(end.solver.constraints)
        )
        for end in ends
    ]


def _native(
    inputs: dict[str, claripy.ast.BV], mem: claripy.ast.BV
) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_mt_moon_b2f_check_got_a_fossil")
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, claripy.BVV(0, 64)
    )
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(MON_ADDR, mem)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    end = manager.deadended[0]
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            constraints=tuple(end.solver.constraints),
        )
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_mt_moon_b2f_check_got_a_fossil_symbolic_equivalence() -> None:
    inputs = symbolic_registers("mmb")
    mem = claripy.BVS("mmb_byte", 8)
    assert_pathwise_equivalent(
        _assembly(inputs, mem),
        _native(inputs, mem),
        ("a", "b", "c", "d", "e", "h", "l"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_mt_moon_b2f_check_got_a_fossil_exact_linked_body() -> None:
    loc = symbol_location(SYMBOLS, "MtMoonB2FCheckGotAFossil")
    assert linked_bytes(ROM, loc, 9) == bytes.fromhex(
        "faf6d7e6c0ca1932c9"
    )
