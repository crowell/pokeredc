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
    Sm83LoadAFromRegister,
    Sm83StoreAHighImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
DONE = 0xEFFF

H_MULTIPLICAND = 0xFF96
H_MULTIPLICAND_1 = 0xFF97
H_MULTIPLICAND_2 = 0xFF98
H_MULTIPLIER = 0xFF99


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
    m0: claripy.ast.BV
    m1: claripy.ast.BV
    m2: claripy.ast.BV
    m3: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class Boundary(angr.SimProcedure):
    """The `jp Multiply` tail call is the explicit boundary."""

    def run(self) -> None:  # type: ignore[override]
        self.jump(DONE)


def _assembly(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    loc = symbol_location(SYMBOLS, "CalcDSquared")
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
    # xor a                     ; clears A, sets Z
    # ldh [hMultiplicand], a    ; hMultiplicand   = 0
    # ldh [hMultiplicand+1], a  ; hMultiplicand+1 = 0
    # ld a, d                   ; A = d, flags cleared
    # ldh [hMultiplicand+2], a  ; hMultiplicand+2 = d
    # ldh [hMultiplier], a      ; hMultiplier     = d
    # jp Multiply               ; boundary
    project.hook(base + 0x01, Sm83StoreAHighImmediate(0x96, base + 0x03), length=2)
    project.hook(base + 0x03, Sm83StoreAHighImmediate(0x97, base + 0x05), length=2)
    project.hook(base + 0x05, Sm83LoadAFromRegister("d", base + 0x06), length=1)
    project.hook(base + 0x06, Sm83StoreAHighImmediate(0x98, base + 0x08), length=2)
    project.hook(base + 0x08, Sm83StoreAHighImmediate(0x99, base + 0x0A), length=2)
    project.hook(base + 0x0A, Boundary(), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, inputs)
    for addr in (
        H_MULTIPLICAND,
        H_MULTIPLICAND_1,
        H_MULTIPLICAND_2,
        H_MULTIPLIER,
    ):
        state.memory.store(addr, claripy.BVV(0, 8))
    state.regs.sp = 0xD000
    state.memory.store(0xD000, claripy.BVV(0xFFFF, 16), endness="Iend_LE")
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert len(manager.found) == 1
    end = manager.found[0]
    return [
        Endpoint(
            **assembly_registers(end),
            m0=end.memory.load(H_MULTIPLICAND, 1),
            m1=end.memory.load(H_MULTIPLICAND_1, 1),
            m2=end.memory.load(H_MULTIPLICAND_2, 1),
            m3=end.memory.load(H_MULTIPLIER, 1),
            constraints=tuple(end.solver.constraints),
        )
    ]


def _native(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_calc_d_squared")
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
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            m0=end.memory.load(H_MULTIPLICAND, 1),
            m1=end.memory.load(H_MULTIPLICAND_1, 1),
            m2=end.memory.load(H_MULTIPLICAND_2, 1),
            m3=end.memory.load(H_MULTIPLIER, 1),
            constraints=tuple(end.solver.constraints),
        )
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_calc_d_squared_symbolic_equivalence() -> None:
    inputs = symbolic_registers("cds")
    assert_pathwise_equivalent(
        _assembly(inputs),
        _native(inputs),
        (*REGISTERS, "m0", "m1", "m2", "m3"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_calc_d_squared_exact_linked_body() -> None:
    loc = symbol_location(SYMBOLS, "CalcDSquared")
    assert linked_bytes(ROM, loc, 13) == bytes.fromhex("afe096e0977ae098e099c3ac38")
