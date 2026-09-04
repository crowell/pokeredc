"""Path-equivalence proof for the default-name list scanner."""

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
    z80_flags_to_sm83,
    symbol_location,
)
from verification.harness.sm83_shims import (
    Sm83CpImmediate,
    Sm83CpRegister,
    Sm83IncRegister,
    Sm83LoadAAtHlIncrement,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
LIST = 0x6AF2
LIST_LENGTH = 0x16
DONE = 0xEFFF
EXPECTED = bytes.fromhex("470e00545d2afe5020fb78b928030c18f2")


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
class BranchOnZero(angr.SimProcedure):
    def __init__(
        self,
        zero_address: int,
        nonzero_address: int,
        compare_register: str | None = None,
    ) -> None:
        super().__init__()
        self._zero_address = zero_address
        self._nonzero_address = nonzero_address
        self._compare_register = compare_register

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        if self._compare_register is not None:
            left = self.state.regs.a
            right = getattr(self.state.regs, self._compare_register)
            result = left - right
            flags = claripy.BVV(0x02, 8)
            flags |= claripy.If(result == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
            flags |= claripy.If(
                (left & 0x0F).ULT(right & 0x0F),
                claripy.BVV(0x10, 8),
                claripy.BVV(0, 8),
            )
            flags |= claripy.If(
                left.ULT(right), claripy.BVV(0x01, 8), claripy.BVV(0, 8)
            )
            self.state.regs.f = flags
        zero = (self.state.regs.f & claripy.BVV(0x40, 8)) != 0
        zero_state = self.state.copy()
        nonzero_state = self.state.copy()
        zero_state.solver.add(zero)
        nonzero_state.solver.add(claripy.Not(zero))
        self.successors.add_successor(
            zero_state, self._zero_address, zero, "Ijk_Boring"
        )
        self.successors.add_successor(
            nonzero_state, self._nonzero_address, claripy.Not(zero), "Ijk_Boring"
        )
class JumpTo(angr.SimProcedure):
    def __init__(self, address: int) -> None:
        super().__init__()
        self._address = address

    def run(self) -> None:  # type: ignore[override]
        self.jump(self._address)



def _assembly_endpoint(state: angr.SimState) -> Endpoint:
    registers = assembly_registers(state)
    # Every terminal path is the CP C equality branch at foundName.
    registers["f"] = claripy.BVV(0xC0, 8)
    return Endpoint(**registers, constraints=tuple(state.solver.constraints))


class FoundNameBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(DONE)


def _assembly(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    loc = symbol_location(SYMBOLS, "GetDefaultName")
    found = symbol_location(SYMBOLS, "GetDefaultName.foundName")
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
    project.hook(base + 0x05, Sm83LoadAAtHlIncrement(base + 0x06), length=1)
    project.hook(base + 0x06, Sm83CpImmediate(0x50, base + 0x08), length=2)
    project.hook(base + 0x0B, Sm83CpRegister("c", base + 0x0C), length=1)
    project.hook(base + 0x0E, Sm83IncRegister("c", base + 0x0F), length=1)
    project.hook(found.address, FoundNameBoundary(), length=1)
    project.hook(base + 0x08, BranchOnZero(base + 0x0A, base + 0x05), length=2)
    project.hook(base + 0x0F, JumpTo(base + 0x03), length=2)
    project.hook(
        base + 0x0C, BranchOnZero(found.address, base + 0x0E, "c"), length=2
    )
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, inputs)
    state.regs.h = LIST >> 8
    state.regs.l = LIST & 0xFF
    state.solver.add(claripy.ULE(state.regs.a, claripy.BVV(2, 8)))
    returned = collect_returns(project, state, DONE)
    return [
        _assembly_endpoint(end)
        for end in returned
    ]

def _native(inputs: dict[str, claripy.ast.BV], names: bytes) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_get_default_name")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.solver.add(claripy.ULE(inputs["a"], claripy.BVV(2, 8)))
    state.memory.store(NATIVE_STATE + 6, claripy.BVV(LIST >> 8, 8))
    state.memory.store(NATIVE_STATE + 7, claripy.BVV(LIST & 0xFF, 8))
    state.memory.store(NATIVE_MEMORY + LIST, names)
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


def _inputs(index: int) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(f"get_default_name_{index}")
    values["a"] = claripy.BVV(index, 8)
    return values


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
@pytest.mark.parametrize("index", (0, 1, 2))
def test_get_default_name_pathwise_equivalence(index: int) -> None:
    inputs = _inputs(index)
    names = linked_bytes(ROM, symbol_location(SYMBOLS, "DefaultNamesPlayerList"), LIST_LENGTH)
    assert_pathwise_equivalent(
        _assembly(inputs),
        _native(inputs, names),
        ("a", "f", "b", "c", "d", "e", "h", "l"),
    )


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_get_default_name_exact_linked_body() -> None:
    loc = symbol_location(SYMBOLS, "GetDefaultName")
    assert linked_bytes(ROM, loc, len(EXPECTED)) == EXPECTED
