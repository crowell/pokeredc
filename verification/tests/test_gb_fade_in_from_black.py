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
    Sm83DecRegister,
    Sm83LoadAAtHlIncrement,
    Sm83StoreAHighImmediate,
)


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
RETURN = 0xEFFF
PALETTE_REGISTERS = (0xFF47, 0xFF48, 0xFF49)


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
    palettes: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class DelayFramesTerminal(angr.SimProcedure):
    """Terminal behavior of the independently proven DelayFrames(C=8)."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.c = claripy.BVV(0, 8)
        # Z80 layout for the final SM83 Z|N flags from DEC C.
        self.state.regs.f = claripy.BVV(0x42, 8)
        self.jump(self._next_address)


class ReturnBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(RETURN)


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "GBFadeInFromBlack")
    base = location.address
    project = angr.Project(
        rom_window(ROM, location.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": base,
        },
    )
    for offset in (12, 15, 18):
        project.hook(
            base + offset,
            Sm83LoadAAtHlIncrement(base + offset + 1),
            length=1,
        )
    for offset, hardware_offset in ((13, 0x47), (16, 0x48), (19, 0x49)):
        project.hook(
            base + offset,
            Sm83StoreAHighImmediate(hardware_offset, base + offset + 2),
            length=2,
        )
    project.hook(base + 23, DelayFramesTerminal(base + 26), length=3)
    project.hook(base + 26, Sm83DecRegister("b", base + 27), length=1)
    project.hook(base + 29, ReturnBoundary(), length=1)

    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    for address in PALETTE_REGISTERS:
        state.memory.store(address, values[f"palette_{address:04x}"])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN)
    assert not manager.errored
    assert len(manager.found) == 1
    return [
        Endpoint(
            **assembly_registers(end),
            palettes=claripy.Concat(
                *(end.memory.load(address, 1) for address in PALETTE_REGISTERS)
            ),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "FadePal1")
    palette_bytes = linked_bytes(ROM, location, 12)
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_gb_fade_in_from_black")
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_MEMORY + location.address, palette_bytes)
    for address in PALETTE_REGISTERS:
        state.memory.store(
            NATIVE_MEMORY + address, values[f"palette_{address:04x}"]
        )
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            palettes=claripy.Concat(
                *(
                    end.memory.load(NATIVE_MEMORY + address, 1)
                    for address in PALETTE_REGISTERS
                )
            ),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run red")
def test_gb_fade_in_from_black_pathwise_equivalence() -> None:
    values = symbolic_registers("gb_fade_in_from_black")
    for address in PALETTE_REGISTERS:
        values[f"palette_{address:04x}"] = claripy.BVS(
            f"gb_fade_in_from_black_palette_{address:04x}", 8
        )
    assert_pathwise_equivalent(
        _assembly(values), _native(values), (*REGISTERS, "palettes")
    )
