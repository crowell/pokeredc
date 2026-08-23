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
from verification.harness.rom import rom_window, symbol_location
from verification.harness.sm83_shims import (
    Sm83DecRegister,
    Sm83StoreAAtHlIncrement,
)


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
RETURN = 0xEFFF
TILEMAP_LENGTH = 0x0400


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
    tilemap: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class LoadAPreserveFlags(angr.SimProcedure):
    def __init__(self, value: int, next_address: int) -> None:
        super().__init__()
        self._value = value
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(self._value, 8)
        self.jump(self._next_address)


class ReturnBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(RETURN)


def _assembly(
    values: dict[str, claripy.ast.BV], tilemap_start: int
) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "ClearBgMap")
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
    project.hook(base, LoadAPreserveFlags(0x7F, base + 2), length=2)
    project.hook(base + 9, Sm83StoreAAtHlIncrement(base + 10), length=1)
    project.hook(base + 10, Sm83DecRegister("e", base + 11), length=1)
    project.hook(base + 13, Sm83DecRegister("d", base + 14), length=1)
    project.hook(base + 16, ReturnBoundary(), length=1)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.memory.store(tilemap_start, values["tilemap"])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN)
    assert not manager.errored
    assert len(manager.found) == 1
    return [
        Endpoint(
            **assembly_registers(end),
            tilemap=end.memory.load(tilemap_start, TILEMAP_LENGTH),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(
    values: dict[str, claripy.ast.BV], tilemap_start: int
) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_clear_bg_map")
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_MEMORY + tilemap_start, values["tilemap"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            tilemap=end.memory.load(
                NATIVE_MEMORY + tilemap_start, TILEMAP_LENGTH
            ),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run red")
@pytest.mark.parametrize("high", (0x98, 0x9C))
def test_clear_bg_map_pathwise_equivalence(high: int) -> None:
    values = symbolic_registers(f"clear_bg_map_{high:02x}")
    values["h"] = claripy.BVV(high, 8)
    values["tilemap"] = claripy.BVS(
        f"clear_bg_map_{high:02x}_tilemap", TILEMAP_LENGTH * 8
    )
    tilemap_start = high << 8
    assert_pathwise_equivalent(
        _assembly(values, tilemap_start),
        _native(values, tilemap_start),
        (*REGISTERS, "tilemap"),
    )
