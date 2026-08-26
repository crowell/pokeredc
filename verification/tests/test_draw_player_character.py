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
from verification.harness.rom import (
    collect_returns,
    linked_bytes,
    rom_window,
    sm83_flags_to_z80,
    symbol_location,
)
from verification.harness.sm83_shims import (
    Sm83AddImmediate,
    Sm83AddRegister,
    Sm83DecRegister,
    Sm83IncRegister,
    Sm83LoadAImmediate,
    Sm83StoreAAtHlIncrement,
    Sm83StoreAImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xFFFF
SHADOW_OAM = 0xC300
OAM_SIZE = 160
OAM_TILE = 0xCD3D
MARKER = 0x1234
REQUESTED_BANK_OFFSET = 168
LOADED_BANK_OFFSET = 169
ROM_BANK_OFFSET = 170
OAM_TILE_OFFSET = 171
EXPECTED_BODY = bytes.fromhex(
    "21a8661100800130023e04cdf717cd8200afea3dcd2100c3115a600607d50e05"
    "7a227b22c6085ffa3dcd223cea3dcd230d20edd13e0882570520e2c9"
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
    banks: claripy.ast.BV
    oam: claripy.ast.BV
    oam_tile: claripy.ast.BV
    marker: claripy.ast.BV
    calls: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class XorA(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x40, 8)
        self.jump(self.continuation)


def _assembly_register_bytes(state: angr.SimState) -> claripy.ast.BV:
    registers = assembly_registers(state)
    return claripy.Concat(*(registers[name] for name in REGISTERS))


class AssemblyFarCopyData2(angr.SimProcedure):
    """Arbitrary matching transition of the independently proven callee."""

    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["calls"] += (
            claripy.Concat(
                claripy.BVV(1, 8),
                _assembly_register_bytes(self.state),
                *(self.state.globals[field] for field in _BANK_FIELDS),
                self.state.memory.load(MARKER, 1),
            ),
        )
        for register in REGISTERS:
            value = self.state.globals[f"far_{register}"]
            if register == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, register, value)
        for field in _BANK_FIELDS:
            self.state.globals[field] = self.state.globals[f"far_{field}"]
        self.state.memory.store(MARKER, self.state.globals["far_marker"])
        self.jump(self.continuation)


class AssemblyClearSprites(angr.SimProcedure):
    """Complete transition of the independently proven 160-byte loop."""

    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["calls"] += (
            claripy.Concat(
                claripy.BVV(2, 8),
                _assembly_register_bytes(self.state),
                self.state.memory.load(SHADOW_OAM, OAM_SIZE),
            ),
        )
        self.state.memory.store(
            SHADOW_OAM,
            claripy.BVV(0, OAM_SIZE * 8),
            endness="Iend_BE",
        )
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0xC0, 8))
        self.state.regs.b = claripy.BVV(0, 8)
        self.state.regs.h = claripy.BVV(0xC3, 8)
        self.state.regs.l = claripy.BVV(0xA0, 8)
        self.jump(self.continuation)


class NativeFarCopyData2(angr.SimProcedure):
    def run(
        self, state: claripy.ast.BV, memory: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        self.state.globals["calls"] += (
            claripy.Concat(
                claripy.BVV(1, 8),
                self.state.memory.load(state, 11),
                self.state.memory.load(memory + MARKER, 1),
            ),
        )
        for offset, register in enumerate(REGISTERS):
            self.state.memory.store(
                state + offset, self.state.globals[f"far_{register}"]
            )
        for offset, field in enumerate(_BANK_FIELDS, 8):
            self.state.memory.store(
                state + offset, self.state.globals[f"far_{field}"]
            )
        self.state.memory.store(
            memory + MARKER, self.state.globals["far_marker"]
        )


class NativeClearSprites(angr.SimProcedure):
    def run(self, state: claripy.ast.BV) -> None:  # type: ignore[override]
        self.state.globals["calls"] += (
            claripy.Concat(
                claripy.BVV(2, 8), self.state.memory.load(state, 168)
            ),
        )
        self.state.memory.store(state, claripy.BVV(0, 8))
        self.state.memory.store(state + 1, claripy.BVV(0xC0, 8))
        self.state.memory.store(state + 2, claripy.BVV(0, 8))
        self.state.memory.store(state + 6, claripy.BVV(0xC3, 8))
        self.state.memory.store(state + 7, claripy.BVV(0xA0, 8))
        self.state.memory.store(
            state + 8,
            claripy.BVV(0, OAM_SIZE * 8),
            endness="Iend_BE",
        )


_BANK_FIELDS = ("requested_bank", "loaded_bank", "rom_bank")


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for field in _BANK_FIELDS:
        values[field] = claripy.BVS(f"{prefix}_{field}", 8)
        values[f"far_{field}"] = claripy.BVS(f"{prefix}_far_{field}", 8)
    for register in REGISTERS:
        values[f"far_{register}"] = (
            claripy.Concat(
                claripy.BVS(f"{prefix}_far_flags", 4), claripy.BVV(0, 4)
            )
            if register == "f"
            else claripy.BVS(f"{prefix}_far_{register}", 8)
        )
    values["oam"] = claripy.BVS(f"{prefix}_oam", OAM_SIZE * 8)
    values["oam_tile"] = claripy.BVS(f"{prefix}_oam_tile", 8)
    values["marker"] = claripy.BVS(f"{prefix}_marker", 8)
    values["far_marker"] = claripy.BVS(f"{prefix}_far_marker", 8)
    return values


def _setup_globals(
    state: angr.SimState, values: dict[str, claripy.ast.BV]
) -> None:
    for field in _BANK_FIELDS:
        state.globals[field] = values[field]
        state.globals[f"far_{field}"] = values[f"far_{field}"]
    for register in REGISTERS:
        state.globals[f"far_{register}"] = values[f"far_{register}"]
    state.globals["far_marker"] = values["far_marker"]
    state.globals["calls"] = ()


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "DrawPlayerCharacter")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY
    project = angr.Project(
        rom_window(ROM, location.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": location.address,
        },
    )
    base = location.address
    project.hook(base + 11, AssemblyFarCopyData2(base + 14), length=3)
    project.hook(base + 14, AssemblyClearSprites(base + 17), length=3)
    project.hook(base + 17, XorA(base + 18), length=1)
    project.hook(
        base + 18, Sm83StoreAImmediate(OAM_TILE, base + 21), length=3
    )
    for offset in (33, 35, 42):
        project.hook(
            base + offset,
            Sm83StoreAAtHlIncrement(base + offset + 1),
            length=1,
        )
    project.hook(base + 36, Sm83AddImmediate(8, base + 38), length=2)
    project.hook(
        base + 39, Sm83LoadAImmediate(OAM_TILE, base + 42), length=3
    )
    project.hook(base + 43, Sm83IncRegister("a", base + 44), length=1)
    project.hook(
        base + 44, Sm83StoreAImmediate(OAM_TILE, base + 47), length=3
    )
    project.hook(base + 48, Sm83DecRegister("c", base + 49), length=1)
    project.hook(base + 54, Sm83AddRegister("d", base + 55), length=1)
    project.hook(base + 56, Sm83DecRegister("b", base + 57), length=1)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _setup_globals(state, values)
    state.memory.store(SHADOW_OAM, values["oam"], endness="Iend_BE")
    state.memory.store(OAM_TILE, values["oam_tile"])
    state.memory.store(MARKER, values["marker"])
    state.regs.sp = claripy.BVV(STACK, 16)
    state.memory.store(
        STACK, claripy.BVV(RETURN, 16), endness="Iend_LE"
    )
    ends = collect_returns(project, state, RETURN)
    assert len(ends) == 1
    return [
        Endpoint(
            **assembly_registers(end),
            banks=claripy.Concat(
                *(end.globals[field] for field in _BANK_FIELDS)
            ),
            oam=end.memory.load(SHADOW_OAM, OAM_SIZE),
            oam_tile=end.memory.load(OAM_TILE, 1),
            marker=end.memory.load(MARKER, 1),
            calls=claripy.Concat(*end.globals["calls"]),
            constraints=tuple(end.solver.constraints),
        )
        for end in ends
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_draw_player_character")
    far_copy = project.loader.find_symbol("port_far_copy_data2")
    clear_sprites = project.loader.find_symbol("port_clear_sprites")
    assert function is not None and far_copy is not None
    assert clear_sprites is not None
    project.hook(far_copy.rebased_addr, NativeFarCopyData2())
    project.hook(clear_sprites.rebased_addr, NativeClearSprites())
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(
        NATIVE_STATE + 8, values["oam"], endness="Iend_BE"
    )
    for offset, field in zip(
        (REQUESTED_BANK_OFFSET, LOADED_BANK_OFFSET, ROM_BANK_OFFSET),
        _BANK_FIELDS,
    ):
        state.memory.store(NATIVE_STATE + offset, values[field])
    state.memory.store(NATIVE_STATE + OAM_TILE_OFFSET, values["oam_tile"])
    state.memory.store(NATIVE_MEMORY + MARKER, values["marker"])
    _setup_globals(state, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            banks=end.memory.load(
                NATIVE_STATE + REQUESTED_BANK_OFFSET, 3
            ),
            oam=end.memory.load(NATIVE_STATE + 8, OAM_SIZE),
            oam_tile=end.memory.load(NATIVE_STATE + OAM_TILE_OFFSET, 1),
            marker=end.memory.load(NATIVE_MEMORY + MARKER, 1),
            calls=claripy.Concat(*end.globals["calls"]),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(
    not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`"
)
def test_draw_player_character_pathwise_equivalence() -> None:
    values = _inputs("draw_player_character")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "banks", "oam", "oam_tile", "marker", "calls"),
    )
