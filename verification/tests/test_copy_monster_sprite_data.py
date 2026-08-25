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
    linked_bytes,
    rom_window,
    sm83_flags_to_z80,
    symbol_location,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF
MONSTER_SPRITE = 0x4780
TEMP_PIC = 0xC6E8
TILE_SIZE = 16
EXPECTED = bytes.fromhex("0110003e05c3f717")
BANK_FIELDS = ("requested_bank", "loaded_bank", "rom_bank")
CASES = (
    (0, 18),
    (1, 25),
    (2, 19),
    (3, 26),
    (4, 25),
    (5, 32),
    (6, 26),
    (7, 33),
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
    source: claripy.ast.BV
    destination: claripy.ast.BV
    call: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _set_outputs(
    state: angr.SimState, native_address: claripy.ast.BV | None
) -> None:
    for offset, register in enumerate(REGISTERS):
        value = state.globals[f"far_out_{register}"]
        if native_address is None:
            if register == "f":
                value = sm83_flags_to_z80(value)
            setattr(state.regs, register, value)
        else:
            state.memory.store(native_address + offset, value)
    for offset, field in enumerate(BANK_FIELDS, 8):
        value = state.globals[f"far_out_{field}"]
        if native_address is None:
            state.globals[field] = value
        else:
            state.memory.store(native_address + offset, value)


class AssemblyFarCopySummary(angr.SimProcedure):
    def __init__(self, source: int, destination: int) -> None:
        super().__init__()
        self._source = source
        self._destination = destination

    def run(self) -> None:  # type: ignore[override]
        registers = assembly_registers(self.state)
        self.state.globals["call"] = claripy.Concat(
            *(registers[name] for name in REGISTERS),
            *(self.state.globals[field] for field in BANK_FIELDS),
            self.state.memory.load(self._source, TILE_SIZE),
            self.state.memory.load(self._destination, TILE_SIZE),
        )
        _set_outputs(self.state, None)
        self.state.memory.store(
            self._destination, self.state.globals["far_out_destination"]
        )
        self.jump(DONE)


class NativeFarCopySummary(angr.SimProcedure):
    def __init__(self, source: int, destination: int) -> None:
        super().__init__()
        self._source = source
        self._destination = destination

    def run(
        self, state: claripy.ast.BV, memory: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        self.state.globals["call"] = claripy.Concat(
            self.state.memory.load(state, 11),
            self.state.memory.load(memory + self._source, TILE_SIZE),
            self.state.memory.load(memory + self._destination, TILE_SIZE),
        )
        _set_outputs(self.state, state)
        self.state.memory.store(
            memory + self._destination,
            self.state.globals["far_out_destination"],
        )


def _inputs(
    prefix: str, source: int, destination: int
) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["h"] = claripy.BVV(source >> 8, 8)
    values["l"] = claripy.BVV(source & 0xFF, 8)
    values["d"] = claripy.BVV(destination >> 8, 8)
    values["e"] = claripy.BVV(destination & 0xFF, 8)
    for field in BANK_FIELDS:
        values[field] = claripy.BVS(f"{prefix}_{field}", 8)
    values["source"] = claripy.BVS(f"{prefix}_source", TILE_SIZE * 8)
    values["destination"] = claripy.BVS(
        f"{prefix}_destination", TILE_SIZE * 8
    )
    for register in REGISTERS:
        values[f"far_out_{register}"] = (
            claripy.Concat(
                claripy.BVS(f"{prefix}_far_out_flags", 4),
                claripy.BVV(0, 4),
            )
            if register == "f"
            else claripy.BVS(f"{prefix}_far_out_{register}", 8)
        )
    for field in BANK_FIELDS:
        values[f"far_out_{field}"] = claripy.BVS(
            f"{prefix}_far_out_{field}", 8
        )
    values["far_out_destination"] = claripy.BVS(
        f"{prefix}_far_out_destination", TILE_SIZE * 8
    )
    return values


def _setup(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    for field in BANK_FIELDS:
        state.globals[field] = values[field]
    for name, value in values.items():
        if name.startswith("far_out_"):
            state.globals[name] = value


def _assembly(
    values: dict[str, claripy.ast.BV], source: int, destination: int
) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "CopyMonsterSpriteData")
    far_copy = symbol_location(SYMBOLS, "FarCopyData2")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
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
    project.hook(
        far_copy.address, AssemblyFarCopySummary(source, destination)
    )
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.memory.store(source, values["source"])
    state.memory.store(destination, values["destination"])
    _setup(state, values)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE)
    assert not manager.errored and len(manager.found) == 1
    return [
        Endpoint(
            **assembly_registers(end),
            banks=claripy.Concat(
                *(end.globals[field] for field in BANK_FIELDS)
            ),
            source=end.memory.load(source, TILE_SIZE),
            destination=end.memory.load(destination, TILE_SIZE),
            call=end.globals["call"],
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(
    values: dict[str, claripy.ast.BV], source: int, destination: int
) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_copy_monster_sprite_data")
    far_copy = project.loader.find_symbol("port_far_copy_data2")
    assert function is not None and far_copy is not None
    project.hook(
        far_copy.rebased_addr, NativeFarCopySummary(source, destination)
    )
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    for offset, field in enumerate(BANK_FIELDS, 8):
        state.memory.store(NATIVE_STATE + offset, values[field])
    state.memory.store(NATIVE_MEMORY + source, values["source"])
    state.memory.store(NATIVE_MEMORY + destination, values["destination"])
    _setup(state, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            banks=end.memory.load(NATIVE_STATE + 8, 3),
            source=end.memory.load(NATIVE_MEMORY + source, TILE_SIZE),
            destination=end.memory.load(
                NATIVE_MEMORY + destination, TILE_SIZE
            ),
            call=end.globals["call"],
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(
    not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`"
)
def test_copy_monster_sprite_data_pathwise_equivalence() -> None:
    assert symbol_location(SYMBOLS, "MonsterSprite").address == MONSTER_SPRITE
    assert symbol_location(SYMBOLS, "MonsterSprite").bank == 5
    assert symbol_location(SYMBOLS, "wTempPic").address == TEMP_PIC
    for source_tile, destination_tile in CASES:
        source = MONSTER_SPRITE + source_tile * TILE_SIZE
        destination = TEMP_PIC + destination_tile * TILE_SIZE
        values = _inputs(
            f"copy_monster_{source_tile}_{destination_tile}",
            source,
            destination,
        )
        assert_pathwise_equivalent(
            _assembly(values, source, destination),
            _native(values, source, destination),
            (*REGISTERS, "banks", "source", "destination", "call"),
        )
