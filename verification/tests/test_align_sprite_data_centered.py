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
    Sm83AddHlRegisterPair,
    Sm83LoadAHighImmediate,
    Sm83StoreAAtHlIncrement,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xDFF0
RETURN = 0xEFFF
BUFFER_SIZE = 392
H_SPRITE_WIDTH = 0xFF8B
H_SPRITE_HEIGHT = 0xFF8C
H_SPRITE_OFFSET = 0xFF8D
EXPECTED = bytes.fromhex(
    "f08d06004f09f08bf5e5f08c4f1a13220d20fae101380009f13d20ecc9"
)
LAYOUTS = ((5, 40, 72), (6, 48, 64), (7, 56, 0))


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
    parameters: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _inputs(prefix: str, copied_size: int) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["memory"] = claripy.BVS(
        f"{prefix}_memory", (BUFFER_SIZE + copied_size + 2) * 8
    )
    return values


def _entry_registers(
    values: dict[str, claripy.ast.BV], destination: int, source: int
) -> dict[str, claripy.ast.BV]:
    entry = dict(values)
    entry.update(
        d=claripy.BVV(source >> 8, 8),
        e=claripy.BVV(source & 0xFF, 8),
        h=claripy.BVV(destination >> 8, 8),
        l=claripy.BVV(destination & 0xFF, 8),
    )
    return entry


def _assembly(
    values: dict[str, claripy.ast.BV],
    destination: int,
    source: int,
    width: int,
    height: int,
    offset: int,
) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "AlignSpriteDataCentered")
    end = symbol_location(SYMBOLS, "ZeroSpriteBuffer")
    assert end.address - location.address == len(EXPECTED)
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
    base = location.address
    project.hook(base, Sm83LoadAHighImmediate(0x8D, base + 2), length=2)
    project.hook(
        base + 5, Sm83AddHlRegisterPair("bc", base + 6), length=1
    )
    project.hook(
        base + 6, Sm83LoadAHighImmediate(0x8B, base + 8), length=2
    )
    project.hook(
        base + 10, Sm83LoadAHighImmediate(0x8C, base + 12), length=2
    )
    project.hook(
        base + 15, Sm83StoreAAtHlIncrement(base + 16), length=1
    )
    project.hook(
        base + 23, Sm83AddHlRegisterPair("bc", base + 24), length=1
    )
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(
        state, _entry_registers(values, destination, source)
    )
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    state.memory.store(destination - 1, values["memory"])
    state.memory.store(H_SPRITE_OFFSET, claripy.BVV(offset, 8))
    state.memory.store(H_SPRITE_WIDTH, claripy.BVV(width, 8))
    state.memory.store(H_SPRITE_HEIGHT, claripy.BVV(height, 8))
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN)
    assert not manager.errored and len(manager.found) == 1
    observed_size = BUFFER_SIZE + width * height + 2
    return [
        Endpoint(
            **assembly_registers(final),
            memory=final.memory.load(destination - 1, observed_size),
            parameters=claripy.Concat(
                final.memory.load(H_SPRITE_OFFSET, 1),
                final.memory.load(H_SPRITE_WIDTH, 1),
                final.memory.load(H_SPRITE_HEIGHT, 1),
            ),
            constraints=tuple(final.solver.constraints),
        )
        for final in manager.found
    ]


def _native(
    values: dict[str, claripy.ast.BV],
    destination: int,
    source: int,
    width: int,
    height: int,
    offset: int,
) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_align_sprite_data_centered")
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(
        state,
        NATIVE_STATE,
        _entry_registers(values, destination, source),
    )
    state.memory.store(NATIVE_STATE + 8, claripy.BVV(offset, 8))
    state.memory.store(NATIVE_STATE + 9, claripy.BVV(width, 8))
    state.memory.store(NATIVE_STATE + 10, claripy.BVV(height, 8))
    state.memory.store(
        NATIVE_MEMORY + destination - 1, values["memory"]
    )
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    observed_size = BUFFER_SIZE + width * height + 2
    return [
        Endpoint(
            **native_registers(final, NATIVE_STATE),
            memory=final.memory.load(
                NATIVE_MEMORY + destination - 1, observed_size
            ),
            parameters=final.memory.load(NATIVE_STATE + 8, 3),
            constraints=tuple(final.solver.constraints),
        )
        for final in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(
    not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`"
)
def test_align_sprite_data_centered_pathwise_equivalence() -> None:
    buffers = tuple(
        symbol_location(SYMBOLS, f"sSpriteBuffer{index}").address
        for index in range(3)
    )
    assert buffers == (0xA000, 0xA188, 0xA310)
    for pair in range(2):
        destination, source = buffers[pair : pair + 2]
        for width, height, offset in LAYOUTS:
            values = _inputs(
                f"align_sprite_{pair}_{width}", width * height
            )
            assert_pathwise_equivalent(
                _assembly(
                    values,
                    destination,
                    source,
                    width,
                    height,
                    offset,
                ),
                _native(
                    values,
                    destination,
                    source,
                    width,
                    height,
                    offset,
                ),
                (*REGISTERS, "memory", "parameters"),
            )
