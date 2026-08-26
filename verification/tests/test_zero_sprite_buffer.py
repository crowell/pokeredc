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
    Sm83OrRegister,
    Sm83StoreAAtHlIncrement,
    Sm83XorA,
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
OBSERVED_SIZE = BUFFER_SIZE + 2
EXPECTED = bytes.fromhex("018801af220b78b120f9c9")


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
    constraints: tuple[claripy.ast.Bool, ...]


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["memory"] = claripy.BVS(
        f"{prefix}_memory", OBSERVED_SIZE * 8
    )
    return values


def _assembly(
    values: dict[str, claripy.ast.BV], buffer_address: int
) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "ZeroSpriteBuffer")
    loop = symbol_location(SYMBOLS, "ZeroSpriteBuffer.nextByteLoop")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    assert loop.address == location.address + 3
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
    project.hook(loop.address, Sm83XorA(loop.address + 1), length=1)
    project.hook(
        loop.address + 1,
        Sm83StoreAAtHlIncrement(loop.address + 2),
        length=1,
    )
    project.hook(
        loop.address + 4,
        Sm83OrRegister("c", loop.address + 5),
        length=1,
    )
    state = project.factory.blank_state(addr=location.address)
    entry = dict(values)
    entry["h"] = claripy.BVV(buffer_address >> 8, 8)
    entry["l"] = claripy.BVV(buffer_address & 0xFF, 8)
    set_assembly_registers(state, entry)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    state.memory.store(buffer_address - 1, values["memory"])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN)
    assert not manager.errored and len(manager.found) == 1
    return [
        Endpoint(
            **assembly_registers(end),
            memory=end.memory.load(buffer_address - 1, OBSERVED_SIZE),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(
    values: dict[str, claripy.ast.BV], buffer_address: int
) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_zero_sprite_buffer")
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    entry = dict(values)
    entry["h"] = claripy.BVV(buffer_address >> 8, 8)
    entry["l"] = claripy.BVV(buffer_address & 0xFF, 8)
    store_native_registers(state, NATIVE_STATE, entry)
    state.memory.store(
        NATIVE_MEMORY + buffer_address - 1, values["memory"]
    )
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=end.memory.load(
                NATIVE_MEMORY + buffer_address - 1, OBSERVED_SIZE
            ),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(
    not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`"
)
def test_zero_sprite_buffer_pathwise_equivalence() -> None:
    buffers = (
        symbol_location(SYMBOLS, "sSpriteBuffer0").address,
        symbol_location(SYMBOLS, "sSpriteBuffer1").address,
    )
    assert buffers == (0xA000, 0xA188)
    for index, buffer_address in enumerate(buffers):
        values = _inputs(f"zero_sprite_buffer_{index}")
        assert_pathwise_equivalent(
            _assembly(values, buffer_address),
            _native(values, buffer_address),
            (*REGISTERS, "memory"),
        )
