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
from verification.harness.sm83_shims import (
    Sm83AddRegister,
    Sm83IncRegister,
    Sm83LoadAHighImmediate,
    Sm83SrlRegister,
    Sm83StoreAHighImmediate,
    Sm83StoreAImmediate,
    Sm83SubRegister,
    Sm83SwapRegister,
    Sm83XorA,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF

R_RAMB = 0x4000
BUFFER0 = 0xA000
BUFFER1 = 0xA188
BUFFER2 = 0xA310
BUFFER_SIZE = 392
BUFFER_START = BUFFER0 - 1
BUFFER_OBSERVED_SIZE = 3 * BUFFER_SIZE + 2
H_SPRITE_WIDTH = 0xFF8B
H_SPRITE_HEIGHT = 0xFF8C
H_SPRITE_OFFSET = 0xFF8D
H_LOADED_ROM_BANK = 0xFFB8
W_SPRITE_FLIPPED = 0xD0AA

GLOBAL_ADDRESSES = (
    R_RAMB,
    H_SPRITE_WIDTH,
    H_SPRITE_HEIGHT,
    H_SPRITE_OFFSET,
    W_SPRITE_FLIPPED,
    H_LOADED_ROM_BANK,
    0xFFBA,
    0x2000,
    0xFFC7,
    0xFFC8,
    0xFFC9,
    0xFFCA,
    0xFFC6,
    0xFFD6,
)
CALL_COUNT = 5
EXPECTED = bytes.fromhex(
    "d5e60fe08b473e07903ccb3f4787878790e08d79cb37e60f47878787e08c"
    "3e079047f08d80878787e08dafea00402100a0cddf161188a12100a0cdc216"
    "2188a1cddf161110a32188a1cdc216d1c3ea16"
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
    memory: claripy.ast.BV
    calls: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    dimension = claripy.BVS(f"{prefix}_dimension", 8)
    values["a"] = dimension
    values["c"] = dimension
    values["buffers"] = claripy.BVS(
        f"{prefix}_buffers", BUFFER_OBSERVED_SIZE * 8
    )
    for index, _address in enumerate(GLOBAL_ADDRESSES):
        values[f"global_{index}"] = claripy.BVS(
            f"{prefix}_global_{index}", 8
        )
    for call in range(CALL_COUNT):
        values[f"post_{call}_buffers"] = claripy.BVS(
            f"{prefix}_post_{call}_buffers", BUFFER_OBSERVED_SIZE * 8
        )
        for register in REGISTERS:
            values[f"post_{call}_{register}"] = (
                claripy.Concat(
                    claripy.BVS(f"{prefix}_post_{call}_flags", 4),
                    claripy.BVV(0, 4),
                )
                if register == "f"
                else claripy.BVS(f"{prefix}_post_{call}_{register}", 8)
            )
        for index, _address in enumerate(GLOBAL_ADDRESSES):
            values[f"post_{call}_global_{index}"] = claripy.BVS(
                f"{prefix}_post_{call}_global_{index}", 8
            )
    return values


def _dimension_constraint(
    values: dict[str, claripy.ast.BV],
) -> claripy.ast.Bool:
    dimension = values["a"]
    return claripy.Or(
        dimension == 0x55,
        dimension == 0x66,
        dimension == 0x77,
    )


def _setup(
    state: angr.SimState,
    values: dict[str, claripy.ast.BV],
    memory: int = 0,
) -> None:
    state.memory.store(memory + BUFFER_START, values["buffers"])
    for index, address in enumerate(GLOBAL_ADDRESSES):
        state.memory.store(memory + address, values[f"global_{index}"])
    state.globals["call_index"] = 0
    state.solver.add(_dimension_constraint(values))


def _memory(state: angr.SimState, base: int = 0) -> claripy.ast.BV:
    return claripy.Concat(
        state.memory.load(base + BUFFER_START, BUFFER_OBSERVED_SIZE),
        *(state.memory.load(base + address, 1) for address in GLOBAL_ADDRESSES),
    )


def _call(
    state: angr.SimState,
    index: int,
    native: bool,
    register_address: claripy.ast.BV | int = 0,
) -> claripy.ast.BV:
    memory = NATIVE_MEMORY if native else 0
    registers = (
        native_registers(state, register_address)
        if native
        else assembly_registers(state)
    )
    if native and index in (1, 3):
        parameters = tuple(
            state.memory.load(register_address + offset, 1)
            for offset in (8, 9, 10)
        )
    else:
        parameters = (
            state.memory.load(memory + H_SPRITE_OFFSET, 1),
            state.memory.load(memory + H_SPRITE_WIDTH, 1),
            state.memory.load(memory + H_SPRITE_HEIGHT, 1),
        )
    return claripy.Concat(
        claripy.BVV(index, 8),
        *(registers[name] for name in REGISTERS),
        *parameters,
        *(state.memory.load(memory + address, 1) for address in GLOBAL_ADDRESSES),
        state.memory.load(memory + BUFFER_START, BUFFER_OBSERVED_SIZE),
    )


def _apply_post(
    state: angr.SimState,
    values: dict[str, claripy.ast.BV],
    index: int,
    native: bool,
    register_address: claripy.ast.BV | int = 0,
) -> None:
    memory = NATIVE_MEMORY if native else 0
    for offset, register in enumerate(REGISTERS):
        value = values[f"post_{index}_{register}"]
        if native:
            state.memory.store(register_address + offset, value)
        else:
            if register == "f":
                value = sm83_flags_to_z80(value)
            setattr(state.regs, register, value)
    state.memory.store(
        memory + BUFFER_START, values[f"post_{index}_buffers"]
    )
    for global_index, address in enumerate(GLOBAL_ADDRESSES):
        state.memory.store(
            memory + address,
            values[f"post_{index}_global_{global_index}"],
        )


class SaveDE(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["saved_d"] = self.state.regs.d
        self.state.globals["saved_e"] = self.state.regs.e
        self.jump(self.next_address)


class RestoreDE(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.d = self.state.globals["saved_d"]
        self.state.regs.e = self.state.globals["saved_e"]
        self.jump(self.next_address)


class LoadRegister(angr.SimProcedure):
    def __init__(self, destination: str, source: str, next_address: int) -> None:
        super().__init__()
        self.destination = destination
        self.source = source
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.destination, getattr(self.state.regs, self.source))
        self.jump(self.next_address)


class LoadImmediate(angr.SimProcedure):
    def __init__(self, register: str, value: int, next_address: int) -> None:
        super().__init__()
        self.register = register
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.register, claripy.BVV(self.value, 8))
        self.jump(self.next_address)


class LoadPair(angr.SimProcedure):
    def __init__(self, high: str, low: str, value: int, next_address: int) -> None:
        super().__init__()
        self.high = high
        self.low = low
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.high, claripy.BVV(self.value >> 8, 8))
        setattr(self.state.regs, self.low, claripy.BVV(self.value & 0xFF, 8))
        self.jump(self.next_address)


class Sm83AndImmediateCorrect(angr.SimProcedure):
    def __init__(self, value: int, next_address: int) -> None:
        super().__init__()
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a &= self.value
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x50, 8),
            claripy.BVV(0x10, 8),
        )
        self.jump(self.next_address)


class AssemblyBoundary(angr.SimProcedure):
    def __init__(
        self,
        values: dict[str, claripy.ast.BV],
        index: int,
        next_address: int,
    ) -> None:
        super().__init__()
        self.values = values
        self.index = index
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.globals[f"call_{self.index}"] = _call(
            self.state, self.index, native=False
        )
        _apply_post(self.state, self.values, self.index, native=False)
        self.state.globals["call_index"] = self.index + 1
        self.jump(self.next_address)


class NativeBoundary(angr.SimProcedure):
    def __init__(self, values: dict[str, claripy.ast.BV], kind: str) -> None:
        super().__init__()
        self.values = values
        self.kind = kind

    def run(
        self, register_address: claripy.ast.BV, _memory: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        index = self.state.globals["call_index"]
        expected = {
            "zero": (0, 2),
            "align": (1, 3),
            "interlace": (4,),
        }[self.kind]
        assert index in expected
        self.state.globals[f"call_{index}"] = _call(
            self.state,
            index,
            native=True,
            register_address=register_address,
        )
        _apply_post(
            self.state,
            self.values,
            index,
            native=True,
            register_address=register_address,
        )
        self.state.globals["call_index"] = index + 1


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "LoadUncompressedSpriteData")
    end = symbol_location(SYMBOLS, "AlignSpriteDataCentered")
    assert location.bank == end.bank == 0
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
    project.hook(base + 0, SaveDE(base + 1), length=1)
    project.hook(base + 1, Sm83AndImmediateCorrect(0x0F, base + 3), length=2)
    project.hook(base + 3, Sm83StoreAHighImmediate(0x8B, base + 5), length=2)
    project.hook(base + 5, LoadRegister("b", "a", base + 6), length=1)
    project.hook(base + 6, LoadImmediate("a", 7, base + 8), length=2)
    project.hook(base + 8, Sm83SubRegister("b", base + 9), length=1)
    project.hook(base + 9, Sm83IncRegister("a", base + 10), length=1)
    project.hook(base + 10, Sm83SrlRegister("a", base + 12), length=2)
    project.hook(base + 12, LoadRegister("b", "a", base + 13), length=1)
    for offset in (13, 14, 15):
        project.hook(offset + base, Sm83AddRegister("a", base + offset + 1), length=1)
    project.hook(base + 16, Sm83SubRegister("b", base + 17), length=1)
    project.hook(base + 17, Sm83StoreAHighImmediate(0x8D, base + 19), length=2)
    project.hook(base + 19, LoadRegister("a", "c", base + 20), length=1)
    project.hook(base + 20, Sm83SwapRegister("a", base + 22), length=2)
    project.hook(base + 22, Sm83AndImmediateCorrect(0x0F, base + 24), length=2)
    project.hook(base + 24, LoadRegister("b", "a", base + 25), length=1)
    for offset in (25, 26, 27):
        project.hook(offset + base, Sm83AddRegister("a", base + offset + 1), length=1)
    project.hook(base + 28, Sm83StoreAHighImmediate(0x8C, base + 30), length=2)
    project.hook(base + 30, LoadImmediate("a", 7, base + 32), length=2)
    project.hook(base + 32, Sm83SubRegister("b", base + 33), length=1)
    project.hook(base + 33, LoadRegister("b", "a", base + 34), length=1)
    project.hook(base + 34, Sm83LoadAHighImmediate(0x8D, base + 36), length=2)
    project.hook(base + 36, Sm83AddRegister("b", base + 37), length=1)
    for offset in (37, 38, 39):
        project.hook(offset + base, Sm83AddRegister("a", base + offset + 1), length=1)
    project.hook(base + 40, Sm83StoreAHighImmediate(0x8D, base + 42), length=2)
    project.hook(base + 42, Sm83XorA(base + 43), length=1)
    project.hook(base + 43, Sm83StoreAImmediate(R_RAMB, base + 46), length=3)
    project.hook(base + 46, LoadPair("h", "l", BUFFER0, base + 49), length=3)
    project.hook(base + 49, AssemblyBoundary(values, 0, base + 52), length=3)
    project.hook(base + 52, LoadPair("d", "e", BUFFER1, base + 55), length=3)
    project.hook(base + 55, LoadPair("h", "l", BUFFER0, base + 58), length=3)
    project.hook(base + 58, AssemblyBoundary(values, 1, base + 61), length=3)
    project.hook(base + 61, LoadPair("h", "l", BUFFER1, base + 64), length=3)
    project.hook(base + 64, AssemblyBoundary(values, 2, base + 67), length=3)
    project.hook(base + 67, LoadPair("d", "e", BUFFER2, base + 70), length=3)
    project.hook(base + 70, LoadPair("h", "l", BUFFER1, base + 73), length=3)
    project.hook(base + 73, AssemblyBoundary(values, 3, base + 76), length=3)
    project.hook(base + 76, RestoreDE(base + 77), length=1)
    project.hook(base + 77, AssemblyBoundary(values, 4, DONE), length=3)

    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _setup(state, values)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE)
    assert not manager.errored and len(manager.found) == 1
    final = manager.found[0]
    assert final.globals["call_index"] == CALL_COUNT
    return [
        Endpoint(
            **assembly_registers(final),
            memory=_memory(final),
            calls=claripy.Concat(
                *(final.globals[f"call_{index}"] for index in range(CALL_COUNT))
            ),
            constraints=tuple(final.solver.constraints),
        )
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_load_uncompressed_sprite_data")
    zero = project.loader.find_symbol("port_zero_sprite_buffer")
    align = project.loader.find_symbol("port_align_sprite_data_centered")
    interlace = project.loader.find_symbol("port_interlace_merge_sprite_buffers")
    assert function is not None and zero is not None and align is not None
    assert interlace is not None
    project.hook(zero.rebased_addr, NativeBoundary(values, "zero"))
    project.hook(align.rebased_addr, NativeBoundary(values, "align"))
    project.hook(interlace.rebased_addr, NativeBoundary(values, "interlace"))
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, values, NATIVE_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and manager.deadended
    endpoints = []
    for final in manager.deadended:
        assert final.globals["call_index"] == CALL_COUNT
        endpoints.append(
            Endpoint(
                **native_registers(final, NATIVE_STATE),
                memory=_memory(final, NATIVE_MEMORY),
                calls=claripy.Concat(
                    *(final.globals[f"call_{index}"] for index in range(CALL_COUNT))
                ),
                constraints=tuple(final.solver.constraints),
            )
        )
    return endpoints


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(
    not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`"
)
def test_load_uncompressed_sprite_data_pathwise_equivalence() -> None:
    values = _inputs("load_uncompressed_sprite_data")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "memory", "calls"),
    )
