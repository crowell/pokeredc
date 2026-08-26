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
    Sm83DecRegister,
    Sm83LoadAHighImmediate,
    Sm83LoadAImmediate,
    Sm83OrRegister,
    Sm83StoreAAtHlDecrement,
    Sm83StoreAHighImmediate,
    Sm83StoreAImmediate,
    Sm83XorA,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF
STACK = 0xDFF0
BUFFER0 = 0xA000
BUFFER1 = 0xA188
BUFFER2 = 0xA310
BUFFER_SIZE = 392
BUFFER_OBSERVED_SIZE = 3 * BUFFER_SIZE + 2
R_RAMB = 0x4000
SPRITE_FLIPPED = 0xD0AA
COUNTER = 0xFF8B
LOADED_BANK = 0xFFB8
COPY_ADDRESSES = (
    0xFFBA,
    LOADED_BANK,
    COUNTER,
    0x2000,
    0xFFC7,
    0xFFC8,
    0xFFC9,
    0xFFCA,
    0xFFC6,
    0xFFD6,
)
EXPECTED = bytes.fromhex(
    "afea0040d52197a4110fa30187a13ec4e08b1a1b320a0b321a1b320a0b32"
    "f08b3de08b20edfaaad0a7280e0110032188a1cb36230b78b120f8e11188a1"
    "0e31f0b847c34818"
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
    call: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _memory(state: angr.SimState, base: int = 0) -> claripy.ast.BV:
    return claripy.Concat(
        state.memory.load(base + BUFFER0 - 1, BUFFER_OBSERVED_SIZE),
        state.memory.load(base + R_RAMB, 1),
        state.memory.load(base + SPRITE_FLIPPED, 1),
        *(state.memory.load(base + address, 1) for address in COPY_ADDRESSES),
    )


def _call(state: angr.SimState, memory: int = 0) -> claripy.ast.BV:
    registers = (
        assembly_registers(state)
        if memory == 0
        else native_registers(state, NATIVE_STATE)
    )
    return claripy.Concat(
        *(registers[name] for name in REGISTERS),
        *(state.memory.load(memory + address, 1) for address in COPY_ADDRESSES),
        state.memory.load(memory + R_RAMB, 1),
        state.memory.load(memory + SPRITE_FLIPPED, 1),
    )


class AssemblyCopyVideoData(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.globals["call"] = _call(self.state)
        for register in REGISTERS:
            value = self.state.globals[f"callee_{register}"]
            if register == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, register, value)
        for index, address in enumerate(COPY_ADDRESSES):
            self.state.memory.store(
                address, self.state.globals[f"callee_memory_{index}"]
            )
        self.jump(DONE)


class NativeCopyVideoData(angr.SimProcedure):
    def run(
        self, state: claripy.ast.BV, memory: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        self.state.globals["call"] = _call(self.state, NATIVE_MEMORY)
        for offset, register in enumerate(REGISTERS):
            self.state.memory.store(
                state + offset, self.state.globals[f"callee_{register}"]
            )
        for index, address in enumerate(COPY_ADDRESSES):
            self.state.memory.store(
                memory + address,
                self.state.globals[f"callee_memory_{index}"],
            )


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["buffers"] = claripy.BVS(
        f"{prefix}_buffers", BUFFER_OBSERVED_SIZE * 8
    )
    values["ramb"] = claripy.BVS(f"{prefix}_ramb", 8)
    values["sprite_flipped"] = claripy.BVS(
        f"{prefix}_sprite_flipped", 8
    )
    for index, _address in enumerate(COPY_ADDRESSES):
        values[f"memory_{index}"] = claripy.BVS(
            f"{prefix}_memory_{index}", 8
        )
        values[f"callee_memory_{index}"] = claripy.BVS(
            f"{prefix}_callee_memory_{index}", 8
        )
    for register in REGISTERS:
        values[f"callee_{register}"] = (
            claripy.Concat(
                claripy.BVS(f"{prefix}_callee_flags", 4),
                claripy.BVV(0, 4),
            )
            if register == "f"
            else claripy.BVS(f"{prefix}_callee_{register}", 8)
        )
    return values


def _setup(
    state: angr.SimState,
    values: dict[str, claripy.ast.BV],
    memory: int = 0,
) -> None:
    state.memory.store(memory + BUFFER0 - 1, values["buffers"])
    state.memory.store(memory + R_RAMB, values["ramb"])
    state.memory.store(
        memory + SPRITE_FLIPPED, values["sprite_flipped"]
    )
    for index, address in enumerate(COPY_ADDRESSES):
        state.memory.store(memory + address, values[f"memory_{index}"])
        state.globals[f"callee_memory_{index}"] = values[
            f"callee_memory_{index}"
        ]
    for register in REGISTERS:
        state.globals[f"callee_{register}"] = values[f"callee_{register}"]
    state.globals["call"] = claripy.BVV(0, 160)


class Sm83SwapAtHl(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        value = self.state.memory.load(self.state.regs.hl, 1)
        value = (value << 4) | claripy.LShR(value, 4)
        self.state.memory.store(self.state.regs.hl, value)
        self.state.regs.f = claripy.If(
            value == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)
        )
        self.jump(self.next_address)


class Sm83AndA(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x50, 8),
            claripy.BVV(0x10, 8),
        )
        self.jump(self.next_address)


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "InterlaceMergeSpriteBuffers")
    end = symbol_location(SYMBOLS, "Underground_Coll")
    copy_video = symbol_location(SYMBOLS, "CopyVideoData")
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
    project.hook(base, Sm83XorA(base + 1), length=1)
    project.hook(base + 1, Sm83StoreAImmediate(R_RAMB, base + 4), length=3)
    for offset in (20, 23, 26, 29):
        project.hook(
            base + offset,
            Sm83StoreAAtHlDecrement(base + offset + 1),
            length=1,
        )
    project.hook(
        base + 16,
        Sm83StoreAHighImmediate(0x8B, base + 18),
        length=2,
    )
    project.hook(
        base + 30,
        Sm83LoadAHighImmediate(0x8B, base + 32),
        length=2,
    )
    project.hook(base + 32, Sm83DecRegister("a", base + 33), length=1)
    project.hook(
        base + 33,
        Sm83StoreAHighImmediate(0x8B, base + 35),
        length=2,
    )
    project.hook(
        base + 37,
        Sm83LoadAImmediate(SPRITE_FLIPPED, base + 40),
        length=3,
    )
    project.hook(base + 40, Sm83AndA(base + 41), length=1)
    project.hook(base + 49, Sm83SwapAtHl(base + 51), length=2)
    project.hook(base + 54, Sm83OrRegister("c", base + 55), length=1)
    project.hook(
        base + 63,
        Sm83LoadAHighImmediate(0xB8, base + 65),
        length=2,
    )
    project.hook(copy_video.address, AssemblyCopyVideoData())
    state = project.factory.blank_state(addr=base)
    state.regs.sp = STACK
    set_assembly_registers(state, values)
    _setup(state, values)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=2)
    assert not manager.errored and len(manager.found) == 2
    return [
        Endpoint(
            **assembly_registers(final),
            memory=_memory(final),
            call=final.globals["call"],
            constraints=tuple(final.solver.constraints),
        )
        for final in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_interlace_merge_sprite_buffers")
    copy_video = project.loader.find_symbol("port_copy_video_data")
    assert function is not None and copy_video is not None
    project.hook(copy_video.rebased_addr, NativeCopyVideoData())
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, values, NATIVE_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 2
    return [
        Endpoint(
            **native_registers(final, NATIVE_STATE),
            memory=_memory(final, NATIVE_MEMORY),
            call=final.globals["call"],
            constraints=tuple(final.solver.constraints),
        )
        for final in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(
    not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`"
)
def test_interlace_merge_sprite_buffers_pathwise_equivalence() -> None:
    values = _inputs("interlace_merge_sprite_buffers")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "memory", "call"),
    )
