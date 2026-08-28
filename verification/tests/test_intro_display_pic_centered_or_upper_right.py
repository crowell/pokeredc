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
    Sm83LoadAHighImmediate,
    Sm83LoadAImmediate,
    Sm83StoreAHighImmediate,
    Sm83StoreAImmediate,
    Sm83XorA,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF

BUFFER0 = 0xA000
BUFFER1 = 0xA188
BUFFER2 = 0xA310
BUFFER_SIZE = 392
BUFFER_BYTES = 3 * BUFFER_SIZE
COPY_DESTINATION_BYTES = 2 * BUFFER_SIZE
TILE_START = 0xC3C2
TILE_END = 0xC475
TILE_BYTES = TILE_END - TILE_START + 1

R_RAMB = 0x4000
R_ROMB = 0x2000
W_PREDEF_ID = 0xCC4E
W_PREDEF_HL = 0xCC4F
W_PREDEF_DE = 0xCC51
W_PREDEF_BC = 0xCC53
W_PREDEF_PARENT = 0xCF12
W_SPRITE_FLIPPED = 0xD0AA
W_SPRITE_SOURCE = 0xD0AB
W_PREDEF_BANK = 0xD0B7
H_INTERLACE_COUNTER = 0xFF8B
H_LOADED_ROM_BANK = 0xFFB8
H_START_TILE_ID = 0xFFE1

COPY_VIDEO_GLOBALS = (
    0xFFBA,
    H_LOADED_ROM_BANK,
    H_INTERLACE_COUNTER,
    R_ROMB,
    0xFFC7,
    0xFFC8,
    0xFFC9,
    0xFFCA,
    0xFFC6,
    0xFFD6,
)
OBSERVED_GLOBALS = tuple(
    dict.fromkeys(
        (
            R_RAMB,
            R_ROMB,
            W_PREDEF_ID,
            W_PREDEF_HL,
            W_PREDEF_HL + 1,
            W_PREDEF_DE,
            W_PREDEF_DE + 1,
            W_PREDEF_BC,
            W_PREDEF_BC + 1,
            W_PREDEF_PARENT,
            W_SPRITE_FLIPPED,
            W_SPRITE_SOURCE,
            W_SPRITE_SOURCE + 1,
            W_PREDEF_BANK,
            H_INTERLACE_COUNTER,
            H_LOADED_ROM_BANK,
            H_START_TILE_ID,
            *COPY_VIDEO_GLOBALS,
        )
    )
)

EXPECTED = bytes.fromhex(
    "c578cdeb362188a11100a0011003cdb500110090cdea16c179a721c3c32003"
    "21f6c3afe0e13e01c36d3e"
)
PREDEF_EXPECTED = bytes.fromhex(
    "ea4eccf0b8ea12cff53e13e0b8ea0020cd497efab7d0e0b8ea0020118d3e"
    "d5e9f1e0b8ea0020c9"
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
    fields: claripy.ast.BV
    calls: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _canonical_symbolic_registers(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["buffers"] = claripy.BVS(f"{prefix}_buffers", BUFFER_BYTES * 8)
    values["tiles"] = claripy.BVS(f"{prefix}_tiles", TILE_BYTES * 8)
    values["writes"] = claripy.BVS(f"{prefix}_writes", 49 * 8)
    for index, _address in enumerate(OBSERVED_GLOBALS):
        values[f"global_{index}"] = claripy.BVS(
            f"{prefix}_global_{index}", 8
        )
    for register in REGISTERS:
        values[f"copy_post_{register}"] = (
            claripy.Concat(
                claripy.BVS(f"{prefix}_copy_post_flags", 4),
                claripy.BVV(0, 4),
            )
            if register == "f"
            else claripy.BVS(f"{prefix}_copy_post_{register}", 8)
        )
        values[f"interlace_post_{register}"] = (
            claripy.Concat(
                claripy.BVS(f"{prefix}_interlace_post_flags", 4),
                claripy.BVV(0, 4),
            )
            if register == "f"
            else claripy.BVS(f"{prefix}_interlace_post_{register}", 8)
        )
    values["copy_post_destination"] = claripy.BVS(
        f"{prefix}_copy_post_destination", COPY_DESTINATION_BYTES * 8
    )
    values["interlace_post_buffers"] = claripy.BVS(
        f"{prefix}_interlace_post_buffers", BUFFER_BYTES * 8
    )
    for index, _address in enumerate((R_RAMB, *COPY_VIDEO_GLOBALS)):
        values[f"interlace_post_global_{index}"] = claripy.BVS(
            f"{prefix}_interlace_post_global_{index}", 8
        )
    return values


def _setup(
    state: angr.SimState,
    values: dict[str, claripy.ast.BV],
    memory: int = 0,
) -> None:
    state.memory.store(memory + BUFFER0, values["buffers"])
    state.memory.store(memory + TILE_START, values["tiles"])
    for index, address in enumerate(OBSERVED_GLOBALS):
        state.memory.store(memory + address, values[f"global_{index}"])
    state.globals["saved_b"] = values["b"]
    state.globals["saved_c"] = values["c"]
    state.globals["saved_predef_a"] = claripy.BVV(0, 8)
    state.globals["saved_predef_f"] = claripy.BVV(0, 8)
    state.globals["writes"] = [
        values["writes"][(48 - index) * 8 + 7 : (48 - index) * 8]
        for index in range(49)
    ]
    state.globals["call_index"] = 0


def _registers(
    state: angr.SimState,
    native: bool,
    register_address: claripy.ast.BV | int = 0,
) -> dict[str, claripy.ast.BV]:
    return (
        native_registers(state, register_address)
        if native
        else assembly_registers(state)
    )


def _set_registers(
    state: angr.SimState,
    values: dict[str, claripy.ast.BV],
    prefix: str,
    native: bool,
    register_address: claripy.ast.BV | int = 0,
) -> None:
    for offset, register in enumerate(REGISTERS):
        value = values[f"{prefix}_{register}"]
        if native:
            state.memory.store(register_address + offset, value)
        else:
            setattr(
                state.regs,
                register,
                sm83_flags_to_z80(value) if register == "f" else value,
            )


def _record(
    state: angr.SimState,
    index: int,
    registers: dict[str, claripy.ast.BV],
    extra: tuple[claripy.ast.BV, ...],
) -> None:
    state.globals[f"call_{index}"] = claripy.Concat(
        claripy.BVV(index, 8),
        *(registers[name] for name in REGISTERS),
        *extra,
    )
    state.globals["call_index"] = index + 1


def _memory(state: angr.SimState, base: int = 0) -> claripy.ast.BV:
    return claripy.Concat(
        state.memory.load(base + BUFFER0, BUFFER_BYTES),
        state.memory.load(base + TILE_START, TILE_BYTES),
        *(state.memory.load(base + address, 1) for address in OBSERVED_GLOBALS),
    )


def _fields(state: angr.SimState, native: bool) -> claripy.ast.BV:
    if native:
        return state.memory.load(NATIVE_STATE + 8, 53)
    return claripy.Concat(
        state.memory.load(W_SPRITE_FLIPPED, 1),
        state.memory.load(W_PREDEF_HL, 1),
        state.memory.load(W_PREDEF_HL + 1, 1),
        state.memory.load(H_START_TILE_ID, 1),
        *state.globals["writes"],
    )


def _apply_pic_writes(
    state: angr.SimState,
    memory: int,
    base: int,
    flipped: bool,
) -> None:
    index = 0
    for column in range(7):
        column_offset = 6 - column if flipped else column
        for row in range(7):
            state.memory.store(
                memory + base + column_offset + 20 * row,
                state.globals["writes"][index],
            )
            index += 1


def _apply_pic_transition(
    state: angr.SimState,
    native: bool,
    register_address: claripy.ast.BV | int,
    flipped: bool,
) -> None:
    memory = NATIVE_MEMORY if native else 0
    registers = _registers(state, native, register_address)
    high = state.memory.load(
        register_address + 9 if native else W_PREDEF_HL, 1
    )
    low = state.memory.load(
        register_address + 10 if native else W_PREDEF_HL + 1, 1
    )
    base = state.solver.eval(claripy.Concat(high, low))
    tile = (
        state.memory.load(register_address + 11, 1)
        if native
        else state.memory.load(H_START_TILE_ID, 1)
    )
    writes = []
    for index in range(49):
        writes.append(tile + index)
    state.globals["writes"] = writes
    if native:
        for index, value in enumerate(writes):
            state.memory.store(register_address + 12 + index, value)
    registers["a"] = tile + 49
    registers["b"] = claripy.BVV(0, 8)
    registers["c"] = claripy.BVV(7, 8)
    registers["d"] = claripy.BVV(0, 8)
    registers["e"] = claripy.BVV(20, 8)
    registers["h"] = claripy.BVV((base - 1 if flipped else base + 7) >> 8, 8)
    registers["l"] = claripy.BVV((base - 1 if flipped else base + 7) & 0xFF, 8)
    last_add = (base + (120 if flipped else 126)) & 0xFFFF
    flags = 0xC0 | (0x10 if last_add > 0xFFEB else 0)
    registers["f"] = claripy.BVV(flags, 8)
    if native:
        for offset, name in enumerate(REGISTERS):
            state.memory.store(register_address + offset, registers[name])
    else:
        for name in REGISTERS:
            setattr(
                state.regs,
                name,
                sm83_flags_to_z80(registers[name]) if name == "f" else registers[name],
            )
    _apply_pic_writes(state, memory, base, flipped)


class SaveBC(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["saved_b"] = self.state.regs.b
        self.state.globals["saved_c"] = self.state.regs.c
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


class RestoreBC(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.b = self.state.globals["saved_b"]
        self.state.regs.c = self.state.globals["saved_c"]
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


class Jump(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__()
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.jump(self.target)


class AssemblyUncompress(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        _record(
            self.state,
            0,
            assembly_registers(self.state),
            (
                self.state.memory.load(W_SPRITE_SOURCE, 1),
                self.state.memory.load(W_SPRITE_SOURCE + 1, 1),
            ),
        )
        self.state.memory.store(W_SPRITE_SOURCE, self.state.regs.e)
        self.state.memory.store(W_SPRITE_SOURCE + 1, self.state.regs.d)
        self.state.regs.h = claripy.BVV(0xD0, 8)
        self.state.regs.l = claripy.BVV(0xAC, 8)
        self.jump(self.next_address)


class AssemblyCopy(angr.SimProcedure):
    def __init__(self, values: dict[str, claripy.ast.BV], next_address: int) -> None:
        super().__init__()
        self.values = values
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        _record(
            self.state,
            1,
            assembly_registers(self.state),
            (self.state.memory.load(BUFFER0, BUFFER_BYTES),),
        )
        _set_registers(self.state, self.values, "copy_post", False)
        self.state.memory.store(BUFFER0, self.values["copy_post_destination"])
        self.jump(self.next_address)


class AssemblyInterlace(angr.SimProcedure):
    def __init__(self, values: dict[str, claripy.ast.BV], next_address: int) -> None:
        super().__init__()
        self.values = values
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        _record(
            self.state,
            2,
            assembly_registers(self.state),
            (
                self.state.memory.load(BUFFER0, BUFFER_BYTES),
                self.state.memory.load(R_RAMB, 1),
                self.state.memory.load(W_SPRITE_FLIPPED, 1),
                *(self.state.memory.load(address, 1) for address in COPY_VIDEO_GLOBALS),
            ),
        )
        _set_registers(self.state, self.values, "interlace_post", False)
        self.state.memory.store(BUFFER0, self.values["interlace_post_buffers"])
        for index, address in enumerate((R_RAMB, *COPY_VIDEO_GLOBALS)):
            self.state.memory.store(
                address, self.values[f"interlace_post_global_{index}"]
            )
        self.jump(self.next_address)


class AssemblyPointer(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        registers = assembly_registers(self.state)
        _record(
            self.state,
            3,
            registers,
            (
                self.state.memory.load(W_PREDEF_ID, 1),
                claripy.BVV(0x0F, 8),
                claripy.BVV(0xC6, 8),
                claripy.BVV(0x70, 8),
            ),
        )
        self.state.memory.store(W_PREDEF_HL, registers["h"])
        self.state.memory.store(W_PREDEF_HL + 1, registers["l"])
        self.state.memory.store(W_PREDEF_DE, registers["d"])
        self.state.memory.store(W_PREDEF_DE + 1, registers["e"])
        self.state.memory.store(W_PREDEF_BC, registers["b"])
        self.state.memory.store(W_PREDEF_BC + 1, registers["c"])
        self.state.memory.store(W_PREDEF_BANK, claripy.BVV(0x0F, 8))
        self.state.regs.a = claripy.BVV(0x70, 8)
        self.state.regs.f = claripy.BVV(0x00, 8)
        self.state.regs.d = claripy.BVV(0x7E, 8)
        self.state.regs.e = claripy.BVV(0x7F, 8)
        self.state.regs.h = claripy.BVV(0x70, 8)
        self.state.regs.l = claripy.BVV(0xC6, 8)
        self.jump(self.next_address)


class AssemblyTarget(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        for flipped in (False, True):
            child = self.state.copy()
            flip = child.memory.load(W_SPRITE_FLIPPED, 1)
            condition = flip == 0 if not flipped else flip != 0
            child.regs.d = claripy.BVV(0x3E, 8)
            child.regs.e = claripy.BVV(0x8D, 8)
            _record(
                child,
                4,
                assembly_registers(child),
                (
                    flip,
                    child.memory.load(W_PREDEF_HL, 1),
                    child.memory.load(W_PREDEF_HL + 1, 1),
                    child.memory.load(H_START_TILE_ID, 1),
                    *child.globals["writes"],
                ),
            )
            _apply_pic_transition(child, False, 0, flipped)
            self.successors.add_successor(
                child, self.next_address, condition, "Ijk_Boring"
            )


class SavePredefAF(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        registers = assembly_registers(self.state)
        self.state.globals["saved_predef_a"] = registers["a"]
        self.state.globals["saved_predef_f"] = registers["f"]
        self.jump(self.next_address)


class RestorePredefAF(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals["saved_predef_a"]
        self.state.regs.f = sm83_flags_to_z80(
            self.state.globals["saved_predef_f"]
        )
        self.jump(self.next_address)


class Finish(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(DONE)


class NativeUncompress(angr.SimProcedure):
    def run(
        self, register_address: claripy.ast.BV, memory_address: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        _record(
            self.state,
            0,
            native_registers(self.state, register_address),
            (
                self.state.memory.load(NATIVE_MEMORY + W_SPRITE_SOURCE, 1),
                self.state.memory.load(NATIVE_MEMORY + W_SPRITE_SOURCE + 1, 1),
            ),
        )
        registers = native_registers(self.state, register_address)
        self.state.memory.store(NATIVE_MEMORY + W_SPRITE_SOURCE, registers["e"])
        self.state.memory.store(NATIVE_MEMORY + W_SPRITE_SOURCE + 1, registers["d"])
        self.state.memory.store(register_address + 6, claripy.BVV(0xD0, 8))
        self.state.memory.store(register_address + 7, claripy.BVV(0xAC, 8))


class NativeCopy(angr.SimProcedure):
    def __init__(self, values: dict[str, claripy.ast.BV]) -> None:
        super().__init__()
        self.values = values

    def run(
        self, register_address: claripy.ast.BV, memory_address: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        _record(
            self.state,
            1,
            native_registers(self.state, register_address),
            (self.state.memory.load(NATIVE_MEMORY + BUFFER0, BUFFER_BYTES),),
        )
        _set_registers(
            self.state, self.values, "copy_post", True, register_address
        )
        self.state.memory.store(
            NATIVE_MEMORY + BUFFER0, self.values["copy_post_destination"]
        )


class NativeInterlace(angr.SimProcedure):
    def __init__(self, values: dict[str, claripy.ast.BV]) -> None:
        super().__init__()
        self.values = values

    def run(
        self, register_address: claripy.ast.BV, memory_address: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        _record(
            self.state,
            2,
            native_registers(self.state, register_address),
            (
                self.state.memory.load(NATIVE_MEMORY + BUFFER0, BUFFER_BYTES),
                self.state.memory.load(NATIVE_MEMORY + R_RAMB, 1),
                self.state.memory.load(NATIVE_MEMORY + W_SPRITE_FLIPPED, 1),
                *(
                    self.state.memory.load(NATIVE_MEMORY + address, 1)
                    for address in COPY_VIDEO_GLOBALS
                ),
            ),
        )
        _set_registers(
            self.state, self.values, "interlace_post", True, register_address
        )
        self.state.memory.store(
            NATIVE_MEMORY + BUFFER0, self.values["interlace_post_buffers"]
        )
        for index, address in enumerate((R_RAMB, *COPY_VIDEO_GLOBALS)):
            self.state.memory.store(
                NATIVE_MEMORY + address,
                self.values[f"interlace_post_global_{index}"],
            )


class NativePointer(angr.SimProcedure):
    def run(self, state_address: claripy.ast.BV) -> None:  # type: ignore[override]
        registers = native_registers(self.state, state_address)
        _record(
            self.state,
            3,
            registers,
            tuple(self.state.memory.load(state_address + offset, 1) for offset in (8, 16, 17, 18)),
        )
        self.state.memory.store(state_address + 9, registers["h"])
        self.state.memory.store(state_address + 10, registers["l"])
        self.state.memory.store(state_address + 11, registers["d"])
        self.state.memory.store(state_address + 12, registers["e"])
        self.state.memory.store(state_address + 13, registers["b"])
        self.state.memory.store(state_address + 14, registers["c"])
        self.state.memory.store(state_address + 15, claripy.BVV(0x0F, 8))
        outputs = {
            "a": claripy.BVV(0x70, 8),
            "f": claripy.BVV(0x00, 8),
            "b": registers["b"],
            "c": registers["c"],
            "d": claripy.BVV(0x7E, 8),
            "e": claripy.BVV(0x7F, 8),
            "h": claripy.BVV(0x70, 8),
            "l": claripy.BVV(0xC6, 8),
        }
        for offset, name in enumerate(REGISTERS):
            self.state.memory.store(state_address + offset, outputs[name])


class NativeTarget(angr.SimProcedure):
    def run(self, state_address: claripy.ast.BV) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        for destination in (0xC3F6, 0xC3C3):
            for flipped in (False, True):
                child = self.state.copy()
                flip = child.memory.load(state_address + 8, 1)
                actual_destination = claripy.Concat(
                    child.memory.load(state_address + 9, 1),
                    child.memory.load(state_address + 10, 1),
                )
                condition = claripy.And(
                    actual_destination == destination,
                    flip == 0 if not flipped else flip != 0,
                )
                child.add_constraints(condition)
                child.globals["writes"] = [
                    child.memory.load(state_address + 12 + index, 1)
                    for index in range(49)
                ]
                _record(
                    child,
                    4,
                    native_registers(child, state_address),
                    (
                        flip,
                        child.memory.load(state_address + 9, 1),
                        child.memory.load(state_address + 10, 1),
                        child.memory.load(state_address + 11, 1),
                        *child.globals["writes"],
                    ),
                )
                _apply_pic_transition(child, True, state_address, flipped)
                return_address = child.memory.load(
                    child.regs.sp, 8, endness="Iend_LE"
                )
                child.regs.sp += 8
                self.successors.add_successor(
                    child, return_address, claripy.BoolV(True), "Ijk_Ret"
                )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "IntroDisplayPicCenteredOrUpperRight")
    predef = symbol_location(SYMBOLS, "Predef")
    pointer_entry = symbol_location(
        SYMBOLS, "CopyUncompressedPicToTilemapPredef"
    )
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    assert linked_bytes(ROM, predef, len(PREDEF_EXPECTED)) == PREDEF_EXPECTED
    assert linked_bytes(ROM, pointer_entry, 3) == bytes.fromhex("0fc670")
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
    project.hook(base, SaveBC(base + 1), length=1)
    project.hook(base + 1, LoadRegister("a", "b", base + 2), length=1)
    project.hook(base + 2, AssemblyUncompress(base + 5), length=3)
    project.hook(base + 5, LoadPair("h", "l", BUFFER1, base + 8), length=3)
    project.hook(base + 8, LoadPair("d", "e", BUFFER0, base + 11), length=3)
    project.hook(base + 11, LoadPair("b", "c", 0x0310, base + 14), length=3)
    project.hook(base + 14, AssemblyCopy(values, base + 17), length=3)
    project.hook(base + 17, LoadPair("d", "e", 0x9000, base + 20), length=3)
    project.hook(base + 20, AssemblyInterlace(values, base + 23), length=3)
    project.hook(base + 23, RestoreBC(base + 24), length=1)
    project.hook(base + 24, LoadRegister("a", "c", base + 25), length=1)
    project.hook(base + 25, Sm83AndA(base + 26), length=1)
    project.hook(base + 26, LoadPair("h", "l", 0xC3C3, base + 29), length=3)
    project.hook(base + 31, LoadPair("h", "l", 0xC3F6, base + 34), length=3)
    project.hook(base + 34, Sm83XorA(base + 35), length=1)
    project.hook(base + 35, Sm83StoreAHighImmediate(0xE1, base + 37), length=2)
    project.hook(base + 39, Jump(predef.address), length=3)

    pbase = predef.address
    project.hook(pbase, Sm83StoreAImmediate(W_PREDEF_ID, pbase + 3), length=3)
    project.hook(pbase + 3, Sm83LoadAHighImmediate(0xB8, pbase + 5), length=2)
    project.hook(pbase + 5, Sm83StoreAImmediate(W_PREDEF_PARENT, pbase + 8), length=3)
    project.hook(pbase + 8, SavePredefAF(pbase + 9), length=1)
    project.hook(pbase + 11, Sm83StoreAHighImmediate(0xB8, pbase + 13), length=2)
    project.hook(pbase + 13, Sm83StoreAImmediate(R_ROMB, pbase + 16), length=3)
    project.hook(pbase + 16, AssemblyPointer(pbase + 19), length=3)
    project.hook(pbase + 19, Sm83LoadAImmediate(W_PREDEF_BANK, pbase + 22), length=3)
    project.hook(pbase + 22, Sm83StoreAHighImmediate(0xB8, pbase + 24), length=2)
    project.hook(pbase + 24, Sm83StoreAImmediate(R_ROMB, pbase + 27), length=3)
    project.hook(pbase + 27, AssemblyTarget(pbase + 32), length=5)
    project.hook(pbase + 32, RestorePredefAF(pbase + 33), length=1)
    project.hook(pbase + 33, Sm83StoreAHighImmediate(0xB8, pbase + 35), length=2)
    project.hook(pbase + 35, Sm83StoreAImmediate(R_ROMB, pbase + 38), length=3)
    project.hook(pbase + 38, Finish(), length=1)

    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _setup(state, values)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=4)
    assert not manager.errored and len(manager.found) == 4
    return [
        Endpoint(
            **assembly_registers(final),
            memory=_memory(final),
            fields=_fields(final, False),
            calls=claripy.Concat(
                *(final.globals[f"call_{index}"] for index in range(5))
            ),
            constraints=tuple(final.solver.constraints),
        )
        for final in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol(
        "port_intro_display_pic_centered_or_upper_right"
    )
    uncompress = project.loader.find_symbol("port_uncompress_sprite_from_de")
    copy = project.loader.find_symbol("port_copy_data")
    interlace = project.loader.find_symbol("port_interlace_merge_sprite_buffers")
    pointer = project.loader.find_symbol("port_get_predef_pointer")
    target = project.loader.find_symbol("port_copy_uncompressed_pic_to_tilemap")
    assert all((function, uncompress, copy, interlace, pointer, target))
    project.hook(uncompress.rebased_addr, NativeUncompress())
    project.hook(copy.rebased_addr, NativeCopy(values))
    project.hook(interlace.rebased_addr, NativeInterlace(values))
    project.hook(pointer.rebased_addr, NativePointer())
    project.hook(target.rebased_addr, NativeTarget())
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, claripy.BVV(0, 32))
    state.memory.store(NATIVE_STATE + 12, values["writes"])
    _setup(state, values, NATIVE_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 4
    return [
        Endpoint(
            **native_registers(final, NATIVE_STATE),
            memory=_memory(final, NATIVE_MEMORY),
            fields=_fields(final, True),
            calls=claripy.Concat(
                *(final.globals[f"call_{index}"] for index in range(5))
            ),
            constraints=tuple(final.solver.constraints),
        )
        for final in manager.deadended
    ]


@pytest.mark.skipif(not ELF.exists(), reason="run native")
@pytest.mark.skipif(
    not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`"
)
def test_intro_display_pic_centered_or_upper_right_pathwise_equivalence() -> None:
    values = _canonical_symbolic_registers(
        "intro_display_pic_centered_or_upper_right"
    )
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "memory", "fields", "calls"),
    )
