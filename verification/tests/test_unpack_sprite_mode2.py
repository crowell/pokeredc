from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

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
    Sm83LoadAImmediate,
    Sm83StoreAImmediate,
    Sm83XorA,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF
STACK = 0xD800

BUFFER1 = 0xA188
BUFFER2 = 0xA310
BUFFER_SIZE = 392
CUR_X = 0xD0A1
CUR_Y = 0xD0A2
WIDTH = 0xD0A3
HEIGHT = 0xD0A4
FLAGS = 0xD0A9
FLIPPED = 0xD0AA
OUTPUT = 0xD0AD
CACHED = 0xD0AF
TABLE0 = 0xD0B1
TABLE1 = 0xD0B3
REVERSE_TABLE = 0x2867
GLOBALS = (
    CUR_X,
    CUR_Y,
    WIDTH,
    HEIGHT,
    FLAGS,
    FLIPPED,
    OUTPUT,
    OUTPUT + 1,
    CACHED,
    CACHED + 1,
    TABLE0,
    TABLE0 + 1,
    TABLE1,
    TABLE1 + 1,
)
EXPECTED = bytes.fromhex(
    "cd4128faaad0f5afeaaad0faafd06ffab0d067cdd426cd4128f1eaaad0c3c727"
)
REVERSE = bytes.fromhex("0008040c020a060e0109050d030b070f")
SNAPSHOT_SIZE = len(GLOBALS) + 2 * BUFFER_SIZE + len(REVERSE)
CALL_INPUT_SIZE = len(REGISTERS) + SNAPSHOT_SIZE


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
    decode_input: claripy.ast.BV
    xor_input: claripy.ast.BV
    reset_calls: claripy.ast.BV
    decode_calls: claripy.ast.BV
    xor_calls: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def inputs(tag: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(tag)
    values["buffer1"] = claripy.BVS(f"{tag}_buffer1", BUFFER_SIZE * 8)
    values["buffer2"] = claripy.BVS(f"{tag}_buffer2", BUFFER_SIZE * 8)
    values["decode_buffer1"] = claripy.BVS(
        f"{tag}_decode_buffer1", BUFFER_SIZE * 8
    )
    values["decode_buffer2"] = claripy.BVS(
        f"{tag}_decode_buffer2", BUFFER_SIZE * 8
    )
    values["xor_buffer1"] = claripy.BVS(f"{tag}_xor_buffer1", BUFFER_SIZE * 8)
    values["xor_buffer2"] = claripy.BVS(f"{tag}_xor_buffer2", BUFFER_SIZE * 8)
    for index in range(len(GLOBALS)):
        values[f"global{index}"] = claripy.BVS(f"{tag}_global{index}", 8)
        values[f"decode_global{index}"] = claripy.BVS(
            f"{tag}_decode_global{index}", 8
        )
        values[f"xor_global{index}"] = claripy.BVS(
            f"{tag}_xor_global{index}", 8
        )
    for prefix in ("decode", "xor"):
        for register in REGISTERS:
            values[f"{prefix}_{register}"] = (
                claripy.Concat(
                    claripy.BVS(f"{tag}_{prefix}_flags", 4), claripy.BVV(0, 4)
                )
                if register == "f"
                else claripy.BVS(f"{tag}_{prefix}_{register}", 8)
            )
    return values


def snapshot(state, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        *(state.memory.load(base + address, 1) for address in GLOBALS),
        state.memory.load(base + BUFFER1, BUFFER_SIZE),
        state.memory.load(base + BUFFER2, BUFFER_SIZE),
        state.memory.load(base + REVERSE_TABLE, len(REVERSE)),
    )


def setup(state, values, base: int) -> None:
    state.memory.store(base + BUFFER1, values["buffer1"])
    state.memory.store(base + BUFFER2, values["buffer2"])
    state.memory.store(base + REVERSE_TABLE, claripy.BVV(REVERSE, len(REVERSE) * 8))
    for index, address in enumerate(GLOBALS):
        state.memory.store(base + address, values[f"global{index}"])
    state.globals["reset_calls"] = claripy.BVV(0, 8)
    state.globals["decode_calls"] = claripy.BVV(0, 8)
    state.globals["xor_calls"] = claripy.BVV(0, 8)
    state.globals["decode_input"] = claripy.BVV(0, 1)
    state.globals["xor_input"] = claripy.BVV(0, 1)
    state.globals["decode_buffer1"] = values["decode_buffer1"]
    state.globals["decode_buffer2"] = values["decode_buffer2"]
    state.globals["xor_buffer1"] = values["xor_buffer1"]
    state.globals["xor_buffer2"] = values["xor_buffer2"]
    for index in range(len(GLOBALS)):
        state.globals[f"decode_global{index}"] = values[f"decode_global{index}"]
        state.globals[f"xor_global{index}"] = values[f"xor_global{index}"]
    for prefix in ("decode", "xor"):
        for register in REGISTERS:
            state.globals[f"{prefix}_{register}"] = values[f"{prefix}_{register}"]


def reset_transition(state, base: int, get_registers, set_registers) -> None:
    registers = get_registers()
    flags = state.memory.load(base + FLAGS, 1)
    state.globals["reset_calls"] += 1
    registers["a"] = flags
    registers["f"] = (
        (registers["f"] & 0x10)
        | 0x20
        | claripy.If(
            (flags & 1) == 0, claripy.BVV(0x80, 8), claripy.BVV(0, 8)
        )
    )
    buffer1 = claripy.BVV(BUFFER1, 16)
    buffer2 = claripy.BVV(BUFFER2, 16)
    de = claripy.If((flags & 1) == 0, buffer1, buffer2)
    hl = claripy.If((flags & 1) == 0, buffer2, buffer1)
    registers["d"], registers["e"] = de[15:8], de[7:0]
    registers["h"], registers["l"] = hl[15:8], hl[7:0]
    registers["a"] = registers["l"]
    state.memory.store(base + OUTPUT, registers["a"])
    registers["a"] = registers["h"]
    state.memory.store(base + OUTPUT + 1, registers["a"])
    registers["a"] = registers["e"]
    state.memory.store(base + CACHED, registers["a"])
    registers["a"] = registers["d"]
    state.memory.store(base + CACHED + 1, registers["a"])
    set_registers(registers)


def decode_transition(state, base: int, get_registers, set_registers) -> None:
    registers = get_registers()
    state.globals["decode_calls"] += 1
    state.globals["decode_input"] = claripy.Concat(
        *(registers[name] for name in REGISTERS), snapshot(state, base)
    )
    state.memory.store(base + BUFFER1, state.globals["decode_buffer1"])
    state.memory.store(base + BUFFER2, state.globals["decode_buffer2"])
    for name in REGISTERS:
        registers[name] = state.globals[f"decode_{name}"]
    state.memory.store(base + CUR_X, claripy.BVV(0, 8))
    state.memory.store(base + CUR_Y, claripy.BVV(0, 8))
    for index, address in enumerate(GLOBALS):
        if address not in (CUR_X, CUR_Y, WIDTH, HEIGHT, FLAGS, FLIPPED):
            state.memory.store(base + address, state.globals[f"decode_global{index}"])
    set_registers(registers)


def xor_transition(state, base: int, get_registers, set_registers) -> None:
    registers = get_registers()
    state.globals["xor_calls"] += 1
    state.globals["xor_input"] = claripy.Concat(
        *(registers[name] for name in REGISTERS), snapshot(state, base)
    )
    state.memory.store(base + BUFFER1, state.globals["xor_buffer1"])
    state.memory.store(base + BUFFER2, state.globals["xor_buffer2"])
    for index, address in enumerate(GLOBALS):
        state.memory.store(base + address, state.globals[f"xor_global{index}"])
    for name in REGISTERS:
        registers[name] = state.globals[f"xor_{name}"]
    set_registers(registers)


def assembly_get(state):
    return assembly_registers(state)


def assembly_set(state, registers) -> None:
    set_assembly_registers(state, registers)


class ResetAssembly(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__()
        self.next_address = next_address

    def run(self):
        reset_transition(
            self.state,
            0,
            lambda: assembly_get(self.state),
            lambda registers: assembly_set(self.state, registers),
        )
        self.jump(self.next_address)


class DecodeAssembly(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__()
        self.next_address = next_address

    def run(self):
        decode_transition(
            self.state,
            0,
            lambda: assembly_get(self.state),
            lambda registers: assembly_set(self.state, registers),
        )
        self.jump(self.next_address)


class XorAssembly(angr.SimProcedure):
    def run(self):
        xor_transition(
            self.state,
            0,
            lambda: assembly_get(self.state),
            lambda registers: assembly_set(self.state, registers),
        )
        self.jump(DONE)


class RegisterCopy(angr.SimProcedure):
    def __init__(self, destination: str, source: str, next_address: int):
        super().__init__()
        self.destination = destination
        self.source = source
        self.next_address = next_address

    def run(self):
        registers = assembly_get(self.state)
        registers[self.destination] = registers[self.source]
        assembly_set(self.state, registers)
        self.jump(self.next_address)


class StackAF(angr.SimProcedure):
    def __init__(self, push: bool, next_address: int):
        super().__init__()
        self.push = push
        self.next_address = next_address

    def run(self):
        registers = assembly_get(self.state)
        sp = self.state.solver.eval(self.state.regs.sp)
        if self.push:
            self.state.memory.store(sp - 1, registers["a"])
            self.state.memory.store(sp - 2, registers["f"])
            self.state.regs.sp = sp - 2
        else:
            registers["f"] = self.state.memory.load(sp, 1)
            registers["a"] = self.state.memory.load(sp + 1, 1)
            assembly_set(self.state, registers)
            self.state.regs.sp = sp + 2
        self.jump(self.next_address)


class ResetNative(angr.SimProcedure):
    def run(self, pointer):
        def get_registers():
            return {
                name: self.state.memory.load(pointer + index, 1)
                for index, name in enumerate(REGISTERS)
            }

        def set_registers(registers):
            self.state.memory.store(
                pointer, claripy.Concat(*(registers[name] for name in REGISTERS))
            )

        self.state.memory.store(
            NATIVE_MEMORY + FLAGS, self.state.memory.load(pointer + 8, 1)
        )
        reset_transition(self.state, NATIVE_MEMORY, get_registers, set_registers)
        for index, address in enumerate(
            (OUTPUT, OUTPUT + 1, CACHED, CACHED + 1), start=1
        ):
            self.state.memory.store(
                pointer + 8 + index, self.state.memory.load(NATIVE_MEMORY + address, 1)
            )


class DecodeNative(angr.SimProcedure):
    def run(self, pointer, memory):
        def get_registers():
            return {
                name: self.state.memory.load(pointer + index, 1)
                for index, name in enumerate(REGISTERS)
            }

        def set_registers(registers):
            self.state.memory.store(
                pointer, claripy.Concat(*(registers[name] for name in REGISTERS))
            )

        decode_transition(self.state, NATIVE_MEMORY, get_registers, set_registers)


class XorNative(angr.SimProcedure):
    def run(self, pointer, memory):
        def get_registers():
            return {
                name: self.state.memory.load(pointer + index, 1)
                for index, name in enumerate(REGISTERS)
            }

        def set_registers(registers):
            self.state.memory.store(
                pointer, claripy.Concat(*(registers[name] for name in REGISTERS))
            )

        xor_transition(self.state, NATIVE_MEMORY, get_registers, set_registers)


def endpoint(state, base: int) -> Endpoint:
    registers = (
        native_registers(state, NATIVE_STATE)
        if base
        else assembly_registers(state)
    )
    return Endpoint(
        **registers,
        memory=snapshot(state, base),
        decode_input=state.globals["decode_input"],
        xor_input=state.globals["xor_input"],
        reset_calls=state.globals["reset_calls"],
        decode_calls=state.globals["decode_calls"],
        xor_calls=state.globals["xor_calls"],
        constraints=tuple(state.solver.constraints),
    )


def run_assembly(values) -> list[Endpoint]:
    location = symbol_location(SYMS, "UnpackSpriteMode2")
    end = symbol_location(SYMS, "StoreSpriteOutputPointer")
    reset = symbol_location(SYMS, "ResetSpriteBufferPointers")
    decode = symbol_location(SYMS, "SpriteDifferentialDecode")
    xor = symbol_location(SYMS, "XorSpriteChunks")
    assert location.bank == 0
    assert end.address - location.address == len(EXPECTED)
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    assert reset.address == 0x2841
    assert decode.address == 0x26D4
    assert xor.address == 0x27C7
    project = angr.Project(
        rom_window(ROM, 0),
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
    project.hook(base, ResetAssembly(base + 3), length=3)
    project.hook(base + 3, Sm83LoadAImmediate(FLIPPED, base + 6), length=3)
    project.hook(base + 6, StackAF(True, base + 7), length=1)
    project.hook(base + 7, Sm83XorA(base + 8), length=1)
    project.hook(base + 8, Sm83StoreAImmediate(FLIPPED, base + 11), length=3)
    project.hook(base + 11, Sm83LoadAImmediate(CACHED, base + 14), length=3)
    project.hook(base + 14, RegisterCopy("l", "a", base + 15), length=1)
    project.hook(base + 15, Sm83LoadAImmediate(CACHED + 1, base + 18), length=3)
    project.hook(base + 18, RegisterCopy("h", "a", base + 19), length=1)
    project.hook(base + 19, DecodeAssembly(base + 22), length=3)
    project.hook(base + 22, ResetAssembly(base + 25), length=3)
    project.hook(base + 25, StackAF(False, base + 26), length=1)
    project.hook(base + 26, Sm83StoreAImmediate(FLIPPED, base + 29), length=3)
    project.hook(xor.address, XorAssembly(), length=1)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.regs.sp = STACK
    setup(state, values, 0)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE)
    assert not manager.errored
    assert len(manager.found) == 1
    return [endpoint(found, 0) for found in manager.found]


def run_native(values) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_unpack_sprite_mode2")
    reset = project.loader.find_symbol("port_reset_sprite_buffer_pointers")
    decode = project.loader.find_symbol("port_sprite_differential_decode")
    xor = project.loader.find_symbol("port_xor_sprite_chunks")
    assert function is not None
    assert reset is not None
    assert decode is not None
    assert xor is not None
    project.hook(reset.rebased_addr, ResetNative())
    project.hook(decode.rebased_addr, DecodeNative())
    project.hook(xor.rebased_addr, XorNative())
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    setup(state, values, NATIVE_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    return [endpoint(deadended, NATIVE_MEMORY) for deadended in manager.deadended]


def assert_equal(solver, left, right, label: str) -> None:
    difference = left != right
    if not claripy.is_false(difference) and solver.satisfiable(
        extra_constraints=(difference,)
    ):
        raise AssertionError(f"{label} differs")


def assert_chunks(solver, left, right, bits: int, label: str) -> None:
    assert left.size() == bits
    assert right.size() == bits
    for offset in range(0, bits, 64):
        high = bits - 1 - offset
        low = max(0, high - 63)
        assert_equal(solver, left[high:low], right[high:low], f"{label} {low}:{high}")


def assert_equivalent(assembly: list[Endpoint], native: list[Endpoint]) -> None:
    assert len(assembly) == 1
    assert len(native) == 1
    left = assembly[0]
    right = native[0]
    solver = claripy.Solver()
    solver.add(left.constraints)
    solver.add(right.constraints)
    assert solver.satisfiable()
    for name in (
        *REGISTERS,
        "reset_calls",
        "decode_calls",
        "xor_calls",
    ):
        assert_equal(solver, getattr(left, name), getattr(right, name), name)
    assert_chunks(solver, left.memory, right.memory, SNAPSHOT_SIZE * 8, "memory")
    assert_chunks(
        solver,
        left.decode_input,
        right.decode_input,
        CALL_INPUT_SIZE * 8,
        "decode_input",
    )
    assert_chunks(
        solver,
        left.xor_input,
        right.xor_input,
        CALL_INPUT_SIZE * 8,
        "xor_input",
    )
    assert solver.is_true(left.reset_calls == 2)
    assert solver.is_true(left.decode_calls == 1)
    assert solver.is_true(left.xor_calls == 1)
    assert solver.is_true(right.reset_calls == 2)
    assert solver.is_true(right.decode_calls == 1)
    assert solver.is_true(right.xor_calls == 1)


@pytest.mark.skipif(
    not ELF.exists() or not ROM.exists() or not SYMS.exists(), reason="build"
)
def test_unpack_sprite_mode2_pathwise_equivalence():
    values = inputs("unpack_sprite_mode2")
    assert_equivalent(run_assembly(values), run_native(values))
