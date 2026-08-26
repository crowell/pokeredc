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
from verification.harness.sm83_shims import Sm83LoadAImmediate

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
MODE = 0xD0A9
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
    MODE,
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
MODE_INDEX = GLOBALS.index(MODE)
EXPECTED = bytes.fromhex("faa9d0fe02ca7728a7c2c7272188a1cdd4262110a3")
REVERSE = bytes.fromhex("0008040c020a060e0109050d030b070f")
SNAPSHOT_SIZE = len(GLOBALS) + 2 * BUFFER_SIZE + len(REVERSE)
CALL_INPUT_SIZE = len(REGISTERS) + SNAPSHOT_SIZE
POST_KINDS = ("decode0", "decode1", "xor", "mode2")


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
    decode0_input: claripy.ast.BV
    decode1_input: claripy.ast.BV
    xor_input: claripy.ast.BV
    mode2_input: claripy.ast.BV
    decode_calls: claripy.ast.BV
    xor_calls: claripy.ast.BV
    mode2_calls: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def inputs(tag: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(tag)
    values["buffer1"] = claripy.BVS(f"{tag}_buffer1", BUFFER_SIZE * 8)
    values["buffer2"] = claripy.BVS(f"{tag}_buffer2", BUFFER_SIZE * 8)
    for index in range(len(GLOBALS)):
        values[f"global{index}"] = claripy.BVS(f"{tag}_global{index}", 8)
    for kind in POST_KINDS:
        values[f"{kind}_buffer1"] = claripy.BVS(
            f"{tag}_{kind}_buffer1", BUFFER_SIZE * 8
        )
        values[f"{kind}_buffer2"] = claripy.BVS(
            f"{tag}_{kind}_buffer2", BUFFER_SIZE * 8
        )
        for index in range(len(GLOBALS)):
            values[f"{kind}_global{index}"] = claripy.BVS(
                f"{tag}_{kind}_global{index}", 8
            )
        for register in REGISTERS:
            values[f"{kind}_{register}"] = (
                claripy.Concat(
                    claripy.BVS(f"{tag}_{kind}_flags", 4), claripy.BVV(0, 4)
                )
                if register == "f"
                else claripy.BVS(f"{tag}_{kind}_{register}", 8)
            )
    return values


def snapshot(state, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        *(state.memory.load(base + address, 1) for address in GLOBALS),
        state.memory.load(base + BUFFER1, BUFFER_SIZE),
        state.memory.load(base + BUFFER2, BUFFER_SIZE),
        state.memory.load(base + REVERSE_TABLE, len(REVERSE)),
    )


def setup(state, values, base: int, domain: str) -> None:
    state.memory.store(base + BUFFER1, values["buffer1"])
    state.memory.store(base + BUFFER2, values["buffer2"])
    state.memory.store(base + REVERSE_TABLE, claripy.BVV(REVERSE, len(REVERSE) * 8))
    for index, address in enumerate(GLOBALS):
        state.memory.store(base + address, values[f"global{index}"])
    mode = values[f"global{MODE_INDEX}"]
    if domain == "zero":
        state.solver.add(mode == 0)
    elif domain == "two":
        state.solver.add(mode == 2)
    else:
        state.solver.add(mode != 0, mode != 2)
    for name in ("decode", "xor", "mode2"):
        state.globals[f"{name}_calls"] = claripy.BVV(0, 8)
    for name in ("decode0_input", "decode1_input", "xor_input", "mode2_input"):
        state.globals[name] = claripy.BVV(0, CALL_INPUT_SIZE * 8)
    for kind in POST_KINDS:
        state.globals[f"{kind}_buffer1"] = values[f"{kind}_buffer1"]
        state.globals[f"{kind}_buffer2"] = values[f"{kind}_buffer2"]
        for index in range(len(GLOBALS)):
            state.globals[f"{kind}_global{index}"] = values[
                f"{kind}_global{index}"
            ]
        for register in REGISTERS:
            state.globals[f"{kind}_{register}"] = values[f"{kind}_{register}"]


def apply_boundary(state, base: int, kind: str, get_registers, set_registers) -> None:
    registers = get_registers()
    if kind == "decode":
        index = state.solver.eval(state.globals["decode_calls"])
        assert index in (0, 1)
        post = f"decode{index}"
        state.globals[f"decode{index}_input"] = claripy.Concat(
            *(registers[name] for name in REGISTERS), snapshot(state, base)
        )
        state.globals["decode_calls"] += 1
    else:
        post = kind
        state.globals[f"{kind}_input"] = claripy.Concat(
            *(registers[name] for name in REGISTERS), snapshot(state, base)
        )
        state.globals[f"{kind}_calls"] += 1
    state.memory.store(base + BUFFER1, state.globals[f"{post}_buffer1"])
    state.memory.store(base + BUFFER2, state.globals[f"{post}_buffer2"])
    for index, address in enumerate(GLOBALS):
        state.memory.store(base + address, state.globals[f"{post}_global{index}"])
    for register in REGISTERS:
        registers[register] = state.globals[f"{post}_{register}"]
    set_registers(registers)


class CompareImmediate(angr.SimProcedure):
    def __init__(self, value: int, next_address: int):
        super().__init__()
        self.value = value
        self.next_address = next_address

    def run(self):
        registers = assembly_registers(self.state)
        left = registers["a"]
        right = claripy.BVV(self.value, 8)
        registers["f"] = (
            claripy.BVV(0x40, 8)
            | claripy.If(left == right, claripy.BVV(0x80, 8), claripy.BVV(0, 8))
            | claripy.If(
                (left & 0x0F) < (right & 0x0F),
                claripy.BVV(0x20, 8),
                claripy.BVV(0, 8),
            )
            | claripy.If(left < right, claripy.BVV(0x10, 8), claripy.BVV(0, 8))
        )
        set_assembly_registers(self.state, registers)
        self.jump(self.next_address)


class AndA(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__()
        self.next_address = next_address

    def run(self):
        registers = assembly_registers(self.state)
        registers["f"] = claripy.BVV(0x20, 8) | claripy.If(
            registers["a"] == 0,
            claripy.BVV(0x80, 8),
            claripy.BVV(0, 8),
        )
        set_assembly_registers(self.state, registers)
        self.jump(self.next_address)


class ConditionalJump(angr.SimProcedure):
    def __init__(self, taken: int, fallthrough: int, when_zero: bool):
        super().__init__()
        self.taken = taken
        self.fallthrough = fallthrough
        self.when_zero = when_zero

    def run(self):
        self.inhibit_autoret = True
        zero = (assembly_registers(self.state)["f"] & 0x80) != 0
        condition = zero if self.when_zero else claripy.Not(zero)
        self.successors.add_successor(
            self.state.copy(), self.taken, condition, "Ijk_Boring"
        )
        self.successors.add_successor(
            self.state.copy(), self.fallthrough, claripy.Not(condition), "Ijk_Boring"
        )


class LoadHL(angr.SimProcedure):
    def __init__(self, value: int, next_address: int):
        super().__init__()
        self.value = value
        self.next_address = next_address

    def run(self):
        registers = assembly_registers(self.state)
        registers["h"] = claripy.BVV(self.value >> 8, 8)
        registers["l"] = claripy.BVV(self.value & 0xFF, 8)
        set_assembly_registers(self.state, registers)
        self.jump(self.next_address)


class AssemblyBoundary(angr.SimProcedure):
    def __init__(self, kind: str, next_address: int):
        super().__init__()
        self.kind = kind
        self.next_address = next_address

    def run(self):
        apply_boundary(
            self.state,
            0,
            self.kind,
            lambda: assembly_registers(self.state),
            lambda registers: set_assembly_registers(self.state, registers),
        )
        self.jump(self.next_address)


class NativeBoundary(angr.SimProcedure):
    def __init__(self, kind: str):
        super().__init__()
        self.kind = kind

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

        apply_boundary(
            self.state, NATIVE_MEMORY, self.kind, get_registers, set_registers
        )


def endpoint(state, base: int) -> Endpoint:
    registers = native_registers(state, NATIVE_STATE) if base else assembly_registers(state)
    return Endpoint(
        **registers,
        memory=snapshot(state, base),
        decode0_input=state.globals["decode0_input"],
        decode1_input=state.globals["decode1_input"],
        xor_input=state.globals["xor_input"],
        mode2_input=state.globals["mode2_input"],
        decode_calls=state.globals["decode_calls"],
        xor_calls=state.globals["xor_calls"],
        mode2_calls=state.globals["mode2_calls"],
        constraints=tuple(state.solver.constraints),
    )


def run_assembly(values, domain: str) -> Endpoint:
    location = symbol_location(SYMS, "UnpackSprite")
    decode = symbol_location(SYMS, "SpriteDifferentialDecode")
    xor = symbol_location(SYMS, "XorSpriteChunks")
    mode2 = symbol_location(SYMS, "UnpackSpriteMode2")
    assert location.bank == 0
    assert decode.address - location.address == len(EXPECTED)
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
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
    project.hook(base, Sm83LoadAImmediate(MODE, base + 3), length=3)
    project.hook(base + 3, CompareImmediate(2, base + 5), length=2)
    project.hook(
        base + 5, ConditionalJump(mode2.address, base + 8, True), length=3
    )
    project.hook(base + 8, AndA(base + 9), length=1)
    project.hook(
        base + 9, ConditionalJump(xor.address, base + 12, False), length=3
    )
    project.hook(base + 12, LoadHL(BUFFER1, base + 15), length=3)
    project.hook(base + 15, AssemblyBoundary("decode", base + 18), length=3)
    project.hook(base + 18, LoadHL(BUFFER2, decode.address), length=3)
    project.hook(decode.address, AssemblyBoundary("decode", DONE), length=1)
    project.hook(xor.address, AssemblyBoundary("xor", DONE), length=1)
    project.hook(mode2.address, AssemblyBoundary("mode2", DONE), length=1)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.regs.sp = STACK
    setup(state, values, 0, domain)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE)
    assert not manager.errored
    assert len(manager.found) == 1
    return endpoint(manager.found[0], 0)


def run_native(values, domain: str) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_unpack_sprite")
    decode = project.loader.find_symbol("port_sprite_differential_decode")
    xor = project.loader.find_symbol("port_xor_sprite_chunks")
    mode2 = project.loader.find_symbol("port_unpack_sprite_mode2")
    assert function is not None
    assert decode is not None
    assert xor is not None
    assert mode2 is not None
    project.hook(decode.rebased_addr, NativeBoundary("decode"))
    project.hook(xor.rebased_addr, NativeBoundary("xor"))
    project.hook(mode2.rebased_addr, NativeBoundary("mode2"))
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    setup(state, values, NATIVE_MEMORY, domain)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert manager.deadended
    return [endpoint(state, NATIVE_MEMORY) for state in manager.deadended]


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


def assert_equivalent(left: Endpoint, right: Endpoint, domain: str) -> None:
    solver = claripy.Solver()
    solver.add(left.constraints)
    solver.add(right.constraints)
    assert solver.satisfiable()
    for name in (*REGISTERS, "decode_calls", "xor_calls", "mode2_calls"):
        assert_equal(solver, getattr(left, name), getattr(right, name), name)
    assert_chunks(solver, left.memory, right.memory, SNAPSHOT_SIZE * 8, "memory")
    for name in ("decode0_input", "decode1_input", "xor_input", "mode2_input"):
        assert_chunks(
            solver,
            getattr(left, name),
            getattr(right, name),
            CALL_INPUT_SIZE * 8,
            name,
        )
    expected = {
        "zero": (2, 0, 0),
        "xor": (0, 1, 0),
        "two": (0, 0, 1),
    }[domain]
    for name, count in zip(
        ("decode_calls", "xor_calls", "mode2_calls"), expected, strict=True
    ):
        assert solver.is_true(getattr(left, name) == count)
        assert solver.is_true(getattr(right, name) == count)


@pytest.mark.skipif(
    not ELF.exists() or not ROM.exists() or not SYMS.exists(), reason="build"
)
def test_unpack_sprite_pathwise_equivalence():
    for domain in ("zero", "xor", "two"):
        values = inputs(f"unpack_sprite_{domain}")
        assembly = run_assembly(values, domain)
        native = run_native(values, domain)
        assert len(native) == {"zero": 1, "xor": 3, "two": 1}[domain]
        for endpoint_state in native:
            assert_equivalent(assembly, endpoint_state, domain)
