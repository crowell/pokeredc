from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode
from pypcode import Context

from verification.harness.sm83_shims import Sm83CpAtHl, Sm83DecRegister
from verification.harness.rom import (
    collect_returns,
    linked_bytes,
    rom_window,
    symbol_location,
    sm83_flags_to_z80,
    z80_flags_to_sm83,
)


ROOT = Path(__file__).resolve().parents[2]
VERIFY = ROOT / "verification"
NATIVE_ELF = VERIFY / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"

GB_LEFT = 0xC000
GB_RIGHT = 0xC100
GB_STACK = 0xD000
GB_RETURN = 0xFFFF

NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000

FLAG_C = 0x10
FLAG_H = 0x20
FLAG_N = 0x40
FLAG_Z = 0x80


@dataclass(frozen=True)
class Endpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    c: claripy.ast.BV
    de: claripy.ast.BV
    hl: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@dataclass(frozen=True)
class StepEndpoint:
    a: claripy.ast.BV
    f: claripy.ast.BV
    c: claripy.ast.BV
    de: claripy.ast.BV
    hl: claripy.ast.BV
    continuation: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class StringCmpLoadLeft(angr.SimProcedure):
    def __init__(self, next_address: int, loop_boundary: int) -> None:
        super().__init__()
        self._next_address = next_address
        self._loop_boundary = loop_boundary

    def run(self) -> None:  # type: ignore[override]
        if self.state.globals.get("string_cmp_entered", False):
            self.jump(self._loop_boundary)
            return
        self.state.globals["string_cmp_entered"] = True
        self.state.regs.a = self.state.globals["string_cmp_left"]
        self.jump(self._next_address)


class StringCmpCompareRight(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        left = self.state.regs.a
        right = self.state.globals["string_cmp_right"]
        flags = claripy.BVV(0x02, 8)
        flags |= claripy.If(
            left == right, claripy.BVV(0x40, 8), claripy.BVV(0, 8)
        )
        flags |= claripy.If(
            (left & 0x0F).ULT(right & 0x0F),
            claripy.BVV(0x10, 8),
            claripy.BVV(0, 8),
        )
        flags |= claripy.If(
            left.ULT(right), claripy.BVV(1, 8), claripy.BVV(0, 8)
        )
        self.state.regs.f = flags
        self.jump(self._next_address)


def _assembly_endpoints(
    left: list[claripy.ast.BV], right: list[claripy.ast.BV]
) -> list[Endpoint]:
    assert len(left) == len(right)
    assert 0 < len(left) < 256
    location = symbol_location(SYMBOLS, "StringCmp")
    assert location.bank == 0
    address = location.address
    project = angr.Project(
        rom_window(ROM, location.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": address,
        },
    )
    # Generic Z80 and SM83 use the same opcode for CP (HL), but the bundled
    # Z80 SLEIGH model has a broken H calculation. Keep the correction local
    # and explicit until an audited SM83 language definition replaces it.
    project.hook(address + 1, Sm83CpAtHl(next_address=address + 2), length=1)
    state = project.factory.blank_state(addr=address)
    state.regs.de = GB_LEFT
    state.regs.hl = GB_RIGHT
    state.regs.c = len(left)
    state.regs.sp = GB_STACK
    for index, value in enumerate(left):
        state.memory.store(GB_LEFT + index, value)
    for index, value in enumerate(right):
        state.memory.store(GB_RIGHT + index, value)
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")

    returned = collect_returns(project, state, GB_RETURN)

    return [
        Endpoint(
            a=end.regs.a,
            f=z80_flags_to_sm83(end.regs.f),
            c=end.regs.c,
            de=end.regs.de,
            hl=end.regs.hl,
            constraints=tuple(end.solver.constraints),
        )
        for end in returned
    ]


def _native_endpoints(
    left: list[claripy.ast.BV], right: list[claripy.ast.BV]
) -> list[Endpoint]:
    assert len(left) == len(right)
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_string_cmp")
    assert function is not None

    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    state.memory.store(NATIVE_STATE + 0, claripy.BVV(0, 8))  # a
    state.memory.store(NATIVE_STATE + 1, claripy.BVV(0, 8))  # f
    state.memory.store(NATIVE_STATE + 2, claripy.BVV(len(left), 8))  # c
    state.memory.store(NATIVE_STATE + 3, claripy.BVV(0, 8))  # reserved
    state.memory.store(NATIVE_STATE + 4, claripy.BVV(GB_LEFT, 16), endness="Iend_LE")
    state.memory.store(NATIVE_STATE + 6, claripy.BVV(GB_RIGHT, 16), endness="Iend_LE")
    for index, value in enumerate(left):
        state.memory.store(NATIVE_MEMORY + GB_LEFT + index, value)
    for index, value in enumerate(right):
        state.memory.store(NATIVE_MEMORY + GB_RIGHT + index, value)

    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert manager.deadended

    return [
        Endpoint(
            a=end.memory.load(NATIVE_STATE + 0, 1),
            f=end.memory.load(NATIVE_STATE + 1, 1),
            c=end.memory.load(NATIVE_STATE + 2, 1),
            de=end.memory.load(NATIVE_STATE + 4, 2, endness="Iend_LE"),
            hl=end.memory.load(NATIVE_STATE + 6, 2, endness="Iend_LE"),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


def _endpoint_difference(left: Endpoint, right: Endpoint) -> claripy.ast.Bool:
    return claripy.Or(
        left.a != right.a,
        left.f != right.f,
        left.c != right.c,
        left.de != right.de,
        left.hl != right.hl,
    )


def _overlap_solver(left: Endpoint, right: Endpoint) -> claripy.Solver:
    solver = claripy.Solver()
    solver.add(left.constraints)
    solver.add(right.constraints)
    return solver


def _string_cmp_step_assembly(
    inputs: dict[str, claripy.ast.BV]
) -> list[StepEndpoint]:
    location = symbol_location(SYMBOLS, "StringCmp")
    address = location.address
    loop_boundary = 0xEFFF
    project = angr.Project(
        rom_window(ROM, location.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": address,
        },
    )
    project.hook(
        address,
        StringCmpLoadLeft(address + 1, loop_boundary),
        length=1,
    )
    project.hook(address + 1, StringCmpCompareRight(address + 2), length=1)
    project.hook(
        address + 5, Sm83DecRegister("c", address + 6), length=1
    )
    state = project.factory.blank_state(addr=address)
    state.regs.a = inputs["a"]
    state.regs.f = sm83_flags_to_z80(inputs["f"])
    state.regs.c = inputs["c"]
    state.regs.de = inputs["de"]
    state.regs.hl = inputs["hl"]
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    state.globals["string_cmp_left"] = inputs["left"]
    state.globals["string_cmp_right"] = inputs["right"]
    state.solver.add(
        claripy.Or(inputs["de"] != inputs["hl"], inputs["left"] == inputs["right"])
    )
    manager = project.factory.simulation_manager(state)
    manager.stashes["found"] = []
    while manager.active:
        manager.move(
            from_stash="active",
            to_stash="found",
            filter_func=lambda candidate: candidate.addr in {loop_boundary, GB_RETURN},
        )
        if manager.active:
            manager.step()
    assert not manager.errored
    assert {end.addr for end in manager.found} == {loop_boundary, GB_RETURN}
    return [
        StepEndpoint(
            a=end.regs.a,
            f=z80_flags_to_sm83(end.regs.f),
            c=end.regs.c,
            de=end.regs.de,
            hl=end.regs.hl,
            continuation=claripy.BVV(
                1 if end.addr == loop_boundary else 0, 8
            ),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _string_cmp_step_native(
    inputs: dict[str, claripy.ast.BV]
) -> list[StepEndpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_string_cmp_step")
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr,
        NATIVE_STATE,
        claripy.ZeroExt(56, inputs["left"]),
        claripy.ZeroExt(56, inputs["right"]),
    )
    state.memory.store(NATIVE_STATE, inputs["a"])
    state.memory.store(NATIVE_STATE + 1, inputs["f"])
    state.memory.store(NATIVE_STATE + 2, inputs["c"])
    state.memory.store(NATIVE_STATE + 3, 0)
    state.memory.store(NATIVE_STATE + 4, inputs["de"], endness="Iend_LE")
    state.memory.store(NATIVE_STATE + 6, inputs["hl"], endness="Iend_LE")
    state.solver.add(
        claripy.Or(inputs["de"] != inputs["hl"], inputs["left"] == inputs["right"])
    )
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        StepEndpoint(
            a=end.memory.load(NATIVE_STATE, 1),
            f=end.memory.load(NATIVE_STATE + 1, 1),
            c=end.memory.load(NATIVE_STATE + 2, 1),
            de=end.memory.load(NATIVE_STATE + 4, 2, endness="Iend_LE"),
            hl=end.memory.load(NATIVE_STATE + 6, 2, endness="Iend_LE"),
            continuation=claripy.If(
                end.regs.rax[7:0] == 0,
                claripy.BVV(1, 8),
                claripy.BVV(0, 8),
            ),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


def test_string_cmp_one_step_inductive_equivalence() -> None:
    for left_value in range(256):
        inputs = {
            name: claripy.BVS(f"string_cmp_step_{left_value}_{name}", bits)
            for name, bits in (
                ("a", 8), ("f", 8), ("c", 8), ("de", 16), ("hl", 16),
                ("right", 8),
            )
        }
        inputs["left"] = claripy.BVV(left_value, 8)
        assembly = _string_cmp_step_assembly(inputs)
        native = _string_cmp_step_native(inputs)
        overlaps = []
        for assembly_index, assembly_end in enumerate(assembly):
            for native_index, native_end in enumerate(native):
                solver = claripy.Solver()
                solver.add(assembly_end.constraints)
                solver.add(native_end.constraints)
                if not solver.satisfiable():
                    continue
                overlaps.append((assembly_index, native_index))
                solver.add(
                    claripy.Or(
                        *(
                            getattr(assembly_end, name) != getattr(native_end, name)
                            for name in (
                                "a", "f", "c", "de", "hl", "continuation"
                            )
                        )
                    )
                )
                if solver.satisfiable():
                    observable_names = (
                        "a", "f", "c", "de", "hl", "continuation"
                    )
                    input_names = tuple(inputs)
                    expressions = [inputs[name] for name in input_names]
                    expressions += [
                        getattr(endpoint, name)
                        for name in observable_names
                        for endpoint in (assembly_end, native_end)
                    ]
                    values = solver.batch_eval(expressions, 1)[0]
                    input_values = dict(zip(input_names, values[:len(input_names)]))
                    output_values = values[len(input_names):]
                    model_values = {
                        name: tuple(output_values[index:index + 2])
                        for index, name in zip(
                            range(0, len(output_values), 2), observable_names
                        )
                    }
                    pytest.fail(
                        f"left={left_value:#04x}, inputs={input_values}, "
                        f"assembly/native={model_values}"
                    )
        assert {left for left, _ in overlaps} == set(range(len(assembly)))
        assert {right for _, right in overlaps} == set(range(len(native)))


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make DEBUG=1 red`")
@pytest.mark.parametrize("length", [1, 2])
def test_string_cmp_symbolic_equivalence(length: int) -> None:
    left = [claripy.BVS(f"string_cmp_left_{index}", 8) for index in range(length)]
    right = [claripy.BVS(f"string_cmp_right_{index}", 8) for index in range(length)]
    assembly = _assembly_endpoints(left, right)
    native = _native_endpoints(left, right)

    # One path returns at each mismatching byte, plus one all-equal path.
    assert len(assembly) == length + 1
    assert len(native) == length + 1

    overlaps: list[tuple[int, int]] = []
    for assembly_index, assembly_end in enumerate(assembly):
        for native_index, native_end in enumerate(native):
            solver = _overlap_solver(assembly_end, native_end)
            if not solver.satisfiable():
                continue
            overlaps.append((assembly_index, native_index))
            solver.add(_endpoint_difference(assembly_end, native_end))
            assert not solver.satisfiable()

    # Every terminal path on either side must overlap a terminal path on the
    # other side; the pairwise checks above then rule out an observable
    # difference anywhere in those shared input domains.
    assert {left for left, _ in overlaps} == set(range(len(assembly)))
    assert {right for _, right in overlaps} == set(range(len(native)))


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make DEBUG=1 red`")
def test_string_cmp_uses_z80_compatible_instruction_encodings() -> None:
    location = symbol_location(SYMBOLS, "StringCmp")
    code = linked_bytes(ROM, location, 9)
    instructions = Context("z80:LE:16:default").disassemble(
        code, location.address
    ).instructions

    assert [(instruction.mnem, instruction.length) for instruction in instructions] == [
        ("LD", 1),
        ("CP", 1),
        ("RET", 1),
        ("INC", 1),
        ("INC", 1),
        ("DEC", 1),
        ("JR", 2),
        ("RET", 1),
    ]
    assert [instruction.body for instruction in instructions] == [
        "A,(DE)",
        "(HL)",
        "NZ",
        "DE",
        "HL",
        "C",
        "NZ,0x3a8e",
        "",
    ]
