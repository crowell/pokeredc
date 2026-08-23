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
    Sm83DecRegister,
    Sm83LoadAHighImmediate,
    Sm83StoreAHighImmediate,
    Sm83StoreAImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
STACK = 0xD000
RETURN = 0xFFFF
DONE = 0xEFFF
LOOP = 0xEFFE
DISABLE = 0xD0A0
H_MUTATE_WY = 0xFF96
R_WY = 0xFF4A
PREDEF_FIELDS = tuple(f"predef{index}" for index in range(6))
STATE_FIELDS = (*PREDEF_FIELDS, "disable", "mutate_wy", "wy")
MUTATE_EXPECTED = bytes.fromhex("f096a8e096e04a0e03c33937")
STEP_EXPECTED = bytes.fromhex("e096cd1941cd1941057820f4")
FUNCTION_EXPECTED = bytes.fromhex(
    "cd943e3e01eaa0d0afe096cd1941cd1941057820f4afeaa0d0c9"
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
    state: claripy.ast.BV
    calls: claripy.ast.BV
    continuation: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class XorRegister(angr.SimProcedure):
    def __init__(self, register: str, next_address: int):
        super().__init__()
        self._register = register
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a ^= getattr(self.state.regs, self._register)
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x40, 8),
            claripy.BVV(0, 8),
        )
        self.jump(self._next_address)


class XorA(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x40, 8)
        self.jump(self._next_address)


class LoadAConstant(angr.SimProcedure):
    def __init__(self, value: int, next_address: int):
        super().__init__()
        self._value = value
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(self._value, 8)
        self.jump(self._next_address)


class CopyRegister(angr.SimProcedure):
    def __init__(self, destination: str, source: str, next_address: int):
        super().__init__()
        self._destination = destination
        self._source = source
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        setattr(
            self.state.regs,
            self._destination,
            getattr(self.state.regs, self._source),
        )
        self.jump(self._next_address)


class BranchNotZero(angr.SimProcedure):
    def __init__(self, taken: int, fallthrough: int):
        super().__init__()
        self._taken = taken
        self._fallthrough = fallthrough

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.successors.add_successor(
            self.state.copy(), self._taken, (self.state.regs.f & 0x40) == 0,
            "Ijk_Boring",
        )
        self.successors.add_successor(
            self.state, self._fallthrough, (self.state.regs.f & 0x40) != 0,
            "Ijk_Boring",
        )


class Boundary(angr.SimProcedure):
    def __init__(self, destination: int):
        super().__init__()
        self._destination = destination

    def run(self) -> None:  # type: ignore[override]
        self.jump(self._destination)


def _set_assembly_outputs(
    state: angr.SimState, prefix: str, *, force_b_zero: bool = False
) -> None:
    for register in REGISTERS:
        value = (
            claripy.BVV(0, 8)
            if force_b_zero and register == "b"
            else state.globals[f"{prefix}_{register}"]
        )
        if register == "f":
            value = sm83_flags_to_z80(value)
        setattr(state.regs, register, value)


class AssemblyDelaySummary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        registers = assembly_registers(self.state)
        self.state.globals["call_delay"] = claripy.Concat(
            *(registers[register] for register in REGISTERS),
            claripy.BVV(0, 24),
        )
        _set_assembly_outputs(self.state, "delay_out")
        self.jump(DONE)


class NativeDelaySummary(angr.SimProcedure):
    def run(
        self, callee_state: claripy.ast.BV, observations: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        self.state.globals["call_delay"] = claripy.Concat(
            self.state.memory.load(callee_state, 10),
            self.state.memory.load(observations, 1),
        )
        self.state.memory.store(
            callee_state,
            claripy.Concat(
                *(self.state.globals[f"delay_out_{register}"]
                  for register in REGISTERS)
            ),
        )


class AssemblyMutateSummary(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        index = self.state.globals["mutate_index"]
        registers = assembly_registers(self.state)
        self.state.globals[f"call_mutate{index}"] = claripy.Concat(
            *(registers[register] for register in REGISTERS),
            self.state.memory.load(H_MUTATE_WY, 1),
            self.state.memory.load(R_WY, 1),
        )
        _set_assembly_outputs(self.state, f"mutate{index}_out")
        self.state.memory.store(
            H_MUTATE_WY, self.state.globals[f"mutate{index}_out_mutate_wy"]
        )
        self.state.memory.store(
            R_WY, self.state.globals[f"mutate{index}_out_wy"]
        )
        self.state.globals["mutate_index"] = index + 1
        self.jump(self._next_address)


class NativeMutateSummary(angr.SimProcedure):
    def run(self, callee_state: claripy.ast.BV) -> None:  # type: ignore[override]
        index = self.state.globals["mutate_index"]
        self.state.globals[f"call_mutate{index}"] = claripy.Concat(
            self.state.memory.load(callee_state, 8),
            self.state.memory.load(callee_state + 15, 2),
        )
        self.state.memory.store(
            callee_state,
            claripy.Concat(
                *(self.state.globals[f"mutate{index}_out_{register}"]
                  for register in REGISTERS)
            ),
        )
        self.state.memory.store(
            callee_state + 15,
            claripy.Concat(
                self.state.globals[f"mutate{index}_out_mutate_wy"],
                self.state.globals[f"mutate{index}_out_wy"],
            ),
        )
        self.state.globals["mutate_index"] = index + 1


class AssemblyPredefSummary(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        registers = assembly_registers(self.state)
        self.state.globals["call_predef"] = claripy.Concat(
            *(registers[register] for register in REGISTERS),
            *(self.state.globals[field] for field in PREDEF_FIELDS),
        )
        _set_assembly_outputs(self.state, "predef_out")
        self.jump(self._next_address)


class NativePredefSummary(angr.SimProcedure):
    def run(self, callee_state: claripy.ast.BV) -> None:  # type: ignore[override]
        self.state.globals["call_predef"] = self.state.memory.load(
            callee_state, 14
        )
        self.state.memory.store(
            callee_state,
            claripy.Concat(
                *(self.state.globals[f"predef_out_{register}"]
                  for register in REGISTERS)
            ),
        )


class AssemblyLoopSummary(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        registers = assembly_registers(self.state)
        self.state.globals["call_loop"] = claripy.Concat(
            *(registers[register] for register in REGISTERS),
            self.state.memory.load(H_MUTATE_WY, 1),
            self.state.memory.load(R_WY, 1),
        )
        _set_assembly_outputs(self.state, "loop_out", force_b_zero=True)
        self.state.memory.store(
            H_MUTATE_WY, self.state.globals["loop_out_mutate_wy"]
        )
        self.state.memory.store(R_WY, self.state.globals["loop_out_wy"])
        self.jump(self._next_address)


class NativeLoopSummary(angr.SimProcedure):
    def run(self, callee_state: claripy.ast.BV) -> None:  # type: ignore[override]
        self.state.globals["call_loop"] = claripy.Concat(
            self.state.memory.load(callee_state, 8),
            self.state.memory.load(callee_state + 15, 2),
        )
        outputs = [
            claripy.BVV(0, 8)
            if register == "b"
            else self.state.globals[f"loop_out_{register}"]
            for register in REGISTERS
        ]
        self.state.memory.store(callee_state, claripy.Concat(*outputs))
        self.state.memory.store(
            callee_state + 15,
            claripy.Concat(
                self.state.globals["loop_out_mutate_wy"],
                self.state.globals["loop_out_wy"],
            ),
        )


def _project(symbol: str) -> tuple[angr.Project, int]:
    location = symbol_location(SYMBOLS, symbol)
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
    return project, location.address


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for field in STATE_FIELDS:
        values[field] = claripy.BVS(f"{prefix}_{field}", 8)
    for output in ("delay_out", "predef_out", "loop_out"):
        for register in REGISTERS:
            values[f"{output}_{register}"] = _output_register(
                prefix, output, register
            )
    for index in range(2):
        for register in REGISTERS:
            values[f"mutate{index}_out_{register}"] = _output_register(
                prefix, f"mutate{index}_out", register
            )
        values[f"mutate{index}_out_mutate_wy"] = claripy.BVS(
            f"{prefix}_mutate{index}_out_mutate_wy", 8
        )
        values[f"mutate{index}_out_wy"] = claripy.BVS(
            f"{prefix}_mutate{index}_out_wy", 8
        )
    values["loop_out_mutate_wy"] = claripy.BVS(
        f"{prefix}_loop_out_mutate_wy", 8
    )
    values["loop_out_wy"] = claripy.BVS(f"{prefix}_loop_out_wy", 8)
    return values


def _output_register(
    prefix: str, output: str, register: str
) -> claripy.ast.BV:
    if register == "f":
        return claripy.Concat(
            claripy.BVS(f"{prefix}_{output}_flags", 4), claripy.BVV(0, 4)
        )
    return claripy.BVS(f"{prefix}_{output}_{register}", 8)


def _setup_globals(
    state: angr.SimState, values: dict[str, claripy.ast.BV]
) -> None:
    for field in PREDEF_FIELDS:
        state.globals[field] = values[field]
    for key, value in values.items():
        if key not in REGISTERS and key not in STATE_FIELDS:
            state.globals[key] = value
    state.globals["call_delay"] = claripy.BVV(0, 88)
    state.globals["call_predef"] = claripy.BVV(0, 112)
    state.globals["call_loop"] = claripy.BVV(0, 80)
    state.globals["call_mutate0"] = claripy.BVV(0, 80)
    state.globals["call_mutate1"] = claripy.BVV(0, 80)
    state.globals["mutate_index"] = 0


def _store_native_state(
    state: angr.SimState, values: dict[str, claripy.ast.BV]
) -> None:
    store_native_registers(state, NATIVE_STATE, values)
    for offset, field in enumerate(STATE_FIELDS, 8):
        state.memory.store(NATIVE_STATE + offset, values[field])


def _assembly_state(state: angr.SimState) -> claripy.ast.BV:
    return claripy.Concat(
        *(state.globals[field] for field in PREDEF_FIELDS),
        state.memory.load(DISABLE, 1),
        state.memory.load(H_MUTATE_WY, 1),
        state.memory.load(R_WY, 1),
    )


def _native_state(state: angr.SimState) -> claripy.ast.BV:
    return state.memory.load(NATIVE_STATE + 8, len(STATE_FIELDS))


def _initialize_assembly_memory(
    state: angr.SimState, values: dict[str, claripy.ast.BV]
) -> None:
    state.memory.store(DISABLE, values["disable"])
    state.memory.store(H_MUTATE_WY, values["mutate_wy"])
    state.memory.store(R_WY, values["wy"])


def _mutate_assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, base = _project("PredefShakeScreenVertically.MutateWY")
    location = symbol_location(SYMBOLS, "PredefShakeScreenVertically.MutateWY")
    assert linked_bytes(ROM, location, len(MUTATE_EXPECTED)) == MUTATE_EXPECTED
    project.hook(base, Sm83LoadAHighImmediate(0x96, base + 2), length=2)
    project.hook(base + 2, XorRegister("b", base + 3), length=1)
    project.hook(base + 3, Sm83StoreAHighImmediate(0x96, base + 5), length=2)
    project.hook(base + 5, Sm83StoreAHighImmediate(0x4A, base + 7), length=2)
    project.hook(base + 9, AssemblyDelaySummary(), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _initialize_assembly_memory(state, values)
    _setup_globals(state, values)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE)
    assert not manager.errored
    return [
        Endpoint(
            **assembly_registers(end),
            state=_assembly_state(end),
            calls=end.globals["call_delay"],
            continuation=claripy.BVV(0, 8),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _mutate_native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(
        "port_predef_shake_screen_vertically_mutate_wy"
    )
    delay = project.loader.find_symbol("port_delay_frames")
    assert function is not None and delay is not None
    project.hook(delay.rebased_addr, NativeDelaySummary())
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    _store_native_state(state, values)
    _setup_globals(state, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            state=_native_state(end),
            calls=end.globals["call_delay"],
            continuation=claripy.BVV(0, 8),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


def _step_assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, base = _project("PredefShakeScreenVertically.loop")
    location = symbol_location(SYMBOLS, "PredefShakeScreenVertically.loop")
    assert linked_bytes(ROM, location, len(STEP_EXPECTED)) == STEP_EXPECTED
    project.hook(base, Sm83StoreAHighImmediate(0x96, base + 2), length=2)
    project.hook(base + 2, AssemblyMutateSummary(base + 5), length=3)
    project.hook(base + 5, AssemblyMutateSummary(base + 8), length=3)
    project.hook(base + 8, Sm83DecRegister("b", base + 9), length=1)
    project.hook(base + 9, CopyRegister("a", "b", base + 10), length=1)
    project.hook(base + 10, BranchNotZero(LOOP, DONE), length=2)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _initialize_assembly_memory(state, values)
    _setup_globals(state, values)
    manager = project.factory.simulation_manager(state)
    manager.stashes["found"] = []
    while manager.active:
        manager.move(
            from_stash="active",
            to_stash="found",
            filter_func=lambda end: end.addr in {LOOP, DONE},
        )
        if manager.active:
            manager.step()
    assert not manager.errored
    return [
        Endpoint(
            **assembly_registers(end),
            state=_assembly_state(end),
            calls=claripy.Concat(
                end.globals["call_mutate0"], end.globals["call_mutate1"]
            ),
            continuation=claripy.BVV(1 if end.addr == LOOP else 0, 8),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _step_native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(
        "port_predef_shake_screen_vertically_step"
    )
    mutate = project.loader.find_symbol(
        "port_predef_shake_screen_vertically_mutate_wy"
    )
    assert function is not None and mutate is not None
    project.hook(mutate.rebased_addr, NativeMutateSummary())
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    _store_native_state(state, values)
    _setup_globals(state, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            state=_native_state(end),
            calls=claripy.Concat(
                end.globals["call_mutate0"], end.globals["call_mutate1"]
            ),
            continuation=end.regs.rax[7:0],
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


def _function_assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project, base = _project("PredefShakeScreenVertically")
    location = symbol_location(SYMBOLS, "PredefShakeScreenVertically")
    assert linked_bytes(ROM, location, len(FUNCTION_EXPECTED)) == FUNCTION_EXPECTED
    project.hook(base, AssemblyPredefSummary(base + 3), length=3)
    project.hook(base + 3, LoadAConstant(1, base + 5), length=2)
    project.hook(base + 5, Sm83StoreAImmediate(DISABLE, base + 8), length=3)
    project.hook(base + 8, XorA(base + 9), length=1)
    project.hook(base + 9, AssemblyLoopSummary(base + 21), length=12)
    project.hook(base + 21, XorA(base + 22), length=1)
    project.hook(base + 22, Sm83StoreAImmediate(DISABLE, base + 25), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.regs.sp = claripy.BVV(STACK, 16)
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    _initialize_assembly_memory(state, values)
    _setup_globals(state, values)
    returned = collect_returns(project, state, RETURN)
    assert len(returned) == 1
    end = returned[0]
    return [
        Endpoint(
            **assembly_registers(end),
            state=_assembly_state(end),
            calls=claripy.Concat(
                end.globals["call_predef"], end.globals["call_loop"]
            ),
            continuation=claripy.BVV(0, 8),
            constraints=tuple(end.solver.constraints),
        )
    ]


def _function_native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(
        "port_predef_shake_screen_vertically_private"
    )
    predef = project.loader.find_symbol("port_get_predef_registers")
    loop = project.loader.find_symbol("port_predef_shake_screen_vertically_loop")
    assert function is not None and predef is not None and loop is not None
    project.hook(predef.rebased_addr, NativePredefSummary())
    project.hook(loop.rebased_addr, NativeLoopSummary())
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    _store_native_state(state, values)
    _setup_globals(state, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            state=_native_state(end),
            calls=claripy.Concat(
                end.globals["call_predef"], end.globals["call_loop"]
            ),
            continuation=claripy.BVV(0, 8),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_predef_shake_screen_vertically_mutate_wy_pathwise_equivalence() -> None:
    values = _inputs("vertical_mutate")
    assert_pathwise_equivalent(
        _mutate_assembly(values),
        _mutate_native(values),
        (*REGISTERS, "state", "calls", "continuation"),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_predef_shake_screen_vertically_step_pathwise_equivalence() -> None:
    values = _inputs("vertical_step")
    assert_pathwise_equivalent(
        _step_assembly(values),
        _step_native(values),
        (*REGISTERS, "state", "calls", "continuation"),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_predef_shake_screen_vertically_pathwise_equivalence() -> None:
    values = _inputs("vertical_function")
    assert_pathwise_equivalent(
        _function_assembly(values),
        _function_native(values),
        (*REGISTERS, "state", "calls", "continuation"),
    )
