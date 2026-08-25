from __future__ import annotations

from dataclasses import dataclass
from functools import cache
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
    symbol_location,
)
from verification.harness.sm83_shims import (
    Sm83CpRegister,
    Sm83DecRegister,
    Sm83LoadAAtHlIncrement,
)


ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xE000
RETURN = 0xFFFF
TABLE = 0x769F
STRING_BUFFER = 0xCF4B
COPY_LENGTH = 10
EXPECTED = bytes.fromhex("219f760e500528062ab928f918fa114bcf010a00c3b500")


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
    table: claripy.ast.BV
    output: claripy.ast.BV
    copy_call: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _capture_assembly_registers(state: angr.SimState) -> claripy.ast.BV:
    registers = assembly_registers(state)
    return claripy.Concat(*(registers[name] for name in REGISTERS))


def _copy_transition(
    state: angr.SimState,
    registers: dict[str, claripy.ast.BV],
    memory_base: claripy.ast.BV | int,
) -> None:
    source = claripy.Concat(registers["h"], registers["l"])
    destination = claripy.Concat(registers["d"], registers["e"])
    for offset in range(COPY_LENGTH):
        source_address = source + offset
        destination_address = destination + offset
        if isinstance(memory_base, int):
            state.memory.store(
                destination_address,
                state.memory.load(source_address, 1),
            )
        else:
            state.memory.store(
                memory_base + claripy.ZeroExt(48, destination_address),
                state.memory.load(
                    memory_base + claripy.ZeroExt(48, source_address), 1
                ),
            )


class AssemblyCopyData(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.globals["copy_call"] = _capture_assembly_registers(self.state)
        registers = assembly_registers(self.state)
        source = claripy.Concat(registers["h"], registers["l"])
        destination = claripy.Concat(registers["d"], registers["e"])
        _copy_transition(self.state, registers, 0)
        self.state.regs.a = 0
        self.state.regs.f = 0x40
        self.state.regs.bc = 0
        self.state.regs.hl = source + COPY_LENGTH
        self.state.regs.de = destination + COPY_LENGTH
        self.jump(RETURN)


class NativeCopyData(angr.SimProcedure):
    def run(
        self, address: claripy.ast.BV, memory: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        assert not memory.symbolic and self.state.solver.eval(memory) == NATIVE_MEMORY
        self.state.globals["copy_call"] = self.state.memory.load(address, 8)
        registers = {
            name: self.state.memory.load(address + offset, 1)
            for offset, name in enumerate(REGISTERS)
        }
        source = claripy.Concat(registers["h"], registers["l"])
        destination = claripy.Concat(registers["d"], registers["e"])
        _copy_transition(self.state, registers, memory)
        self.state.memory.store(address, claripy.BVV(0, 8))
        self.state.memory.store(address + 1, claripy.BVV(0x80, 8))
        self.state.memory.store(address + 2, claripy.BVV(0, 16))
        self.state.memory.store(address + 4, destination + COPY_LENGTH)
        self.state.memory.store(address + 6, source + COPY_LENGTH)


def _table_bytes() -> bytes:
    location = symbol_location(SYMS, "StatModTextStrings")
    return linked_bytes(ROM, location, 48)


def _inputs(prefix: str, stat_index: int) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["b"] = claripy.BVV(stat_index, 8)
    for offset in range(COPY_LENGTH):
        values[f"output_{offset}"] = claripy.BVS(f"{prefix}_output_{offset}", 8)
    return values


def _setup(
    state: angr.SimState, values: dict[str, claripy.ast.BV], native: bool
) -> None:
    memory_base = NATIVE_MEMORY if native else 0
    for offset, byte in enumerate(_table_bytes()):
        state.memory.store(memory_base + TABLE + offset, claripy.BVV(byte, 8))
    for offset in range(COPY_LENGTH):
        state.memory.store(
            memory_base + STRING_BUFFER + offset, values[f"output_{offset}"]
        )
    state.globals["copy_call"] = claripy.BVV(0, 64)


def _endpoint(state: angr.SimState, native: bool) -> Endpoint:
    memory_base = NATIVE_MEMORY if native else 0
    registers = (
        native_registers(state, NATIVE_STATE)
        if native
        else assembly_registers(state)
    )
    return Endpoint(
        **registers,
        table=state.memory.load(memory_base + TABLE, 48),
        output=state.memory.load(memory_base + STRING_BUFFER, COPY_LENGTH),
        copy_call=state.globals["copy_call"],
        constraints=tuple(state.solver.constraints),
    )


@cache
def _assembly_project() -> tuple[angr.Project, int]:
    location = symbol_location(SYMS, "PrintStatText")
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
    copy_data = symbol_location(SYMS, "CopyData").address
    project.hook(base + 5, Sm83DecRegister("b", base + 6), length=1)
    project.hook(base + 8, Sm83LoadAAtHlIncrement(base + 9), length=1)
    project.hook(base + 9, Sm83CpRegister("c", base + 10), length=1)
    project.hook(copy_data, AssemblyCopyData())
    return project, base


@cache
def _native_project() -> tuple[angr.Project, int]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_print_stat_text")
    copy_data = project.loader.find_symbol("port_copy_data")
    assert function is not None and copy_data is not None
    project.hook(copy_data.rebased_addr, NativeCopyData())
    return project, function.rebased_addr


def _assembly(
    values: dict[str, claripy.ast.BV], stat_index: int
) -> list[Endpoint]:
    project, base = _assembly_project()
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _setup(state, values, False)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    return [_endpoint(end, False) for end in collect_returns(project, state, RETURN)]


def _native(values: dict[str, claripy.ast.BV], stat_index: int) -> list[Endpoint]:
    project, function = _native_project()
    state = project.factory.call_state(function, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, values, True)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [_endpoint(manager.deadended[0], True)]


@pytest.mark.skipif(
    not ELF.exists() or not ROM.exists() or not SYMS.exists(), reason="build"
)
@pytest.mark.parametrize("stat_index", range(1, 7))
def test_print_stat_text_pathwise_equivalence(stat_index: int) -> None:
    values = _inputs(f"print_stat_{stat_index}", stat_index)
    assert_pathwise_equivalent(
        _assembly(values, stat_index),
        _native(values, stat_index),
        (*REGISTERS, "table", "output", "copy_call"),
    )
