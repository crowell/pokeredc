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
from verification.harness.sm83_shims import Sm83DecRegister

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD800
RETURN = 0xFFFF
NAME_BUFFER = 0xCD6D
EXPECTED = bytes.fromhex(
    "e5f0b8f53e07e0b8ea0020fa1ed13d211e420e0a0600cd873a116dcdd5010a00"
    "cdb5002177cd3650d1f1e0b8ea0020e1c9"
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
    globals: claripy.ast.BV
    output: claripy.ast.BV
    add_call: claripy.ast.BV
    copy_call: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _register_concat(state: angr.SimState) -> claripy.ast.BV:
    registers = assembly_registers(state)
    return claripy.Concat(*(registers[name] for name in REGISTERS))


class LoadGlobal(angr.SimProcedure):
    def __init__(self, field: str, continuation: int) -> None:
        super().__init__()
        self.field = field
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals[self.field]
        self.jump(self.continuation)


class StoreGlobal(angr.SimProcedure):
    def __init__(self, field: str, continuation: int) -> None:
        super().__init__()
        self.field = field
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.globals[self.field] = self.state.regs.a
        self.jump(self.continuation)


class AddNTimesSummary(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["add_call"] = _register_concat(self.state)
        a = self.state.regs.a
        bc = claripy.Concat(self.state.regs.b, self.state.regs.c)
        hl = claripy.Concat(self.state.regs.h, self.state.regs.l)
        result = hl + claripy.ZeroExt(8, a) * bc
        last_sum = hl + claripy.ZeroExt(8, a - 1) * bc
        last_wide = claripy.ZeroExt(1, last_sum) + claripy.ZeroExt(1, bc)
        canonical_f = claripy.If(
            a == 0,
            claripy.BVV(0xA0, 8),
            claripy.BVV(0xC0, 8) | claripy.If(
                last_wide[16] == 1,
                claripy.BVV(0x10, 8),
                claripy.BVV(0, 8),
            ),
        )
        self.state.regs.a = 0
        self.state.regs.h = result[15:8]
        self.state.regs.l = result[7:0]
        self.state.regs.f = sm83_flags_to_z80(canonical_f)
        self.jump(self.continuation)


class CopyDataSummary(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["copy_call"] = _register_concat(self.state)
        hl = claripy.Concat(self.state.regs.h, self.state.regs.l) + 10
        de = claripy.Concat(self.state.regs.d, self.state.regs.e)
        for offset, value in enumerate(self.state.globals["copied"]):
            self.state.memory.store(de + offset, value)
        de += 10
        self.state.regs.a = 0
        self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0x80, 8))
        self.state.regs.b = 0
        self.state.regs.c = 0
        self.state.regs.h = hl[15:8]
        self.state.regs.l = hl[7:0]
        self.state.regs.d = de[15:8]
        self.state.regs.e = de[7:0]
        self.jump(self.continuation)


class NativeAddNTimesSummary(angr.SimProcedure):
    def run(self, registers: claripy.ast.BV) -> None:  # type: ignore[override]
        self.state.globals["add_call"] = self.state.memory.load(registers, 8)
        a = self.state.memory.load(registers, 1)
        bc = self.state.memory.load(registers + 2, 2)
        hl = self.state.memory.load(registers + 6, 2)
        result = hl + claripy.ZeroExt(8, a) * bc
        last_sum = hl + claripy.ZeroExt(8, a - 1) * bc
        last_wide = claripy.ZeroExt(1, last_sum) + claripy.ZeroExt(1, bc)
        flags = claripy.If(
            a == 0,
            claripy.BVV(0xA0, 8),
            claripy.BVV(0xC0, 8) | claripy.If(
                last_wide[16] == 1,
                claripy.BVV(0x10, 8),
                claripy.BVV(0, 8),
            ),
        )
        self.state.memory.store(registers, claripy.BVV(0, 8))
        self.state.memory.store(registers + 1, flags)
        self.state.memory.store(registers + 6, result)


class NativeCopyDataSummary(angr.SimProcedure):
    def run(
        self, registers: claripy.ast.BV, memory: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        self.state.globals["copy_call"] = self.state.memory.load(registers, 8)
        hl = self.state.memory.load(registers + 6, 2) + 10
        de = self.state.memory.load(registers + 4, 2)
        for offset, value in enumerate(self.state.globals["copied"]):
            self.state.memory.store(memory + claripy.ZeroExt(48, de) + offset, value)
        de += 10
        self.state.memory.store(registers, claripy.BVV(0x80, 16))
        self.state.memory.store(registers + 2, claripy.BVV(0, 16))
        self.state.memory.store(registers + 4, de)
        self.state.memory.store(registers + 6, hl)


def _inputs() -> dict[str, claripy.ast.BV | tuple[claripy.ast.BV, ...]]:
    values: dict[str, claripy.ast.BV | tuple[claripy.ast.BV, ...]] = symbolic_registers(
        "get_mon_name"
    )
    values["named"] = claripy.BVS("get_mon_name_named", 8)
    values["loaded"] = claripy.BVS("get_mon_name_loaded", 8)
    values["rom"] = claripy.BVS("get_mon_name_rom", 8)
    values["copied"] = tuple(
        claripy.BVS(f"get_mon_name_copied_{index}", 8) for index in range(10)
    )
    return values


def _assembly(values: dict[str, object]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "GetMonName")
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
    project.hook(base + 1, LoadGlobal("loaded", base + 3), length=2)
    project.hook(base + 6, StoreGlobal("loaded", base + 8), length=2)
    project.hook(base + 8, StoreGlobal("rom", base + 11), length=3)
    project.hook(base + 11, LoadGlobal("named", base + 14), length=3)
    project.hook(base + 14, Sm83DecRegister("a", base + 15), length=1)
    project.hook(base + 22, AddNTimesSummary(base + 25), length=3)
    project.hook(base + 32, CopyDataSummary(base + 35), length=3)
    project.hook(base + 42, StoreGlobal("loaded", base + 44), length=2)
    project.hook(base + 44, StoreGlobal("rom", base + 47), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)  # type: ignore[arg-type]
    state.globals["named"] = values["named"]
    state.globals["loaded"] = values["loaded"]
    state.globals["rom"] = values["rom"]
    state.globals["copied"] = values["copied"]
    state.globals["add_call"] = claripy.BVV(0, 64)
    state.globals["copy_call"] = claripy.BVV(0, 64)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    return [
        Endpoint(
            **assembly_registers(end),
            globals=claripy.Concat(
                end.globals["named"], end.globals["loaded"], end.globals["rom"]
            ),
            output=end.memory.load(NAME_BUFFER, 11),
            add_call=end.globals["add_call"],
            copy_call=end.globals["copy_call"],
            constraints=tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, RETURN)
    ]


def _native(values: dict[str, object]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_get_mon_name")
    add = project.loader.find_symbol("port_add_n_times")
    copy = project.loader.find_symbol("port_copy_data")
    assert function is not None and add is not None and copy is not None
    project.hook(add.rebased_addr, NativeAddNTimesSummary())
    project.hook(copy.rebased_addr, NativeCopyDataSummary())
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)  # type: ignore[arg-type]
    state.memory.store(NATIVE_STATE + 8, values["named"])
    state.memory.store(NATIVE_STATE + 9, values["loaded"])
    state.memory.store(NATIVE_STATE + 10, values["rom"])
    state.globals["copied"] = values["copied"]
    state.globals["add_call"] = claripy.BVV(0, 64)
    state.globals["copy_call"] = claripy.BVV(0, 64)
    manager = project.factory.simulation_manager(state)
    manager.run()
    if manager.errored:
        raise manager.errored[0].error
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            globals=end.memory.load(NATIVE_STATE + 8, 3),
            output=end.memory.load(NATIVE_MEMORY + NAME_BUFFER, 11),
            add_call=end.globals["add_call"],
            copy_call=end.globals["copy_call"],
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_get_mon_name_pathwise_equivalence() -> None:
    values = _inputs()
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "globals", "output", "add_call", "copy_call"),
    )
