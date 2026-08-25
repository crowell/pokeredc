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
    z80_flags_to_sm83,
)
from verification.harness.sm83_shims import (
    Sm83AddImmediate,
    Sm83AddRegister,
    Sm83CpImmediate,
    Sm83IncRegister,
    Sm83SubImmediate,
)

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
    "e5d5c5fa1ed1f5fec9300dc605ea1ed1213e300102001806213c30010200116dcd"
    "cdb500fa1ed1d6c806f6d60a38030418f9c60af5781213f106f68012133e5012f1"
    "ea1ed1c1d1e1c9"
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
    named: claripy.ast.BV
    output: claripy.ast.BV
    saved: claripy.ast.BV
    call: claripy.ast.BV
    result: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _concat(registers: dict[str, claripy.ast.BV]) -> claripy.ast.BV:
    return claripy.Concat(*(registers[name] for name in REGISTERS))


class LoadNamed(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals["named"]
        self.jump(self.continuation)


class StoreNamed(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["named"] = self.state.regs.a
        self.jump(self.continuation)


class CopyDataSummary(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["call"] = _concat(assembly_registers(self.state))
        de = claripy.Concat(self.state.regs.d, self.state.regs.e)
        self.state.memory.store(de, claripy.Concat(*self.state.globals["prefix"]))
        hl = claripy.Concat(self.state.regs.h, self.state.regs.l) + 2
        de += 2
        self.state.regs.a = 0
        self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0x80, 8))
        self.state.regs.b = 0
        self.state.regs.c = 0
        self.state.regs.d = de[15:8]
        self.state.regs.e = de[7:0]
        self.state.regs.h = hl[15:8]
        self.state.regs.l = hl[7:0]
        self.jump(self.continuation)


class NativeCopyDataSummary(angr.SimProcedure):
    def run(
        self, registers: claripy.ast.BV, memory: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        self.state.globals["call"] = self.state.memory.load(registers, 8)
        de = self.state.memory.load(registers + 4, 2)
        address = memory + claripy.ZeroExt(48, de)
        self.state.memory.store(address, claripy.Concat(*self.state.globals["prefix"]))
        hl = self.state.memory.load(registers + 6, 2) + 2
        de += 2
        self.state.memory.store(registers, claripy.BVV(0x80, 16))
        self.state.memory.store(registers + 2, claripy.BVV(0, 16))
        self.state.memory.store(registers + 4, de)
        self.state.memory.store(registers + 6, hl)


def _saved_from_stack(state: angr.SimState) -> claripy.ast.BV:
    sp = state.regs.sp
    return claripy.Concat(
        state.memory.load(sp + 1, 1),
        z80_flags_to_sm83(state.memory.load(sp, 1)),
        state.memory.load(sp + 3, 1),
        state.memory.load(sp + 2, 1),
        state.memory.load(sp + 5, 1),
        state.memory.load(sp + 4, 1),
        state.memory.load(sp + 7, 1),
        state.memory.load(sp + 6, 1),
    )


def _endpoint(
    state: angr.SimState, *, native: bool, result: claripy.ast.BV | None = None
) -> Endpoint:
    registers = native_registers(state, NATIVE_STATE) if native else assembly_registers(state)
    memory_base = NATIVE_MEMORY if native else 0
    named = state.memory.load(NATIVE_STATE + 8, 1) if native else state.globals["named"]
    saved = state.memory.load(NATIVE_STATE + 9, 8) if native else _saved_from_stack(state)
    return Endpoint(
        **registers,
        named=named,
        output=state.memory.load(memory_base + NAME_BUFFER, 5),
        saved=saved,
        call=state.globals.get("call", claripy.BVV(0, 64)),
        result=result if result is not None else claripy.BVV(0, 8),
        constraints=tuple(state.solver.constraints),
    )


def _inputs(tag: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(tag)
    values["named"] = claripy.BVS(f"{tag}_named", 8)
    values["prefix0"] = claripy.BVS(f"{tag}_prefix0", 8)
    values["prefix1"] = claripy.BVS(f"{tag}_prefix1", 8)
    for index in range(5):
        values[f"initial{index}"] = claripy.BVS(f"{tag}_initial{index}", 8)
    return values


def _store_initial_buffer(
    state: angr.SimState, values: dict[str, claripy.ast.BV], base: int
) -> None:
    for index in range(5):
        state.memory.store(base + NAME_BUFFER + index, values[f"initial{index}"])


def _assembly_begin(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "GetMachineName")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    base = location.address
    loop = symbol_location(SYMBOLS, "GetMachineName.FirstDigit").address
    project.hook(base + 3, LoadNamed(base + 6), length=3)
    project.hook(base + 7, Sm83CpImmediate(0xC9, base + 9), length=2)
    project.hook(base + 11, Sm83AddImmediate(5, base + 13), length=2)
    project.hook(base + 13, StoreNamed(base + 16), length=3)
    project.hook(base + 33, CopyDataSummary(base + 36), length=3)
    project.hook(base + 36, LoadNamed(base + 39), length=3)
    project.hook(base + 39, Sm83SubImmediate(0xC8, base + 41), length=2)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.globals["named"] = values["named"]
    state.globals["prefix"] = (values["prefix0"], values["prefix1"])
    state.globals["call"] = claripy.BVV(0, 64)
    _store_initial_buffer(state, values, 0)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    manager = project.factory.simulation_manager(state)
    manager.explore(find=loop, num_find=2)
    assert not manager.errored
    return [_endpoint(end, native=False) for end in manager.found]


def _native_begin(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_get_machine_name_begin")
    copy = project.loader.find_symbol("port_copy_data")
    assert function is not None and copy is not None
    project.hook(copy.rebased_addr, NativeCopyDataSummary())
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, values["named"])
    state.globals["prefix"] = (values["prefix0"], values["prefix1"])
    state.globals["call"] = claripy.BVV(0, 64)
    _store_initial_buffer(state, values, NATIVE_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [_endpoint(end, native=True) for end in manager.deadended]


def _assembly_step(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "GetMachineName")
    loop = symbol_location(SYMBOLS, "GetMachineName.FirstDigit").address
    finish = symbol_location(SYMBOLS, "GetMachineName.SecondDigit").address
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": loop},
    )
    project.hook(loop, Sm83SubImmediate(10, loop + 2), length=2)
    project.hook(loop + 4, Sm83IncRegister("b", loop + 5), length=1)
    state = project.factory.blank_state(addr=loop)
    set_assembly_registers(state, values)
    manager = project.factory.simulation_manager(state)
    manager.step()
    manager.explore(
        find=lambda candidate: candidate.addr in (loop, finish), num_find=2
    )
    assert not manager.errored
    return [
        Endpoint(
            **assembly_registers(end), named=claripy.BVV(0, 8),
            output=claripy.BVV(0, 40), saved=claripy.BVV(0, 64),
            call=claripy.BVV(0, 64), result=claripy.BVV(int(end.addr == finish), 8),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native_step(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_get_machine_name_step")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE), named=claripy.BVV(0, 8),
            output=claripy.BVV(0, 40), saved=claripy.BVV(0, 64),
            call=claripy.BVV(0, 64), result=end.regs.rax[7:0],
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


def _store_finish_stack(state: angr.SimState, saved: dict[str, claripy.ast.BV]) -> None:
    pairs = (
        claripy.Concat(saved["a"], sm83_flags_to_z80(saved["f"])),
        claripy.Concat(saved["b"], saved["c"]),
        claripy.Concat(saved["d"], saved["e"]),
        claripy.Concat(saved["h"], saved["l"]),
    )
    for offset, pair in enumerate(pairs):
        state.memory.store(STACK + 2 * offset, pair, endness="Iend_LE")
    state.memory.store(STACK + 8, claripy.BVV(RETURN, 16), endness="Iend_LE")


def _assembly_finish(
    values: dict[str, claripy.ast.BV], saved: dict[str, claripy.ast.BV]
) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "GetMachineName")
    finish = symbol_location(SYMBOLS, "GetMachineName.SecondDigit").address
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": finish},
    )
    base = location.address
    project.hook(base + 50, Sm83AddImmediate(10, base + 52), length=2)
    project.hook(base + 59, Sm83AddRegister("b", base + 60), length=1)
    project.hook(base + 66, StoreNamed(base + 69), length=3)
    state = project.factory.blank_state(addr=finish)
    set_assembly_registers(state, values)
    state.regs.d = 0xCD
    state.regs.e = 0x6F
    state.globals["named"] = values["named"]
    _store_initial_buffer(state, values, 0)
    state.regs.sp = STACK
    _store_finish_stack(state, saved)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN)
    assert not manager.errored
    return [_endpoint(end, native=False) for end in manager.found]


def _native_finish(
    values: dict[str, claripy.ast.BV], saved: dict[str, claripy.ast.BV]
) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_get_machine_name_finish")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 4, claripy.BVV(0xCD6F, 16))
    state.memory.store(NATIVE_STATE + 8, values["named"])
    state.memory.store(NATIVE_STATE + 9, _concat(saved))
    _store_initial_buffer(state, values, NATIVE_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [_endpoint(end, native=True) for end in manager.deadended]


def _assert_complete(endpoints: list[Endpoint]) -> None:
    domains = [claripy.And(*end.constraints) for end in endpoints]
    solver = claripy.Solver()
    solver.add(claripy.Not(claripy.Or(*domains)))
    assert not solver.satisfiable()


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
def test_get_machine_name_pathwise_equivalence() -> None:
    begin = _inputs("get_machine_name_begin")
    assembly_begin = _assembly_begin(begin)
    native_begin = _native_begin(begin)
    assert_pathwise_equivalent(
        assembly_begin, native_begin,
        (*REGISTERS, "named", "output", "saved", "call"),
    )
    _assert_complete(assembly_begin)
    _assert_complete(native_begin)

    step = symbolic_registers("get_machine_name_step")
    assembly_step = _assembly_step(step)
    native_step = _native_step(step)
    assert_pathwise_equivalent(assembly_step, native_step, (*REGISTERS, "result"))
    _assert_complete(assembly_step)
    _assert_complete(native_step)

    finish = _inputs("get_machine_name_finish")
    saved = symbolic_registers("get_machine_name_saved")
    assert_pathwise_equivalent(
        _assembly_finish(finish, saved), _native_finish(finish, saved),
        (*REGISTERS, "named", "output"),
    )
