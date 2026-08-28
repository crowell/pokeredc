from __future__ import annotations

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
from verification.tests import test_print_num_badges as common

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = common.NATIVE_STATE
NATIVE_MEMORY = common.NATIVE_MEMORY
DONE = common.DONE
HOURS = 0xDA41
MINUTES = 0xDA43
HRAM = common.HRAM_START
STATE_SIZE = common.PRINT_STATE_SIZE
COUNT = common.PRINT_WRITE_COUNT
VALUES = common.PRINT_TRACE_VALUES
TRACE_H = common.PRINT_TRACE_H
TRACE_L = common.PRINT_TRACE_L
EXPECTED = bytes.fromhex("1141da010301cd5f3c366d231143da010281c35f3c")


def _post(prefix: str, first: int, writes: int, final_hl: int | None) -> list[claripy.ast.BV]:
    post = []
    for index in range(STATE_SIZE):
        if index == 1:
            value = claripy.Concat(
                claripy.BVS(f"{prefix}_flags", 4), claripy.BVV(0, 4)
            )
        elif index == COUNT:
            value = claripy.BVV(writes, 8)
        elif final_hl is not None and index == 6:
            value = claripy.BVV(final_hl >> 8, 8)
        elif final_hl is not None and index == 7:
            value = claripy.BVV(final_hl & 0xFF, 8)
        else:
            value = claripy.BVS(f"{prefix}_{index}", 8)
        post.append(value)
    for index in range(writes):
        address = first + index
        post[TRACE_H + index] = claripy.BVV(address >> 8, 8)
        post[TRACE_L + index] = claripy.BVV(address & 0xFF, 8)
    return post


def _inputs(prefix: str, destination: int) -> dict[str, object]:
    values: dict[str, object] = symbolic_registers(prefix)
    values["h"] = claripy.BVV(destination >> 8, 8)
    values["l"] = claripy.BVV(destination & 0xFF, 8)
    values["time"] = claripy.BVS(f"{prefix}_time", 5 * 8)
    values["hram"] = claripy.BVS(f"{prefix}_hram", 10 * 8)
    values["tiles"] = claripy.BVS(f"{prefix}_tiles", 9 * 8)
    values["tail"] = [
        claripy.BVS(f"{prefix}_tail_{index}", 8)
        for index in range(STATE_SIZE - 8)
    ]
    values["first_posts"] = {
        writes: _post(
            f"{prefix}_first_{writes}", destination + 3 - writes,
            writes, destination + 3
        )
        for writes in (1, 2, 3)
    }
    values["second_post"] = _post(
        f"{prefix}_second", destination + 4, 2, None
    )
    return values


def _setup(state: angr.SimState, values: dict[str, object], destination: int, memory: int = 0) -> None:
    state.memory.store(memory + HOURS, values["time"])
    state.memory.store(memory + HRAM, values["hram"])
    state.memory.store(memory + destination - 1, values["tiles"])
    state.globals["print_state"] = [
        *(values[name] for name in REGISTERS), *values["tail"]
    ]
    state.globals["call_index"] = 0


def _memory(state: angr.SimState, destination: int, base: int = 0) -> claripy.ast.BV:
    return claripy.Concat(
        state.memory.load(base + HOURS, 5),
        state.memory.load(base + HRAM, 10),
        state.memory.load(base + destination - 1, 9),
    )


def _input_fields(state: angr.SimState, native: bool) -> list[claripy.ast.BV]:
    if native:
        return [state.memory.load(NATIVE_STATE + index, 1) for index in range(STATE_SIZE)]
    fields = list(state.globals["print_state"])
    registers = assembly_registers(state)
    fields[:8] = [registers[name] for name in REGISTERS]
    fields[8] = state.memory.load(HRAM, 1)
    source = (state.solver.eval(state.regs.d) << 8) | state.solver.eval(state.regs.e)
    for index in range(3):
        fields[9 + index] = state.memory.load(HRAM + 1 + index, 1)
        fields[12 + index] = state.memory.load(HRAM + 4 + index, 1)
        fields[15 + index] = state.memory.load(HRAM + 7 + index, 1)
        fields[18 + index] = state.memory.load(source + index, 1)
    return fields


def _condition(value: claripy.ast.BV, writes: int) -> claripy.ast.Bool:
    if writes == 1:
        return value < 10
    if writes == 2:
        return claripy.And(value >= 10, value < 100)
    return value >= 100


def _apply_assembly_post(state: angr.SimState, post: list[claripy.ast.BV], base: int, writes: int) -> None:
    state.globals["print_state"] = list(post)
    for offset, name in enumerate(REGISTERS):
        setattr(
            state.regs,
            name,
            sm83_flags_to_z80(post[offset]) if name == "f" else post[offset],
        )
    state.memory.store(HRAM, post[8])
    for index in range(3):
        state.memory.store(HRAM + 1 + index, post[9 + index])
        state.memory.store(HRAM + 4 + index, post[12 + index])
        state.memory.store(HRAM + 7 + index, post[15 + index])
    first = base + 3 - writes
    for index in range(writes):
        state.memory.store(first + index, post[VALUES + index])


class AssemblyFirst(angr.SimProcedure):
    def __init__(self, posts: dict[int, list[claripy.ast.BV]], destination: int, next_address: int) -> None:
        super().__init__()
        self.posts = posts
        self.destination = destination
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        fields = _input_fields(self.state, False)
        for writes in (1, 2, 3):
            child = self.state.copy()
            child.globals["call_0"] = claripy.Concat(*fields)
            child.globals["call_index"] = 1
            condition = _condition(fields[18], writes)
            child.add_constraints(condition)
            _apply_assembly_post(child, self.posts[writes], self.destination, writes)
            self.successors.add_successor(child, self.next_address, claripy.BoolV(True), "Ijk_Boring")


class StoreSeparator(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(self.state.regs.hl, claripy.BVV(0x6D, 8))
        self.state.regs.hl += 1
        self.jump(self.next_address)


class AssemblySecond(angr.SimProcedure):
    def __init__(self, post: list[claripy.ast.BV], destination: int) -> None:
        super().__init__()
        self.post = post
        self.destination = destination

    def run(self) -> None:  # type: ignore[override]
        fields = _input_fields(self.state, False)
        self.state.globals["call_1"] = claripy.Concat(*fields)
        _apply_assembly_post(self.state, self.post, self.destination + 3, 2)
        self.jump(DONE)


class NativePrint(angr.SimProcedure):
    def __init__(self, first: dict[int, list[claripy.ast.BV]], second: list[claripy.ast.BV]) -> None:
        super().__init__()
        self.first = first
        self.second = second

    def run(self, state_address: claripy.ast.BV) -> None:  # type: ignore[override]
        index = self.state.globals["call_index"]
        if index == 1:
            self.state.globals["call_1"] = self.state.memory.load(state_address, STATE_SIZE)
            self.state.memory.store(state_address, claripy.Concat(*self.second))
            self.state.globals["call_index"] = 2
            return
        self.inhibit_autoret = True
        source = self.state.memory.load(state_address + 18, 1)
        for writes in (1, 2, 3):
            child = self.state.copy()
            child.globals["call_0"] = child.memory.load(state_address, STATE_SIZE)
            child.globals["call_index"] = 1
            condition = _condition(source, writes)
            child.add_constraints(condition)
            child.memory.store(state_address, claripy.Concat(*self.first[writes]))
            return_address = child.memory.load(child.regs.sp, 8, endness="Iend_LE")
            child.regs.sp += 8
            self.successors.add_successor(child, return_address, claripy.BoolV(True), "Ijk_Ret")


def _assembly(values: dict[str, object], destination: int) -> list[common.Endpoint]:
    location = symbol_location(SYMBOLS, "PrintPlayTime")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0, "entry_point": location.address},
    )
    base = location.address
    project.hook(base, common.LoadPair("d", "e", HOURS, base + 3), length=3)
    project.hook(base + 3, common.LoadPair("b", "c", 0x0103, base + 6), length=3)
    project.hook(base + 6, AssemblyFirst(values["first_posts"], destination, base + 9), length=3)
    project.hook(base + 9, StoreSeparator(base + 13), length=4)
    project.hook(base + 13, common.LoadPair("d", "e", MINUTES, base + 16), length=3)
    project.hook(base + 16, common.LoadPair("b", "c", 0x8102, base + 19), length=3)
    project.hook(base + 19, AssemblySecond(values["second_post"], destination), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _setup(state, values, destination)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=3)
    assert not manager.errored and len(manager.found) == 3
    return [common.Endpoint(**assembly_registers(x), memory=_memory(x, destination), fields=claripy.Concat(*x.globals["print_state"]), calls=claripy.Concat(x.globals["call_0"], x.globals["call_1"]), constraints=tuple(x.solver.constraints)) for x in manager.found]


def _native(values: dict[str, object], destination: int) -> list[common.Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_print_play_time")
    print_number = project.loader.find_symbol("port_print_number")
    assert function is not None and print_number is not None
    project.hook(print_number.rebased_addr, NativePrint(values["first_posts"], values["second_post"]))
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, claripy.Concat(*values["tail"]))
    _setup(state, values, destination, NATIVE_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 3
    return [common.Endpoint(**native_registers(x, NATIVE_STATE), memory=_memory(x, destination, NATIVE_MEMORY), fields=x.memory.load(NATIVE_STATE, STATE_SIZE), calls=claripy.Concat(x.globals["call_0"], x.globals["call_1"]), constraints=tuple(x.solver.constraints)) for x in manager.deadended]


@pytest.mark.skipif(not ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_print_play_time_pathwise_equivalence() -> None:
    for destination in (0xC4D9, 0xC44D):
        values = _inputs(f"print_play_time_{destination:04x}", destination)
        assert_pathwise_equivalent(
            _assembly(values, destination), _native(values, destination),
            (*REGISTERS, "memory", "fields", "calls"),
        )
