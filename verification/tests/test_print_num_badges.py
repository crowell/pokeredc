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

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF

W_NUM_SET_BITS = 0xD11E
W_OBTAINED_BADGES = 0xD356
HRAM_START = 0xFF95
HRAM_SIZE = 10
PRINT_STATE_SIZE = 52
PRINT_WRITE_COUNT = 30
PRINT_TRACE_VALUES = 31
PRINT_TRACE_H = 38
PRINT_TRACE_L = 45
EXPECTED = bytes.fromhex("e52156d30601cd7f2be1111ed1010201c35f3c")


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


def _inputs(prefix: str, destination: int) -> dict[str, object]:
    values: dict[str, object] = symbolic_registers(prefix)
    values["h"] = claripy.BVV(destination >> 8, 8)
    values["l"] = claripy.BVV(destination & 0xFF, 8)
    values["badge"] = claripy.BVS(f"{prefix}_badge", 8)
    values["num_region"] = claripy.BVS(f"{prefix}_num_region", 3 * 8)
    values["hram"] = claripy.BVS(f"{prefix}_hram", HRAM_SIZE * 8)
    values["tiles"] = claripy.BVS(f"{prefix}_tiles", 4 * 8)
    values["tail"] = [
        claripy.BVS(f"{prefix}_tail_{index}", 8)
        for index in range(PRINT_STATE_SIZE - 8)
    ]
    post = []
    for index in range(PRINT_STATE_SIZE):
        if index == 1:
            value = claripy.Concat(
                claripy.BVS(f"{prefix}_post_flags", 4), claripy.BVV(0, 4)
            )
        elif index == PRINT_WRITE_COUNT:
            value = claripy.BVV(1, 8)
        elif index == PRINT_TRACE_H:
            value = claripy.BVV((destination + 1) >> 8, 8)
        elif index == PRINT_TRACE_L:
            value = claripy.BVV((destination + 1) & 0xFF, 8)
        else:
            value = claripy.BVS(f"{prefix}_post_{index}", 8)
        post.append(value)
    values["post"] = post
    return values


def _popcount(value: claripy.ast.BV) -> claripy.ast.BV:
    total = claripy.BVV(0, 8)
    for bit in range(8):
        total += claripy.ZeroExt(7, value[bit])
    return total


def _setup(
    state: angr.SimState,
    values: dict[str, object],
    destination: int,
    memory: int = 0,
) -> None:
    state.memory.store(memory + W_OBTAINED_BADGES, values["badge"])
    state.memory.store(memory + W_NUM_SET_BITS, values["num_region"])
    state.memory.store(memory + HRAM_START, values["hram"])
    state.memory.store(memory + destination - 1, values["tiles"])
    registers = [values[name] for name in REGISTERS]
    state.globals["print_state"] = [*registers, *values["tail"]]
    state.globals["saved_h"] = values["h"]
    state.globals["saved_l"] = values["l"]


def _memory(state: angr.SimState, destination: int, base: int = 0) -> claripy.ast.BV:
    return claripy.Concat(
        state.memory.load(base + W_OBTAINED_BADGES, 1),
        state.memory.load(base + W_NUM_SET_BITS, 3),
        state.memory.load(base + HRAM_START, HRAM_SIZE),
        state.memory.load(base + destination - 1, 4),
    )


def _record_count_call(
    state: angr.SimState,
    registers: dict[str, claripy.ast.BV],
    num_set_bits: claripy.ast.BV,
    fetched: claripy.ast.BV,
    badge: claripy.ast.BV,
) -> None:
    state.globals["count_call"] = claripy.Concat(
        *(registers[name] for name in REGISTERS),
        num_set_bits,
        fetched,
        badge,
    )


def _apply_count(
    state: angr.SimState,
    badge: claripy.ast.BV,
    native_address: claripy.ast.BV | int | None = None,
) -> None:
    count = _popcount(badge)
    output = (
        count,
        claripy.BVV(0xC0, 8),
        claripy.BVV(0, 8),
        count,
        claripy.BVV(0, 8),
        claripy.BVV(0, 8),
        claripy.BVV(0xD3, 8),
        claripy.BVV(0x57, 8),
    )
    if native_address is None:
        for name, value in zip(REGISTERS, output, strict=True):
            setattr(
                state.regs,
                name,
                sm83_flags_to_z80(value) if name == "f" else value,
            )
        state.globals["count_num_set_bits"] = count
        state.globals["count_fetched"] = badge
    else:
        for offset, value in enumerate(output):
            state.memory.store(native_address + offset, value)
        state.memory.store(native_address + 8, count)
        state.memory.store(native_address + 9, badge)


def _print_input_assembly(state: angr.SimState) -> list[claripy.ast.BV]:
    fields = list(state.globals["print_state"])
    registers = assembly_registers(state)
    fields[:8] = [registers[name] for name in REGISTERS]
    fields[8] = state.memory.load(HRAM_START, 1)
    for index in range(3):
        fields[9 + index] = state.memory.load(HRAM_START + 1 + index, 1)
        fields[12 + index] = state.memory.load(HRAM_START + 4 + index, 1)
        fields[15 + index] = state.memory.load(HRAM_START + 7 + index, 1)
        fields[18 + index] = state.memory.load(W_NUM_SET_BITS + index, 1)
    return fields


def _apply_print_post(
    state: angr.SimState,
    post: list[claripy.ast.BV],
    destination: int,
    native: bool,
) -> None:
    memory = NATIVE_MEMORY if native else 0
    if native:
        state.memory.store(NATIVE_STATE, claripy.Concat(*post))
    else:
        state.globals["print_state"] = list(post)
        for offset, name in enumerate(REGISTERS):
            value = post[offset]
            setattr(
                state.regs,
                name,
                sm83_flags_to_z80(value) if name == "f" else value,
            )
    state.memory.store(memory + HRAM_START, post[8])
    for index in range(3):
        state.memory.store(memory + HRAM_START + 1 + index, post[9 + index])
        state.memory.store(memory + HRAM_START + 4 + index, post[12 + index])
        state.memory.store(memory + HRAM_START + 7 + index, post[15 + index])
    state.memory.store(memory + destination + 1, post[PRINT_TRACE_VALUES])


class SaveHL(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["saved_h"] = self.state.regs.h
        self.state.globals["saved_l"] = self.state.regs.l
        self.jump(self.next_address)


class RestoreHL(SaveHL):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = self.state.globals["saved_h"]
        self.state.regs.l = self.state.globals["saved_l"]
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


class LoadImmediate(angr.SimProcedure):
    def __init__(self, register: str, value: int, next_address: int) -> None:
        super().__init__()
        self.register = register
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.register, claripy.BVV(self.value, 8))
        self.jump(self.next_address)


class AssemblyCount(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        badge = self.state.memory.load(W_OBTAINED_BADGES, 1)
        _record_count_call(
            self.state,
            assembly_registers(self.state),
            self.state.memory.load(W_NUM_SET_BITS, 1),
            badge,
            badge,
        )
        _apply_count(self.state, badge)
        self.state.memory.store(
            W_NUM_SET_BITS, self.state.globals["count_num_set_bits"]
        )
        self.jump(self.next_address)


class AssemblyPrint(angr.SimProcedure):
    def __init__(self, post: list[claripy.ast.BV], destination: int) -> None:
        super().__init__()
        self.post = post
        self.destination = destination

    def run(self) -> None:  # type: ignore[override]
        fields = _print_input_assembly(self.state)
        self.state.globals["print_call"] = claripy.Concat(*fields)
        _apply_print_post(self.state, self.post, self.destination, False)
        self.jump(DONE)


class NativeCount(angr.SimProcedure):
    def run(
        self, state_address: claripy.ast.BV, memory_address: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        badge = self.state.memory.load(NATIVE_MEMORY + W_OBTAINED_BADGES, 1)
        _record_count_call(
            self.state,
            native_registers(self.state, state_address),
            self.state.memory.load(state_address + 8, 1),
            self.state.memory.load(state_address + 9, 1),
            badge,
        )
        _apply_count(self.state, badge, state_address)


class NativePrint(angr.SimProcedure):
    def __init__(self, post: list[claripy.ast.BV]) -> None:
        super().__init__()
        self.post = post

    def run(self, state_address: claripy.ast.BV) -> None:  # type: ignore[override]
        self.state.globals["print_call"] = self.state.memory.load(
            state_address, PRINT_STATE_SIZE
        )
        self.state.memory.store(state_address, claripy.Concat(*self.post))


def _assembly(
    values: dict[str, object], destination: int
) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "PrintNumBadges")
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
    project.hook(base, SaveHL(base + 1), length=1)
    project.hook(base + 1, LoadPair("h", "l", W_OBTAINED_BADGES, base + 4), length=3)
    project.hook(base + 4, LoadImmediate("b", 1, base + 6), length=2)
    project.hook(base + 6, AssemblyCount(base + 9), length=3)
    project.hook(base + 9, RestoreHL(base + 10), length=1)
    project.hook(base + 10, LoadPair("d", "e", W_NUM_SET_BITS, base + 13), length=3)
    project.hook(base + 13, LoadPair("b", "c", 0x0102, base + 16), length=3)
    project.hook(base + 16, AssemblyPrint(values["post"], destination), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _setup(state, values, destination)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE)
    assert not manager.errored and len(manager.found) == 1
    final = manager.found[0]
    return [
        Endpoint(
            **assembly_registers(final),
            memory=_memory(final, destination),
            fields=claripy.Concat(*final.globals["print_state"]),
            calls=claripy.Concat(
                final.globals["count_call"], final.globals["print_call"]
            ),
            constraints=tuple(final.solver.constraints),
        )
    ]


def _native(values: dict[str, object], destination: int) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_print_num_badges")
    count = project.loader.find_symbol("port_count_set_bits")
    print_number = project.loader.find_symbol("port_print_number")
    assert function is not None and count is not None and print_number is not None
    project.hook(count.rebased_addr, NativeCount())
    project.hook(print_number.rebased_addr, NativePrint(values["post"]))
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, claripy.Concat(*values["tail"]))
    _setup(state, values, destination, NATIVE_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    final = manager.deadended[0]
    return [
        Endpoint(
            **native_registers(final, NATIVE_STATE),
            memory=_memory(final, destination, NATIVE_MEMORY),
            fields=final.memory.load(NATIVE_STATE, PRINT_STATE_SIZE),
            calls=claripy.Concat(
                final.globals["count_call"], final.globals["print_call"]
            ),
            constraints=tuple(final.solver.constraints),
        )
    ]


@pytest.mark.skipif(not ELF.exists(), reason="run native")
@pytest.mark.skipif(
    not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`"
)
def test_print_num_badges_pathwise_equivalence() -> None:
    for destination in (0xC48D, 0xC401):
        values = _inputs(f"print_num_badges_{destination:04x}", destination)
        assert_pathwise_equivalent(
            _assembly(values, destination),
            _native(values, destination),
            (*REGISTERS, "memory", "fields", "calls"),
        )
