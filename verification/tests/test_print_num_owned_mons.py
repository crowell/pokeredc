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
from verification.harness.rom import linked_bytes, rom_window, symbol_location
from verification.tests import test_print_num_badges as common

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = common.NATIVE_STATE
NATIVE_MEMORY = common.NATIVE_MEMORY
DONE = common.DONE

W_NUM_SET_BITS = common.W_NUM_SET_BITS
W_POKEDEX_OWNED = 0xD2F7
OWNED_BYTES = 19
HRAM_START = common.HRAM_START
HRAM_SIZE = common.HRAM_SIZE
PRINT_STATE_SIZE = common.PRINT_STATE_SIZE
PRINT_WRITE_COUNT = common.PRINT_WRITE_COUNT
PRINT_TRACE_VALUES = common.PRINT_TRACE_VALUES
PRINT_TRACE_H = common.PRINT_TRACE_H
PRINT_TRACE_L = common.PRINT_TRACE_L
EXPECTED = bytes.fromhex("e521f7d20613cd7f2be1111ed1010301c35f3c")


def _inputs(prefix: str, destination: int) -> dict[str, object]:
    values: dict[str, object] = symbolic_registers(prefix)
    values["h"] = claripy.BVV(destination >> 8, 8)
    values["l"] = claripy.BVV(destination & 0xFF, 8)
    values["owned"] = claripy.BVS(f"{prefix}_owned", OWNED_BYTES * 8)
    values["num_region"] = claripy.BVS(f"{prefix}_num_region", 3 * 8)
    values["hram"] = claripy.BVS(f"{prefix}_hram", HRAM_SIZE * 8)
    values["tiles"] = claripy.BVS(f"{prefix}_tiles", 5 * 8)
    values["tail"] = [
        claripy.BVS(f"{prefix}_tail_{index}", 8)
        for index in range(PRINT_STATE_SIZE - 8)
    ]
    base_post = []
    for index in range(PRINT_STATE_SIZE):
        value = (
            claripy.Concat(
                claripy.BVS(f"{prefix}_post_flags", 4), claripy.BVV(0, 4)
            )
            if index == 1
            else claripy.BVS(f"{prefix}_post_{index}", 8)
        )
        base_post.append(value)
    posts: dict[int, list[claripy.ast.BV]] = {}
    for count in (1, 2, 3):
        post = list(base_post)
        post[PRINT_WRITE_COUNT] = claripy.BVV(count, 8)
        first = destination + 3 - count
        for index in range(count):
            address = first + index
            post[PRINT_TRACE_H + index] = claripy.BVV(address >> 8, 8)
            post[PRINT_TRACE_L + index] = claripy.BVV(address & 0xFF, 8)
        posts[count] = post
    values["posts"] = posts
    return values


def _setup(
    state: angr.SimState,
    values: dict[str, object],
    destination: int,
    memory: int = 0,
) -> None:
    state.memory.store(memory + W_POKEDEX_OWNED, values["owned"])
    state.memory.store(memory + W_NUM_SET_BITS, values["num_region"])
    state.memory.store(memory + HRAM_START, values["hram"])
    state.memory.store(memory + destination - 1, values["tiles"])
    state.globals["print_state"] = [
        *(values[name] for name in REGISTERS), *values["tail"]
    ]
    state.globals["saved_h"] = values["h"]
    state.globals["saved_l"] = values["l"]


def _memory(state: angr.SimState, destination: int, base: int = 0) -> claripy.ast.BV:
    return claripy.Concat(
        state.memory.load(base + W_POKEDEX_OWNED, OWNED_BYTES),
        state.memory.load(base + W_NUM_SET_BITS, 3),
        state.memory.load(base + HRAM_START, HRAM_SIZE),
        state.memory.load(base + destination - 1, 5),
    )


def _total_owned(owned: claripy.ast.BV) -> claripy.ast.BV:
    total = claripy.BVV(0, 8)
    for bit in range(OWNED_BYTES * 8):
        total += claripy.ZeroExt(7, owned[bit])
    return total


def _count_output(count: claripy.ast.BV) -> tuple[claripy.ast.BV, ...]:
    return (
        count,
        claripy.BVV(0xC0, 8),
        claripy.BVV(0, 8),
        count,
        claripy.BVV(0, 8),
        claripy.BVV(0, 8),
        claripy.BVV(0xD3, 8),
        claripy.BVV(0x0A, 8),
    )


def _apply_count(
    state: angr.SimState,
    count: claripy.ast.BV,
    native_address: claripy.ast.BV | int | None = None,
) -> None:
    output = _count_output(count)
    if native_address is None:
        from verification.harness.rom import sm83_flags_to_z80

        for name, value in zip(REGISTERS, output, strict=True):
            setattr(
                state.regs,
                name,
                sm83_flags_to_z80(value) if name == "f" else value,
            )
        state.globals["count_num_set_bits"] = count
    else:
        for offset, value in enumerate(output):
            state.memory.store(native_address + offset, value)
        state.memory.store(native_address + 8, count)


def _category_condition(source: claripy.ast.BV, writes: int) -> claripy.ast.Bool:
    if writes == 1:
        return source < 10
    if writes == 2:
        return claripy.And(source >= 10, source < 100)
    return source >= 100


def _apply_assembly_post(
    state: angr.SimState,
    post: list[claripy.ast.BV],
    destination: int,
    writes: int,
) -> None:
    from verification.harness.rom import sm83_flags_to_z80

    state.globals["print_state"] = list(post)
    for offset, name in enumerate(REGISTERS):
        value = post[offset]
        setattr(
            state.regs,
            name,
            sm83_flags_to_z80(value) if name == "f" else value,
        )
    state.memory.store(HRAM_START, post[8])
    for index in range(3):
        state.memory.store(HRAM_START + 1 + index, post[9 + index])
        state.memory.store(HRAM_START + 4 + index, post[12 + index])
        state.memory.store(HRAM_START + 7 + index, post[15 + index])
    first = destination + 3 - writes
    for index in range(writes):
        state.memory.store(first + index, post[PRINT_TRACE_VALUES + index])


class AssemblyCount(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        owned = self.state.memory.load(W_POKEDEX_OWNED, OWNED_BYTES)
        self.state.globals["count_call"] = claripy.Concat(
            *(assembly_registers(self.state)[name] for name in REGISTERS),
            self.state.memory.load(W_NUM_SET_BITS, 1),
            self.state.memory.load(W_POKEDEX_OWNED, 1),
            owned,
        )
        count = _total_owned(owned)
        _apply_count(self.state, count)
        self.state.memory.store(W_NUM_SET_BITS, count)
        self.jump(self.next_address)


class NativeCount(angr.SimProcedure):
    def run(
        self, state_address: claripy.ast.BV, memory_address: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        owned = self.state.memory.load(
            NATIVE_MEMORY + W_POKEDEX_OWNED, OWNED_BYTES
        )
        self.state.globals["count_call"] = claripy.Concat(
            *(native_registers(self.state, state_address)[name] for name in REGISTERS),
            self.state.memory.load(state_address + 8, 1),
            self.state.memory.load(state_address + 9, 1),
            owned,
        )
        _apply_count(self.state, _total_owned(owned), state_address)


class AssemblyPrint(angr.SimProcedure):
    def __init__(self, posts: dict[int, list[claripy.ast.BV]], destination: int) -> None:
        super().__init__()
        self.posts = posts
        self.destination = destination

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        fields = common._print_input_assembly(self.state)
        for writes in (1, 2, 3):
            child = self.state.copy()
            child.globals["print_call"] = claripy.Concat(*fields)
            condition = _category_condition(fields[18], writes)
            child.add_constraints(condition)
            _apply_assembly_post(
                child, self.posts[writes], self.destination, writes
            )
            self.successors.add_successor(
                child, DONE, claripy.BoolV(True), "Ijk_Boring"
            )


class NativePrint(angr.SimProcedure):
    def __init__(self, posts: dict[int, list[claripy.ast.BV]]) -> None:
        super().__init__()
        self.posts = posts

    def run(self, state_address: claripy.ast.BV) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        source = self.state.memory.load(state_address + 18, 1)
        for writes in (1, 2, 3):
            child = self.state.copy()
            child.globals["print_call"] = child.memory.load(
                state_address, PRINT_STATE_SIZE
            )
            condition = _category_condition(source, writes)
            child.add_constraints(condition)
            child.memory.store(
                state_address, claripy.Concat(*self.posts[writes])
            )
            return_address = child.memory.load(
                child.regs.sp, 8, endness="Iend_LE"
            )
            child.regs.sp += 8
            self.successors.add_successor(
                child, return_address, claripy.BoolV(True), "Ijk_Ret"
            )


def _assembly(values: dict[str, object], destination: int) -> list[common.Endpoint]:
    location = symbol_location(SYMBOLS, "PrintNumOwnedMons")
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
    project.hook(base, common.SaveHL(base + 1), length=1)
    project.hook(base + 1, common.LoadPair("h", "l", W_POKEDEX_OWNED, base + 4), length=3)
    project.hook(base + 4, common.LoadImmediate("b", OWNED_BYTES, base + 6), length=2)
    project.hook(base + 6, AssemblyCount(base + 9), length=3)
    project.hook(base + 9, common.RestoreHL(base + 10), length=1)
    project.hook(base + 10, common.LoadPair("d", "e", W_NUM_SET_BITS, base + 13), length=3)
    project.hook(base + 13, common.LoadPair("b", "c", 0x0103, base + 16), length=3)
    project.hook(base + 16, AssemblyPrint(values["posts"], destination), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _setup(state, values, destination)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=3)
    assert not manager.errored and len(manager.found) == 3
    return [
        common.Endpoint(
            **assembly_registers(final),
            memory=_memory(final, destination),
            fields=claripy.Concat(*final.globals["print_state"]),
            calls=claripy.Concat(
                final.globals["count_call"], final.globals["print_call"]
            ),
            constraints=tuple(final.solver.constraints),
        )
        for final in manager.found
    ]


def _native(values: dict[str, object], destination: int) -> list[common.Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_print_num_owned_mons")
    count = project.loader.find_symbol("port_count_set_bits")
    print_number = project.loader.find_symbol("port_print_number")
    assert function is not None and count is not None and print_number is not None
    project.hook(count.rebased_addr, NativeCount())
    project.hook(print_number.rebased_addr, NativePrint(values["posts"]))
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, claripy.Concat(*values["tail"]))
    _setup(state, values, destination, NATIVE_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 3
    return [
        common.Endpoint(
            **native_registers(final, NATIVE_STATE),
            memory=_memory(final, destination, NATIVE_MEMORY),
            fields=final.memory.load(NATIVE_STATE, PRINT_STATE_SIZE),
            calls=claripy.Concat(
                final.globals["count_call"], final.globals["print_call"]
            ),
            constraints=tuple(final.solver.constraints),
        )
        for final in manager.deadended
    ]


@pytest.mark.skipif(not ELF.exists(), reason="run native")
@pytest.mark.skipif(
    not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`"
)
def test_print_num_owned_mons_pathwise_equivalence() -> None:
    for destination in (0xC4B4, 0xC428):
        values = _inputs(f"print_num_owned_{destination:04x}", destination)
        assert_pathwise_equivalent(
            _assembly(values, destination),
            _native(values, destination),
            (*REGISTERS, "memory", "fields", "calls"),
        )
