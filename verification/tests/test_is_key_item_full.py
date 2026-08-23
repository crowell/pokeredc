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
from verification.harness.sm83_shims import (
    Sm83CpImmediate,
    Sm83LoadAImmediate,
    Sm83StoreAImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF
MARKER = 0x1234
W_IS_KEY_ITEM = 0xD124
W_CUR_ITEM = 0xCF91
W_BUFFER = 0xCEE9
KEY_ITEM_FLAGS = 0x6799
EXPECTED = bytes.fromhex(
    "3e01ea24d1fa91cffec4301df521996711e9ce010f00cdb500f13d4f21e9ce"
    "06023e10cd6d3e79a7c0fa91cfcd4030d8afea24d1c9"
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
    is_key_item: claripy.ast.BV
    buffer: claripy.ast.BV
    marker: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _comparison_flags(left: claripy.ast.BV, right: int) -> claripy.ast.BV:
    return claripy.If(left == right, claripy.BVV(0xC0, 8), claripy.BVV(0, 8)) | claripy.If(
        (left & 0x0F) < (right & 0x0F),
        claripy.BVV(0x20, 8),
        claripy.BVV(0, 8),
    ) | claripy.If(left < right, claripy.BVV(0x10, 8), claripy.BVV(0x40, 8))


class CopyDataSummary(angr.SimProcedure):
    def __init__(self, next_address: int, native: bool = False):
        super().__init__()
        self.next_address = next_address
        self.native = native

    def run(self, state: claripy.ast.BV | None = None, memory: claripy.ast.BV | None = None) -> None:  # type: ignore[override]
        if self.native:
            if state is None:
                state = self.state.regs.rdi
            if memory is None:
                memory = self.state.regs.rsi
            for index in range(15):
                byte = self.state.memory.load(memory + KEY_ITEM_FLAGS + index, 1)
                self.state.memory.store(memory + W_BUFFER + index, byte)
            self.state.memory.store(state, claripy.BVV(0, 8))
            self.state.memory.store(state + 1, claripy.BVV(0x80, 8))
            self.state.memory.store(state + 2, claripy.BVV(0, 16))
            self.state.memory.store(state + 4, claripy.BVV(0xCEF8, 16))
            self.state.memory.store(state + 6, claripy.BVV(0x67A8, 16))
            return
        for index in range(15):
            byte = self.state.memory.load(KEY_ITEM_FLAGS + index, 1)
            self.state.memory.store(W_BUFFER + index, byte)
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0x80, 8))
        self.state.regs.bc = claripy.BVV(0, 16)
        self.state.regs.de = claripy.BVV(0xCEF8, 16)
        self.state.regs.hl = claripy.BVV(0x67A8, 16)
        self.jump(self.next_address)


class SaveAf(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["saved_a"] = self.state.regs.a
        self.state.globals["saved_f"] = self.state.regs.f
        self.jump(self.next_address)


class RestoreAf(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals["saved_a"]
        self.state.regs.f = self.state.globals["saved_f"]
        self.jump(self.next_address)


class DecA(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        old = self.state.regs.a
        result = old - 1
        carry = self.state.regs.f & 1
        flags = claripy.If(result == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        flags |= claripy.If((old & 0x0F) == 0, claripy.BVV(0x10, 8), claripy.BVV(0, 8))
        self.state.regs.a = result
        self.state.regs.f = flags | claripy.BVV(2, 8) | carry
        self.jump(self.next_address)


class FlagActionSummary(angr.SimProcedure):
    def __init__(self, next_address: int, native: bool = False):
        super().__init__()
        self.next_address = next_address
        self.native = native

    @staticmethod
    def _result(bit: claripy.ast.BV, value: claripy.ast.BV) -> claripy.ast.BV:
        result = claripy.BVV(0, 8)
        for position in range(8):
            result = claripy.If(
                (bit & 7) == position,
                value & (1 << position),
                result,
            )
        return result

    def run(self, state: claripy.ast.BV | None = None) -> None:  # type: ignore[override]
        if self.native:
            if state is None:
                state = self.state.regs.rdi
            bit = self.state.memory.load(state + 3, 1)
            value = self.state.memory.load(state + 8, 1)
            result = self._result(bit, value)
            flags = claripy.If(result == 0, claripy.BVV(0xA0, 8), claripy.BVV(0x20, 8))
            self.state.memory.store(state, result)
            self.state.memory.store(state + 1, flags)
            self.state.memory.store(state + 3, result)
            return
        bit = self.state.regs.c
        index = claripy.LShR(bit, 3)
        value = claripy.BVV(0, 8)
        for offset in range(32):
            value = claripy.If(
                index == offset,
                self.state.memory.load(W_BUFFER + offset, 1),
                value,
            )
        result = self._result(bit, value)
        self.state.regs.a = result
        self.state.regs.f = sm83_flags_to_z80(
            claripy.If(result == 0, claripy.BVV(0xA0, 8), claripy.BVV(0x20, 8))
        )
        self.state.regs.c = result
        self.jump(self.next_address)


class IsItemHMSummary(angr.SimProcedure):
    def __init__(self, next_address: int, native: bool = False):
        super().__init__()
        self.next_address = next_address
        self.native = native

    def run(self, state: claripy.ast.BV | None = None) -> None:  # type: ignore[override]
        if self.native:
            if state is None:
                state = self.state.regs.rdi
            value = self.state.memory.load(state, 1)
            flags = claripy.If(
                value < 0xC4,
                claripy.If(value == 0, claripy.BVV(0xA0, 8), claripy.BVV(0x20, 8)),
                _comparison_flags(value, 0xC9),
            )
            self.state.memory.store(state + 1, flags)
            return
        value = self.state.regs.a
        flags = claripy.If(
            value < 0xC4,
            claripy.If(value == 0, claripy.BVV(0xA0, 8), claripy.BVV(0x20, 8)),
            _comparison_flags(value, 0xC9),
        )
        self.state.regs.f = sm83_flags_to_z80(flags)
        self.jump(self.next_address)


class AndA(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        flags = claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0xA0, 8),
            claripy.BVV(0x20, 8),
        )
        self.state.regs.f = sm83_flags_to_z80(flags)
        self.jump(self.next_address)


class XorA(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0x80, 8))
        self.jump(self.next_address)


class Fork(angr.SimProcedure):
    def __init__(self, taken: int, fallthrough: int, flag_bit: int, set_: bool):
        super().__init__()
        self.taken = taken
        self.fallthrough = fallthrough
        self.flag_bit = flag_bit
        self.set_ = set_

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        bit = (self.state.regs.f >> self.flag_bit) & 1
        condition = bit == (1 if self.set_ else 0)
        for target, guard in (
            (self.taken, condition),
            (self.fallthrough, claripy.Not(condition)),
        ):
            successor = self.state.copy()
            successor.solver.add(guard)
            successor.regs.ip = claripy.BVV(target, 16)
            self.successors.add_successor(successor, target, guard, "Ijk_Boring")


class Finish(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(DONE)


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["item"] = claripy.BVS(f"{prefix}_item", 8)
    values["is_key_item"] = claripy.BVS(f"{prefix}_is_key_item", 8)
    values["marker"] = claripy.BVS(f"{prefix}_marker", 8)
    for index in range(15):
        values[f"table{index}"] = claripy.BVS(f"{prefix}_table{index}", 8)
    for index in range(32):
        values[f"buffer{index}"] = claripy.BVS(f"{prefix}_buffer{index}", 8)
    return values


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "IsKeyItem_")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    project = angr.Project(
        rom_window(ROM, location.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0, "entry_point": location.address},
    )
    base = location.address
    project.hook(base + 2, Sm83StoreAImmediate(W_IS_KEY_ITEM, base + 5), length=3)
    project.hook(base + 5, Sm83LoadAImmediate(W_CUR_ITEM, base + 8), length=3)
    project.hook(base + 8, Sm83CpImmediate(0xC4, base + 10), length=2)
    project.hook(base + 10, Fork(base + 41, base + 12, 0, False), length=2)
    project.hook(base + 12, SaveAf(base + 13), length=1)
    project.hook(base + 22, CopyDataSummary(base + 25), length=3)
    project.hook(base + 25, RestoreAf(base + 26), length=1)
    project.hook(base + 26, DecA(base + 27), length=1)
    project.hook(base + 35, FlagActionSummary(base + 38), length=3)
    project.hook(base + 39, AndA(base + 40), length=1)
    project.hook(base + 40, Fork(DONE, base + 41, 6, False), length=1)
    project.hook(base + 41, Sm83LoadAImmediate(W_CUR_ITEM, base + 44), length=3)
    project.hook(base + 44, IsItemHMSummary(base + 47), length=3)
    project.hook(base + 47, Fork(DONE, base + 48, 0, True), length=1)
    project.hook(base + 48, XorA(base + 49), length=1)
    project.hook(base + 49, Sm83StoreAImmediate(W_IS_KEY_ITEM, base + 52), length=3)
    project.hook(base + 52, Finish(), length=1)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.memory.store(W_CUR_ITEM, values["item"])
    state.memory.store(W_IS_KEY_ITEM, values["is_key_item"])
    for index in range(15):
        state.memory.store(KEY_ITEM_FLAGS + index, values[f"table{index}"])
    for index in range(32):
        state.memory.store(W_BUFFER + index, values[f"buffer{index}"])
    state.memory.store(MARKER, values["marker"])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=10)
    assert not manager.errored
    return [
        Endpoint(
            **assembly_registers(end),
            is_key_item=end.memory.load(W_IS_KEY_ITEM, 1),
            buffer=end.memory.load(W_BUFFER, 32),
            marker=end.memory.load(MARKER, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_is_key_item_")
    copy_data = project.loader.find_symbol("port_copy_data")
    flag_action = project.loader.find_symbol("port_flag_action")
    is_item_hm = project.loader.find_symbol("port_is_item_hm")
    assert function and copy_data and flag_action and is_item_hm
    project.hook(copy_data.rebased_addr, CopyDataSummary(0, True))
    project.hook(flag_action.rebased_addr, FlagActionSummary(0, True))
    project.hook(is_item_hm.rebased_addr, IsItemHMSummary(0, True))
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_MEMORY + W_CUR_ITEM, values["item"])
    state.memory.store(NATIVE_MEMORY + W_IS_KEY_ITEM, values["is_key_item"])
    for index in range(15):
        state.memory.store(NATIVE_MEMORY + KEY_ITEM_FLAGS + index, values[f"table{index}"])
    for index in range(32):
        state.memory.store(NATIVE_MEMORY + W_BUFFER + index, values[f"buffer{index}"])
    state.memory.store(NATIVE_MEMORY + MARKER, values["marker"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            is_key_item=end.memory.load(NATIVE_MEMORY + W_IS_KEY_ITEM, 1),
            buffer=end.memory.load(NATIVE_MEMORY + W_BUFFER, 32),
            marker=end.memory.load(NATIVE_MEMORY + MARKER, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_is_key_item_full_pathwise_equivalence() -> None:
    values = _inputs("is_key_item_full")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "is_key_item", "buffer", "marker"),
    )
