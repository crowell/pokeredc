from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS, assembly_registers, native_registers, set_assembly_registers, store_native_registers, symbolic_registers
from verification.harness.rom import collect_returns, linked_bytes, rom_window, sm83_flags_to_z80, symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair, Sm83CpImmediate, Sm83StoreAImmediate


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
STACK = 0xD000
RETURN = 0xFFFF


class SavePairs(angr.SimProcedure):
    def __init__(self, next_address: int, save_af: bool):
        super().__init__()
        self.next_address = next_address
        self.save_af = save_af

    def run(self):
        if self.save_af:
            self.state.globals["saved_a"] = self.state.regs.a
            self.state.globals["saved_f"] = self.state.regs.f
        else:
            self.state.globals["saved_d"] = self.state.regs.d
            self.state.globals["saved_e"] = self.state.regs.e
        self.jump(self.next_address)


class RestoreAF(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__(); self.next_address = next_address

    def run(self):
        self.state.regs.a = self.state.globals["saved_a"]
        self.state.regs.f = self.state.globals["saved_f"]
        self.jump(self.next_address)


class RestoreDE(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__(); self.next_address = next_address

    def run(self):
        self.state.regs.d = self.state.globals["saved_d"]
        self.state.regs.e = self.state.globals["saved_e"]
        self.jump(self.next_address)


class LoadHeaderHigh(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__(); self.next_address = next_address

    def run(self):
        self.state.regs.a = self.state.globals["header_high"]
        self.state.regs.hl = self.state.regs.hl + 1
        self.jump(self.next_address)


class LoadRegister(angr.SimProcedure):
    def __init__(self, register: str, key: str, next_address: int, increment_hl: bool = False):
        super().__init__(); self.register = register; self.key = key; self.next_address = next_address; self.increment_hl = increment_hl

    def run(self):
        setattr(self.state.regs, self.register, self.state.globals[self.key])
        if self.increment_hl:
            self.state.regs.hl = self.state.regs.hl + 1
        self.jump(self.next_address)


class AndA(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__(); self.next_address = next_address

    def run(self):
        self.state.regs.f = claripy.BVV(0x10, 8) | claripy.If(self.state.regs.a == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        self.jump(self.next_address)


@dataclass(frozen=True)
class Endpoint:
    a: claripy.ast.BV; f: claripy.ast.BV; b: claripy.ast.BV; c: claripy.ast.BV
    d: claripy.ast.BV; e: claripy.ast.BV; h: claripy.ast.BV; l: claripy.ast.BV
    memory: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _inputs() -> dict[str, claripy.ast.BV]:
    inputs = symbolic_registers("trainer_header")
    for name in ("header_high", "header_low", "flag_bit", "fetched_first", "fetched_second"):
        inputs[name] = claripy.BVS("trainer_header_" + name, 8)
    return inputs


def _assembly(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "ReadTrainerHeaderInfo")
    address = location.address
    header = symbol_location(SYMBOLS, "wTrainerHeaderPtr").address
    flag = symbol_location(SYMBOLS, "wTrainerHeaderFlagBit").address
    project = angr.Project(rom_window(ROM, location.bank), auto_load_libs=False, rebase_granularity=0x100, main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0, "entry_point": address})
    project.hook(address, SavePairs(address + 1, False), length=1)
    project.hook(address + 1, SavePairs(address + 2, True), length=1)
    project.hook(address + 8, LoadHeaderHigh(address + 9), length=1)
    project.hook(address + 9, LoadRegister("l", "header_low", address + 10), length=1)
    project.hook(address + 11, Sm83AddHlRegisterPair("de", address + 12), length=1)
    project.hook(address + 12, RestoreAF(address + 13), length=1)
    project.hook(address + 13, AndA(address + 14), length=1)
    project.hook(address + 16, LoadRegister("a", "fetched_first", address + 17), length=1)
    project.hook(address + 17, Sm83StoreAImmediate(flag, address + 20), length=3)
    for offset, immediate in ((22, 2), (26, 4), (30, 6), (34, 8), (38, 10)):
        project.hook(address + offset, Sm83CpImmediate(immediate, address + offset + 2), length=2)
    project.hook(address + 42, LoadRegister("a", "fetched_first", address + 43, True), length=1)
    project.hook(address + 43, LoadRegister("d", "fetched_second", address + 44), length=1)
    project.hook(address + 47, LoadRegister("a", "fetched_first", address + 48, True), length=1)
    project.hook(address + 48, LoadRegister("h", "fetched_second", address + 49), length=1)
    project.hook(address + 50, RestoreDE(address + 51), length=1)
    state = project.factory.blank_state(addr=address)
    set_assembly_registers(state, inputs)
    state.globals["header_high"] = inputs["header_high"]
    state.globals["header_low"] = inputs["header_low"]
    state.globals["fetched_first"] = inputs["fetched_first"]
    state.globals["fetched_second"] = inputs["fetched_second"]
    state.memory.store(header, claripy.Concat(inputs["header_high"], inputs["header_low"]))
    state.memory.store(flag, inputs["flag_bit"])
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    return [Endpoint(**assembly_registers(end), memory=claripy.Concat(end.memory.load(header, 2), end.memory.load(flag, 1), inputs["fetched_first"], inputs["fetched_second"]), constraints=tuple(end.solver.constraints)) for end in collect_returns(project, state, RETURN)]


def _native(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_read_trainer_header_info")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    state.memory.store(NATIVE_STATE + 8, claripy.Concat(inputs["header_high"], inputs["header_low"], inputs["flag_bit"], inputs["fetched_first"], inputs["fetched_second"]))
    manager = project.factory.simulation_manager(state); manager.run(); assert not manager.errored
    return [Endpoint(**native_registers(end, NATIVE_STATE), memory=end.memory.load(NATIVE_STATE + 8, 5), constraints=tuple(end.solver.constraints)) for end in manager.deadended]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
def test_equivalence() -> None:
    inputs = _inputs()
    assert_pathwise_equivalent(_assembly(inputs), _native(inputs), (*REGISTERS, "memory"))


def test_exact_body() -> None:
    location = symbol_location(SYMBOLS, "ReadTrainerHeaderInfo")
    assert linked_bytes(ROM, location, 52) == bytes.fromhex("d5f516005f2130da2a6e6719f1a720067eea55cc181cfe022815fe042811fe06280dfe082809fe0a20082a565f18032a666fd1c9")
