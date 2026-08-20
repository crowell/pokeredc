from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
    assembly_registers,
    native_registers,
    set_assembly_registers,
    store_native_registers,
    symbolic_registers,
)
from verification.harness.rom import linked_bytes, rom_window, symbol_location

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
DONE = 0xEFFF
FIELDS = ("options", "scy", "scx", "loop_b", "loop_c", "loop_d", "loop_e", "loop_h", "loop_l")


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
    options: claripy.ast.BV
    scy: claripy.ast.BV
    scx: claripy.ast.BV
    loop_b: claripy.ast.BV
    loop_c: claripy.ast.BV
    loop_d: claripy.ast.BV
    loop_e: claripy.ast.BV
    loop_h: claripy.ast.BV
    loop_l: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class LoadField(angr.SimProcedure):
    def __init__(self, field: str, next_address: int, length: int) -> None:
        super().__init__()
        self.field = field
        self.next_address = next_address
        self.length = length

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals[self.field]
        self.jump(self.next_address)


class PushNoOp(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(self.state.addr + 1)


class ZeroA(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x40, 8)
        self.jump(self.state.addr + 1)


class ZeroField(angr.SimProcedure):
    def __init__(self, field: str, next_address: int) -> None:
        super().__init__()
        self.field = field
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.globals[self.field] = claripy.BVV(0, 8)
        self.jump(self.next_address)


class LoopSummary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        for register, field in (("b", "loop_b"), ("c", "loop_c"), ("d", "loop_d"), ("e", "loop_e"), ("h", "loop_h"), ("l", "loop_l")):
            setattr(self.state.regs, register, self.state.globals[field])
        self.jump(self.state.addr + 24)


class PopAF(angr.SimProcedure):
    def __init__(self, field: str, next_address: int) -> None:
        super().__init__()
        self.field = field
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals[self.field]
        self.state.regs.f = self.state.globals["input_f_z80"]
        self.jump(self.next_address)


class StoreField(angr.SimProcedure):
    def __init__(self, field: str, next_address: int) -> None:
        super().__init__()
        self.field = field
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.globals[self.field] = self.state.regs.a
        self.jump(self.next_address)


class Boundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(DONE)


def _assembly(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    loc = symbol_location(SYMBOLS, "TradeAnimCommon")
    base = loc.address
    project = angr.Project(rom_window(ROM, loc.bank), auto_load_libs=False, rebase_granularity=0x100, main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0, "entry_point": base})
    project.hook(base, LoadField("options", base + 3, 3), length=3)
    project.hook(base + 3, PushNoOp(), length=1)
    project.hook(base + 4, LoadField("scy", base + 6, 2), length=2)
    project.hook(base + 6, PushNoOp(), length=1)
    project.hook(base + 7, LoadField("scx", base + 9, 2), length=2)
    project.hook(base + 9, PushNoOp(), length=1)
    project.hook(base + 10, ZeroA(), length=1)
    project.hook(base + 11, ZeroField("options", base + 14), length=3)
    project.hook(base + 14, ZeroField("scy", base + 16), length=2)
    project.hook(base + 16, ZeroField("scx", base + 18), length=2)
    project.hook(base + 18, PushNoOp(), length=1)
    project.hook(base + 19, LoopSummary(), length=24)
    project.hook(base + 43, PopAF("saved_scx", base + 44), length=1)
    project.hook(base + 44, StoreField("scx", base + 46), length=2)
    project.hook(base + 46, PopAF("saved_scy", base + 47), length=1)
    project.hook(base + 47, StoreField("scy", base + 49), length=2)
    project.hook(base + 49, PopAF("saved_options", base + 50), length=1)
    project.hook(base + 50, StoreField("options", base + 53), length=3)
    project.hook(base + 53, Boundary(), length=1)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, inputs)
    for field in FIELDS:
        state.globals[field] = inputs[field]
    state.globals["saved_options"] = inputs["options"]
    state.globals["saved_scy"] = inputs["scy"]
    state.globals["saved_scx"] = inputs["scx"]
    state.globals["input_f_z80"] = state.regs.f
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert len(manager.found) == 1
    end = manager.found[0]
    return [Endpoint(**assembly_registers(end), **{field: end.globals[field] for field in FIELDS}, constraints=tuple(end.solver.constraints))]


def _native(inputs: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_trade_anim_common")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, inputs)
    for offset, field in enumerate(FIELDS, 8):
        state.memory.store(NATIVE_STATE + offset, inputs[field])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    end = manager.deadended[0]
    return [Endpoint(**native_registers(end, NATIVE_STATE), **{field: end.memory.load(NATIVE_STATE + offset, 1) for offset, field in enumerate(FIELDS, 8)}, constraints=tuple(end.solver.constraints))]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_trade_anim_common_pathwise_equivalence() -> None:
    inputs = symbolic_registers("tac")
    for field in FIELDS:
        inputs[field] = claripy.BVS(f"tac_{field}", 8)
    assert_pathwise_equivalent(_assembly(inputs), _native(inputs), ("a", "f", "b", "c", "d", "e", "h", "l", *FIELDS))


def test_trade_anim_common_exact_linked_body() -> None:
    loc = symbol_location(SYMBOLS, "TradeAnimCommon")
    assert linked_bytes(ROM, loc, 54) == bytes.fromhex("fa55d3f5f0aff5f0aef5afea55d3e0afe0aed5d11afeff281213d5215f51874f0600092a666f111551d5e9f1e0aef1e0aff1ea55d3c9")
