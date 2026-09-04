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
from verification.harness.rom import linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import (
    Sm83CpImmediate,
    Sm83DecRegister,
    Sm83LoadAImmediate,
    Sm83StoreAAtHlIncrement,
    Sm83StoreAImmediate,
    Sm83XorImmediate,
)


ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NS = 0x100000
NM = 0x200000
RET = 0xFFFF
USE_LIST = 0xCD3D
COUNTER = 0xCD3E
BIRD_IMAGE = 0xCD3F
PLAYER_IMAGE = 0xC102
PLAYER_Y = 0xC104
PLAYER_X = 0xC106
SOURCE = 0xC600
BODY = bytes.fromhex("fa3fcdee01ea3fcdea02c1cdd73dfa3dcdfeff280a2104c11a1322231a1377fa3ecd3dea3ecd20d8c9")


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
    constraints: tuple[claripy.ast.Bool, ...]


class Delay3(angr.SimProcedure):
    """Complete terminal state of the independently proven Delay3 loop."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.c = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x42, 8)
        self.jump(self.next_address)


class LoadAtDE(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self.state.regs.de, 1)
        self.jump(self.next_address)


class BranchZ(angr.SimProcedure):
    def __init__(self, when_set: int, when_clear: int) -> None:
        super().__init__()
        self.when_set = when_set
        self.when_clear = when_clear

    def run(self) -> None:  # type: ignore[override]
        condition = (self.state.regs.f & 0x40) != 0
        yes = self.state.copy()
        no = self.state.copy()
        yes.solver.add(condition)
        no.solver.add(~condition)
        yes.regs.ip = claripy.BVV(self.when_set, 16)
        no.regs.ip = claripy.BVV(self.when_clear, 16)
        self.inhibit_autoret = True
        self.successors.add_successor(yes, self.when_set, condition, "Ijk_Boring")
        self.successors.add_successor(no, self.when_clear, ~condition, "Ijk_Boring")


class Return(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        target = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp += 2
        self.jump(target)


def setup(state: angr.SimState, base: int, values: dict[str, claripy.ast.BV], use_list: int, counter: int) -> None:
    state.memory.store(base + USE_LIST, claripy.BVV(use_list, 8))
    state.memory.store(base + COUNTER, claripy.BVV(counter, 8))
    state.memory.store(base + BIRD_IMAGE, values["bird_image"])
    state.memory.store(base + PLAYER_IMAGE, values["player_image"])
    state.memory.store(base + PLAYER_Y, values["player_y"])
    state.memory.store(base + PLAYER_Y + 1, values["player_y_adjacent"])
    state.memory.store(base + PLAYER_X, values["player_x"])
    for index in range(4):
        state.memory.store(base + SOURCE + index, values[f"source{index}"])


def endpoint(state: angr.SimState, native: bool) -> Endpoint:
    base = NM if native else 0
    registers = native_registers(state, NS) if native else assembly_registers(state)
    watched = (USE_LIST, COUNTER, BIRD_IMAGE, PLAYER_IMAGE, PLAYER_Y, PLAYER_Y + 1, PLAYER_X, *(SOURCE + index for index in range(4)))
    return Endpoint(
        **registers,
        state=claripy.Concat(*(state.memory.load(base + address, 1) for address in watched)),
        constraints=tuple(state.solver.constraints),
    )


def assembly(values: dict[str, claripy.ast.BV], use_list: int, counter: int) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "DoFlyAnimation")
    assert linked_bytes(ROM, location, len(BODY)) == BODY
    project = angr.Project(rom_window(ROM, location.bank), auto_load_libs=False, rebase_granularity=0x100, main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0, "entry_point": location.address})
    start = location.address
    project.hook(start, Sm83LoadAImmediate(BIRD_IMAGE, start + 3), length=3)
    project.hook(start + 3, Sm83XorImmediate(1, start + 5), length=2)
    project.hook(start + 5, Sm83StoreAImmediate(BIRD_IMAGE, start + 8), length=3)
    project.hook(start + 8, Sm83StoreAImmediate(PLAYER_IMAGE, start + 11), length=3)
    project.hook(start + 11, Delay3(start + 14), length=3)
    project.hook(start + 14, Sm83LoadAImmediate(USE_LIST, start + 17), length=3)
    project.hook(start + 17, Sm83CpImmediate(0xFF, start + 19), length=2)
    project.hook(start + 19, BranchZ(start + 31, start + 21), length=2)
    project.hook(start + 24, LoadAtDE(start + 25), length=1)
    project.hook(start + 26, Sm83StoreAAtHlIncrement(start + 27), length=1)
    project.hook(start + 28, LoadAtDE(start + 29), length=1)
    project.hook(start + 31, Sm83LoadAImmediate(COUNTER, start + 34), length=3)
    project.hook(start + 34, Sm83DecRegister("a", start + 35), length=1)
    project.hook(start + 35, Sm83StoreAImmediate(COUNTER, start + 38), length=3)
    project.hook(start + 38, BranchZ(start + 40, start), length=2)
    project.hook(start + 40, Return(), length=1)
    state = project.factory.blank_state(addr=start)
    set_assembly_registers(state, values)
    if use_list != 0xFF:
        state.regs.de = claripy.BVV(SOURCE, 16)
    setup(state, 0, values, use_list, counter)
    state.regs.sp = claripy.BVV(0xD000, 16)
    state.memory.store(0xD000, claripy.BVV(RET, 16), endness="Iend_LE")
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RET)
    assert not manager.errored and len(manager.found) == 1
    return [endpoint(manager.found[0], False)]


def native(values: dict[str, claripy.ast.BV], use_list: int, counter: int) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_do_fly_animation")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NS, NM)
    store_native_registers(state, NS, values)
    if use_list != 0xFF:
        state.memory.store(NS + 4, claripy.BVV(SOURCE >> 8, 8))
        state.memory.store(NS + 5, claripy.BVV(SOURCE & 0xFF, 8))
    setup(state, NM, values, use_list, counter)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [endpoint(manager.deadended[0], True)]


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(), reason="build artifacts missing")
@pytest.mark.parametrize("use_list,counter", ((0xFF, 1), (0xFF, 2), (0, 1), (0, 2)))
def test_do_fly_animation_pathwise_equivalence(use_list: int, counter: int) -> None:
    values = symbolic_registers(f"do_fly_{use_list}_{counter}")
    for name in ("bird_image", "player_image", "player_y", "player_y_adjacent", "player_x", *(f"source{index}" for index in range(4))):
        values[name] = claripy.BVS(f"do_fly_{use_list}_{counter}_{name}", 8)
    assert_pathwise_equivalent(assembly(values, use_list, counter), native(values, use_list, counter), (*REGISTERS, "state"))
