from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
    REGISTERS, assembly_registers, native_registers, set_assembly_registers,
    store_native_registers, symbolic_registers,
)
from verification.harness.rom import linked_bytes, rom_window, sm83_flags_to_z80, symbol_location
from verification.harness.sm83_shims import Sm83CpImmediate, Sm83LoadAImmediate

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF
TILEMAP = 0xC3A0
TILEMAP_SIZE = 360
W_CUR_MAP = 0xD35E
W_SAFARI_STEPS = 0xD70D
W_SAFARI_BALLS = 0xDA47
OBSERVED = (W_CUR_MAP, W_SAFARI_STEPS, W_SAFARI_STEPS + 1,
            W_SAFARI_STEPS + 2, W_SAFARI_BALLS)
CALL_COUNT = 5
CALL_WIDTH = (len(REGISTERS) + len(OBSERVED) + TILEMAP_SIZE) * 8
EXPECTED = bytes.fromhex(
    "fa5ed3fed9d8fee2d021a0c306030e07cd221921b5c3110dd7010302cd5f3c"
    "21b8c3117945cd551921ddc3117e45cd5519fa47dafe0a300621e1c33e7f77"
    "21e2c31147da010201c35f3c"
)


@dataclass(frozen=True)
class Endpoint:
    a: claripy.ast.BV; f: claripy.ast.BV; b: claripy.ast.BV; c: claripy.ast.BV
    d: claripy.ast.BV; e: claripy.ast.BV; h: claripy.ast.BV; l: claripy.ast.BV
    memory: claripy.ast.BV; calls: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _inputs(prefix: str, current_map: int, safari_balls: int) -> dict[str, object]:
    values: dict[str, object] = symbolic_registers(prefix)
    values["tilemap"] = claripy.BVS(f"{prefix}_tilemap", TILEMAP_SIZE * 8)
    values["globals"] = [claripy.BVV(current_map, 8),
                         claripy.BVS(f"{prefix}_steps_hi", 8),
                         claripy.BVS(f"{prefix}_steps_lo", 8),
                         claripy.BVS(f"{prefix}_steps_fraction", 8),
                         claripy.BVV(safari_balls, 8)]
    values["posts"] = []
    for call in range(CALL_COUNT):
        post = [claripy.Concat(claripy.BVS(f"{prefix}_post_{call}_f", 4), claripy.BVV(0, 4))
                if name == "f" else claripy.BVS(f"{prefix}_post_{call}_{name}", 8)
                for name in REGISTERS]
        post.append(claripy.BVS(f"{prefix}_post_{call}_tilemap", TILEMAP_SIZE * 8))
        values["posts"].append(post)
    return values


def _setup(state: angr.SimState, values: dict[str, object], base: int = 0) -> None:
    state.memory.store(base + TILEMAP, values["tilemap"])
    for address, value in zip(OBSERVED, values["globals"], strict=True):
        state.memory.store(base + address, value)
    state.globals["call_index"] = 0
    for index in range(CALL_COUNT): state.globals[f"call_{index}"] = claripy.BVV(0, CALL_WIDTH)


def _regs(state: angr.SimState, native: bool, ptr: int | claripy.ast.BV = 0):
    return native_registers(state, ptr) if native else assembly_registers(state)


def _snapshot(state: angr.SimState, native: bool, ptr: int | claripy.ast.BV = 0) -> claripy.ast.BV:
    base = NATIVE_MEMORY if native else 0
    registers = _regs(state, native, ptr)
    return claripy.Concat(*(registers[name] for name in REGISTERS),
                         *(state.memory.load(base + address, 1) for address in OBSERVED),
                         state.memory.load(base + TILEMAP, TILEMAP_SIZE))


def _post(state: angr.SimState, values: dict[str, object], index: int, native: bool,
          ptr: int | claripy.ast.BV = 0) -> None:
    post = values["posts"][index]
    if native:
        for offset, value in enumerate(post[:8]): state.memory.store(ptr + offset, value)
    else:
        for name, value in zip(REGISTERS, post[:8], strict=True):
            setattr(state.regs, name, sm83_flags_to_z80(value) if name == "f" else value)
    state.memory.store((NATIVE_MEMORY if native else 0) + TILEMAP, post[8])


class Boundary(angr.SimProcedure):
    def __init__(self, values: dict[str, object], index: int, target: int, *, native: bool) -> None:
        super().__init__(); self.values = values; self.index = index; self.target = target; self.native = native
    def run(self, *args: claripy.ast.BV) -> None:  # type: ignore[override]
        ptr = self.state.regs.rdi if self.native else 0
        self.state.globals[f"call_{self.index}"] = _snapshot(self.state, self.native, ptr)
        _post(self.state, self.values, self.index, self.native, ptr)
        self.state.globals["call_index"] = self.index + 1
        if self.native: self.ret()
        else: self.jump(self.target)


class NativeBoundary(angr.SimProcedure):
    def __init__(self, values: dict[str, object]) -> None:
        super().__init__(); self.values = values
    def run(self, *args: claripy.ast.BV) -> None:  # type: ignore[override]
        index = self.state.globals["call_index"]
        pointer = self.state.regs.rdi
        self.state.globals[f"call_{index}"] = _snapshot(self.state, True, pointer)
        _post(self.state, self.values, index, True, pointer)
        self.state.globals["call_index"] = index + 1
        self.ret()


class LoadPair(angr.SimProcedure):
    def __init__(self, high: str, low: str, value: int, target: int) -> None:
        super().__init__(); self.high=high; self.low=low; self.value=value; self.target=target
    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.high, claripy.BVV(self.value >> 8, 8)); setattr(self.state.regs, self.low, claripy.BVV(self.value, 8)); self.jump(self.target)


class Load(angr.SimProcedure):
    def __init__(self, register: str, value: int, target: int) -> None:
        super().__init__(); self.register=register; self.value=value; self.target=target
    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.register, claripy.BVV(self.value, 8)); self.jump(self.target)


class StoreAAtHL(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__(); self.target = target
    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(self.state.regs.hl, self.state.regs.a); self.jump(self.target)


class Branch(angr.SimProcedure):
    def __init__(self, target: int, fallthrough: int, *, carry: bool) -> None:
        super().__init__(); self.target=target; self.fallthrough=fallthrough; self.carry=carry
    def run(self) -> None:  # type: ignore[override]
        condition = ((self.state.regs.f & 1) != 0) == self.carry
        self.inhibit_autoret = True
        self.successors.add_successor(self.state.copy(), self.target, condition, "Ijk_Boring")
        self.successors.add_successor(self.state.copy(), self.fallthrough, claripy.Not(condition), "Ijk_Boring")


def _endpoints(states, native: bool) -> list[Endpoint]:
    base = NATIVE_MEMORY if native else 0
    return [Endpoint(**_regs(state, native, NATIVE_STATE if native else 0),
                     memory=claripy.Concat(state.memory.load(base + TILEMAP, TILEMAP_SIZE),
                                           *(state.memory.load(base + address, 1) for address in OBSERVED)),
                     calls=claripy.Concat(*(state.globals[f"call_{i}"] for i in range(CALL_COUNT))),
                     constraints=tuple(state.solver.constraints)) for state in states]


def _assembly(values: dict[str, object]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "PrintSafariZoneSteps"); b = location.address
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    project = angr.Project(rom_window(ROM, location.bank), auto_load_libs=False, rebase_granularity=0x100,
        main_opts={"backend":"blob", "arch":ArchPcode("z80:LE:16:default"), "base_addr":0, "entry_point":b})
    project.hook(b, Sm83LoadAImmediate(W_CUR_MAP, b+3), length=3); project.hook(b+3, Sm83CpImmediate(0xd9,b+5), length=2); project.hook(b+5, Branch(DONE,b+6,carry=True), length=1)
    project.hook(b+6, Sm83CpImmediate(0xe2,b+8), length=2); project.hook(b+8, Branch(DONE,b+9,carry=False), length=1)
    project.hook(b+9,LoadPair("h","l",0xc3a0,b+12),length=3); project.hook(b+12,Load("b",3,b+14),length=2); project.hook(b+14,Load("c",7,b+16),length=2); project.hook(b+16,Boundary(values,0,b+19,native=False),length=3)
    project.hook(b+19,LoadPair("h","l",0xc3b5,b+22),length=3); project.hook(b+22,LoadPair("d","e",0xd70d,b+25),length=3); project.hook(b+25,LoadPair("b","c",0x0203,b+28),length=3); project.hook(b+28,Boundary(values,1,b+31,native=False),length=3)
    project.hook(b+31,LoadPair("h","l",0xc3b8,b+34),length=3); project.hook(b+34,LoadPair("d","e",0x4579,b+37),length=3); project.hook(b+37,Boundary(values,2,b+40,native=False),length=3)
    project.hook(b+40,LoadPair("h","l",0xc3dd,b+43),length=3); project.hook(b+43,LoadPair("d","e",0x457e,b+46),length=3); project.hook(b+46,Boundary(values,3,b+49,native=False),length=3)
    project.hook(b+49,Sm83LoadAImmediate(W_SAFARI_BALLS,b+52),length=3); project.hook(b+52,Sm83CpImmediate(10,b+54),length=2); project.hook(b+54,Branch(b+62,b+56,carry=False),length=2)
    project.hook(b+56,LoadPair("h","l",0xc3e1,b+59),length=3); project.hook(b+59,Load("a",0x7f,b+61),length=2)
    project.hook(b+61,StoreAAtHL(b+62),length=1)
    project.hook(b+62,LoadPair("h","l",0xc3e2,b+65),length=3); project.hook(b+65,LoadPair("d","e",0xda47,b+68),length=3); project.hook(b+68,LoadPair("b","c",0x0102,b+71),length=3); project.hook(b+71,Boundary(values,4,DONE,native=False),length=3)
    state=project.factory.blank_state(addr=b); set_assembly_registers(state,values); _setup(state,values); manager=project.factory.simulation_manager(state); manager.explore(find=DONE); assert not manager.errored and manager.found; return _endpoints(manager.found,False)


def _native(values: dict[str, object]) -> list[Endpoint]:
    project=angr.Project(ELF,auto_load_libs=False); function=project.loader.find_symbol("port_print_safari_zone_steps"); border=project.loader.find_symbol("port_text_box_border"); number=project.loader.find_symbol("port_print_number"); place=project.loader.find_symbol("port_place_string"); assert all((function,border,number,place))
    project.hook(border.rebased_addr,NativeBoundary(values)); project.hook(number.rebased_addr,NativeBoundary(values)); project.hook(place.rebased_addr,NativeBoundary(values))
    state=project.factory.call_state(function.rebased_addr,NATIVE_STATE,NATIVE_MEMORY); store_native_registers(state,NATIVE_STATE,values); _setup(state,values,NATIVE_MEMORY); manager=project.factory.simulation_manager(state); manager.run(); assert not manager.errored and manager.deadended; return _endpoints(manager.deadended,True)


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),reason="build artifacts missing")
@pytest.mark.parametrize(("current_map", "safari_balls"),
                         ((0xd8, 0), (0xe2, 0), (0xd9, 9), (0xd9, 10)))
def test_print_safari_zone_steps_pathwise_equivalence(current_map: int,
                                                      safari_balls: int) -> None:
    values = _inputs(f"print_safari_{current_map}_{safari_balls}", current_map,
                     safari_balls)
    assert_pathwise_equivalent(_assembly(values), _native(values),
                               (*REGISTERS, "memory", "calls"))
