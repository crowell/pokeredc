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
from verification.harness.rom import linked_bytes, rom_window, sm83_flags_to_z80, symbol_location
from verification.harness.sm83_shims import (
    Sm83LoadAHighImmediate,
    Sm83StoreAHighImmediate,
    Sm83XorA,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF
TILEMAP = 0xC3A0
TILEMAP_SIZE = 360
OBSERVED_MEMORY = ((0xD100, 0x300), (0xFF95, 10), (0xDA41, 5))
H_AUTO = 0xFFBA
H_VBLANK = 30
EXPECTED = bytes.fromhex(
    "afe0ba2130c406080e0ecd22192159c4116a5ecd55192160c41158d1cd5519"
    "218dc4cd2f5e21b4c4cd425e21d9c4cd555e3e01e0ba0e1ec33937"
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
    memory: claripy.ast.BV
    calls: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _inputs(prefix: str) -> dict[str, object]:
    values: dict[str, object] = symbolic_registers(prefix)
    values["tilemap"] = claripy.BVS(f"{prefix}_tilemap", TILEMAP_SIZE * 8)
    values["globals"] = []
    for region, size in OBSERVED_MEMORY:
        values["globals"].extend(
            claripy.BVS(f"{prefix}_g_{region:04x}_{i}", 8)
            for i in range(size)
        )
    values["observations"] = claripy.BVS(f"{prefix}_observations", H_VBLANK * 8)
    values["posts"] = []
    for call in range(7):
        values["posts"].append(
            [
                claripy.Concat(
                    claripy.BVS(f"{prefix}_post_{call}_flags", 4),
                    claripy.BVV(0, 4),
                )
                if register == "f"
                else claripy.BVS(f"{prefix}_post_{call}_{register}", 8)
                for register in REGISTERS
            ]
        )
        values["posts"][call].append(
            claripy.BVS(f"{prefix}_post_{call}_tilemap", TILEMAP_SIZE * 8)
        )
    return values


def _setup(state: angr.SimState, values: dict[str, object], memory: int = 0) -> None:
    state.memory.store(memory + TILEMAP, values["tilemap"])
    offset = 0
    for address, size in OBSERVED_MEMORY:
        data = claripy.Concat(*values["globals"][offset : offset + size])
        state.memory.store(memory + address, data)
        offset += size
    state.globals["observations"] = values["observations"]
    state.globals["call_index"] = 0


def _regs(state: angr.SimState, native: bool, ptr: claripy.ast.BV | int = 0):
    return native_registers(state, ptr) if native else assembly_registers(state)


def _snapshot(state: angr.SimState, native: bool, ptr: claripy.ast.BV | int = 0) -> claripy.ast.BV:
    base = NATIVE_MEMORY if native else 0
    regs = _regs(state, native, ptr)
    return claripy.Concat(
        *(regs[name] for name in REGISTERS),
        *(state.memory.load(base + address, size) for address, size in OBSERVED_MEMORY),
        state.memory.load(base + TILEMAP, TILEMAP_SIZE),
    )


def _set_post(state: angr.SimState, values: dict[str, object], index: int, native: bool, ptr: claripy.ast.BV | int = 0) -> None:
    post = values["posts"][index]
    if native:
        for offset, value in enumerate(post[:8]):
            state.memory.store(ptr + offset, value)
    else:
        for name, value in zip(REGISTERS, post[:8], strict=True):
            setattr(state.regs, name, sm83_flags_to_z80(value) if name == "f" else value)
    base = NATIVE_MEMORY if native else 0
    state.memory.store(base + TILEMAP, post[8])


class AssemblyBoundary(angr.SimProcedure):
    def __init__(self, values: dict[str, object], index: int, next_address: int) -> None:
        super().__init__(); self.values = values; self.index = index; self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.globals[f"call_{self.index}"] = _snapshot(self.state, False)
        _set_post(self.state, self.values, self.index, False)
        self.state.globals["call_index"] = self.index + 1
        self.jump(self.next_address)


class LoadPair(angr.SimProcedure):
    def __init__(self, high: str, low: str, value: int, next_address: int) -> None:
        super().__init__(); self.high = high; self.low = low; self.value = value; self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.high, claripy.BVV(self.value >> 8, 8))
        setattr(self.state.regs, self.low, claripy.BVV(self.value & 0xFF, 8))
        self.jump(self.next_address)


class LoadImmediate(angr.SimProcedure):
    def __init__(self, register: str, value: int, next_address: int) -> None:
        super().__init__(); self.register = register; self.value = value; self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.register, claripy.BVV(self.value, 8))
        self.jump(self.next_address)


class NativeBoundary(angr.SimProcedure):
    def __init__(self, values: dict[str, object], kind: str) -> None:
        super().__init__(); self.values = values; self.kind = kind

    def run(self, ptr: claripy.ast.BV, second: claripy.ast.BV) -> None:  # type: ignore[override]
        index = self.state.globals["call_index"]
        self.state.globals[f"call_{index}"] = _snapshot(self.state, True, ptr)
        _set_post(self.state, self.values, index, True, ptr)
        self.state.globals["call_index"] = index + 1


class NativePlace(NativeBoundary):
    def run(self, ptr: claripy.ast.BV, second: claripy.ast.BV) -> None:  # type: ignore[override]
        super().run(ptr, second)


class NativeDelay(angr.SimProcedure):
    def __init__(self, values: dict[str, object]) -> None:
        super().__init__(); self.values = values

    def run(self, ptr: claripy.ast.BV, observations: claripy.ast.BV) -> None:  # type: ignore[override]
        index = self.state.globals["call_index"]
        self.state.globals[f"call_{index}"] = _snapshot(self.state, True, ptr)
        _set_post(self.state, self.values, index, True, ptr)
        self.state.globals["call_index"] = index + 1


def _memory(state: angr.SimState, native: bool) -> claripy.ast.BV:
    base = NATIVE_MEMORY if native else 0
    return claripy.Concat(
        state.memory.load(base + TILEMAP, TILEMAP_SIZE),
        state.memory.load(base + H_AUTO, 1),
        *(state.memory.load(base + address, size) for address, size in OBSERVED_MEMORY),
    )


def _endpoints(states, native: bool) -> list[Endpoint]:
    out = []
    for state in states:
        out.append(
            Endpoint(
                **_regs(state, native, NATIVE_STATE if native else 0),
                memory=_memory(state, native),
                calls=claripy.Concat(*(state.globals[f"call_{i}"] for i in range(7))),
                constraints=tuple(state.solver.constraints),
            )
        )
    return out


def _assembly(values: dict[str, object]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "DisplayContinueGameInfo")
    delay = symbol_location(SYMBOLS, "DelayFrames")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    project = angr.Project(rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend":"blob","arch":ArchPcode("z80:LE:16:default"),"base_addr":0,"entry_point":location.address})
    b = location.address
    project.hook(b, Sm83XorA(b + 1), length=1)
    project.hook(b + 1, Sm83StoreAHighImmediate(0xBA, b + 3), length=2)
    project.hook(b + 3, LoadPair("h", "l", 0xC430, b + 6), length=3)
    project.hook(b + 6, LoadImmediate("b", 8, b + 8), length=2)
    project.hook(b + 8, LoadImmediate("c", 14, b + 10), length=2)
    project.hook(b + 10, AssemblyBoundary(values, 0, b + 13), length=3)
    project.hook(b + 13, LoadPair("h", "l", 0xC459, b + 16), length=3)
    project.hook(b + 16, LoadPair("d", "e", 0x5E6A, b + 19), length=3)
    project.hook(b + 19, AssemblyBoundary(values, 1, b + 22), length=3)
    project.hook(b + 22, LoadPair("h", "l", 0xC460, b + 25), length=3)
    project.hook(b + 25, LoadPair("d", "e", 0xD158, b + 28), length=3)
    project.hook(b + 28, AssemblyBoundary(values, 2, b + 31), length=3)
    project.hook(b + 31, LoadPair("h", "l", 0xC48D, b + 34), length=3)
    project.hook(b + 34, AssemblyBoundary(values, 3, b + 37), length=3)
    project.hook(b + 37, LoadPair("h", "l", 0xC4B4, b + 40), length=3)
    project.hook(b + 40, AssemblyBoundary(values, 4, b + 43), length=3)
    project.hook(b + 43, LoadPair("h", "l", 0xC4D9, b + 46), length=3)
    project.hook(b + 46, AssemblyBoundary(values, 5, b + 49), length=3)
    project.hook(b + 49, LoadImmediate("a", 1, b + 51), length=2)
    project.hook(b + 51, Sm83StoreAHighImmediate(0xBA, b + 53), length=2)
    project.hook(b + 53, LoadImmediate("c", 30, b + 55), length=2)
    project.hook(b + 55, AssemblyBoundary(values, 6, DONE), length=3)
    state = project.factory.blank_state(addr=b); set_assembly_registers(state, values); _setup(state, values)
    manager = project.factory.simulation_manager(state); manager.explore(find=DONE, num_find=1)
    assert not manager.errored and len(manager.found) == 1
    return _endpoints(manager.found, False)


def _native(values: dict[str, object]) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    fn = project.loader.find_symbol("port_display_continue_game_info")
    border = project.loader.find_symbol("port_text_box_border")
    place = project.loader.find_symbol("port_place_string")
    badges = project.loader.find_symbol("port_print_num_badges")
    owned = project.loader.find_symbol("port_print_num_owned_mons")
    play = project.loader.find_symbol("port_print_play_time")
    delay = project.loader.find_symbol("port_delay_frames")
    assert all((fn, border, place, badges, owned, play, delay))
    project.hook(border.rebased_addr, NativeBoundary(values, "border"))
    project.hook(place.rebased_addr, NativeBoundary(values, "place"))
    project.hook(badges.rebased_addr, NativeBoundary(values, "badges"))
    project.hook(owned.rebased_addr, NativeBoundary(values, "owned"))
    project.hook(play.rebased_addr, NativeBoundary(values, "play"))
    project.hook(delay.rebased_addr, NativeDelay(values))
    state = project.factory.call_state(fn.rebased_addr, NATIVE_STATE, NATIVE_MEMORY, NATIVE_MEMORY + 0x50000)
    store_native_registers(state, NATIVE_STATE, values); _setup(state, values, NATIVE_MEMORY)
    state.memory.store(NATIVE_MEMORY + 0x50000, values["observations"])
    manager = project.factory.simulation_manager(state); manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return _endpoints(manager.deadended, True)


@pytest.mark.skipif(not ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_display_continue_game_info_pathwise_equivalence() -> None:
    values = _inputs("display_continue_game_info")
    assert_pathwise_equivalent(_assembly(values), _native(values), (*REGISTERS, "memory", "calls"))
