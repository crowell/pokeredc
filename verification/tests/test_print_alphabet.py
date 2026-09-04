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
    SymbolLocation,
    collect_returns,
    linked_bytes,
    rom_window,
    symbol_location,
)
from verification.harness.sm83_shims import (
    Sm83AndRegister,
    Sm83DecRegister,
    Sm83LoadABytePreserveF,
    Sm83LoadAImmediate,
    Sm83StoreAAtHlIncrement,
    Sm83StoreAHighImmediate,
    Sm83XorA,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xFFFF
DONE = 0xEFFF

W_ALPHABET_CASE = 0xCEEB
H_AUTO = 0xFFBA
DEST_BASE = 0xC406  # hlcoord 2, 5
DEST_LEN = 0xB1  # 5 rows through 0xC4B6 inclusive
LOWER_CASE_ALPHABET = 0x679E
UPPER_CASE_ALPHABET = 0x67D6
TABLE_LEN = 56  # 45 grid bytes + 11 "@"-terminated label bytes
DELAY_FRAMES = 0x3739

EXPECTED_BODY = bytes.fromhex(
    "af e0ba faebce a7 119e67 2003 11d667 2106c4 010905 c5"
    "1a 222313 0d 20f9 011600 09 c1 05 20f0 cd5519 3e01 e0ba c3d73d"
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
    ps: claripy.ast.BV
    df: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class PlaceBoundary(angr.SimProcedure):
    """Proven PlaceString composition at the called entry: snapshot the
    loop's final registers, apply the shared arbitrary proven transition,
    continue after the replaced CALL."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next = next_address

    def run(self) -> None:  # type: ignore[override]
        regs = assembly_registers(self.state)
        self.state.globals["ps"] = claripy.Concat(
            *(regs[name] for name in REGISTERS)
        )
        from verification.harness.rom import sm83_flags_to_z80

        for name in REGISTERS:
            value = self.state.globals[f"ps_out_{name}"]
            if name == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, name, value)
        self.jump(self._next)


class DelayBoundary(angr.SimProcedure):
    """Proven Delay3 tail at the DelayFrames entry (Delay3 itself is just
    ``ld c, 3`` and executes for real): snapshot the hand-off registers,
    apply the shared arbitrary proven transition, stop."""

    def run(self) -> None:  # type: ignore[override]
        regs = assembly_registers(self.state)
        self.state.globals["df"] = claripy.Concat(
            *(regs[name] for name in REGISTERS)
        )
        from verification.harness.rom import sm83_flags_to_z80

        for name in REGISTERS:
            value = self.state.globals[f"df_out_{name}"]
            if name == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, name, value)
        self.jump(DONE)


class NativePlace(angr.SimProcedure):
    """cpu_register_state* arrives via rdi; explicit RET."""

    def run(self) -> None:  # type: ignore[override]
        state = self.state.regs.rdi
        self.state.globals["ps"] = self.state.memory.load(state, 8)
        self.state.memory.store(
            state,
            claripy.Concat(
                *(self.state.globals[f"ps_out_{name}"] for name in REGISTERS)
            ),
        )
        ret = self.state.memory.load(self.state.regs.sp, 8, endness="Iend_LE")
        self.state.regs.sp = self.state.regs.sp + 8
        self.jump(ret)


class NativeDelay(angr.SimProcedure):
    """delay_frame_state* arrives via rdi; explicit RET. Only the register
    prefix is observable: port_delay3 seeds the VBlank fields itself."""

    def run(self) -> None:  # type: ignore[override]
        state = self.state.regs.rdi
        self.state.globals["df"] = self.state.memory.load(state, 8)
        self.state.memory.store(
            state,
            claripy.Concat(
                *(self.state.globals[f"df_out_{name}"] for name in REGISTERS)
            ),
        )
        ret = self.state.memory.load(self.state.regs.sp, 8, endness="Iend_LE")
        self.state.regs.sp = self.state.regs.sp + 8
        self.jump(ret)


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for pre in ("ps", "df"):
        for name in REGISTERS:
            if name == "f":
                values[f"{pre}_out_{name}"] = claripy.Concat(
                    claripy.BVS(f"{prefix}_{pre}_out_flags", 4),
                    claripy.BVV(0, 4),
                )
            else:
                values[f"{pre}_out_{name}"] = claripy.BVS(
                    f"{prefix}_{pre}_out_{name}", 8
                )
    values["alphabet_case"] = claripy.BVS(f"{prefix}_alphabet_case", 8)
    values["auto_in"] = claripy.BVS(f"{prefix}_auto_in", 8)
    values["dest"] = claripy.Concat(
        *(claripy.BVS(f"{prefix}_dest_{i}", 8) for i in range(DEST_LEN))
    )
    return values


def _tables() -> bytes:
    location = SymbolLocation(1, LOWER_CASE_ALPHABET)
    data = linked_bytes(
        ROM, location, (UPPER_CASE_ALPHABET - LOWER_CASE_ALPHABET) + TABLE_LEN
    )
    gap = UPPER_CASE_ALPHABET - LOWER_CASE_ALPHABET
    assert data[:9] == bytes.fromhex("a0 a1 a2 a3 a4 a5 a6 a7 a8")
    assert data[45:gap] == bytes.fromhex("94 8f 8f 84 91 7f 82 80 92 84 50")
    assert data[gap:gap + 9] == bytes.fromhex("80 81 82 83 84 85 86 87 88")
    assert data[gap + 45:] == bytes.fromhex("ab ae b6 a4 b1 7f a2 a0 b2 a4 50")
    return data


def _setup(state: angr.SimState, values: dict[str, claripy.ast.BV], base: int = 0) -> None:
    state.memory.store(base + W_ALPHABET_CASE, values["alphabet_case"])
    state.memory.store(base + H_AUTO, values["auto_in"])
    state.memory.store(base + DEST_BASE, values["dest"])
    tables = _tables()
    state.memory.store(base + LOWER_CASE_ALPHABET, bytes(tables))
    state.globals["ps"] = claripy.BVV(0, 8 * 8)
    state.globals["df"] = claripy.BVV(0, 8 * 8)
    for key, value in values.items():
        if key.startswith(("ps_out_", "df_out_")):
            state.globals[key] = value


def _memory(state: angr.SimState, base: int = 0) -> claripy.ast.BV:
    return claripy.Concat(
        state.memory.load(base + DEST_BASE, DEST_LEN),
        state.memory.load(base + H_AUTO, 1),
        state.memory.load(base + W_ALPHABET_CASE, 1),
    )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "PrintAlphabet")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY
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
    b = location.address
    project.hook(b + 0, Sm83XorA(b + 1), length=1)
    project.hook(b + 1, Sm83StoreAHighImmediate(0xBA, b + 3), length=2)
    project.hook(b + 3, Sm83LoadAImmediate(W_ALPHABET_CASE, b + 6), length=3)
    project.hook(b + 6, Sm83AndRegister("a", b + 7), length=1)
    project.hook(b + 23, Sm83StoreAAtHlIncrement(b + 24), length=1)
    project.hook(b + 26, Sm83DecRegister("c", b + 27), length=1)
    project.hook(b + 34, Sm83DecRegister("b", b + 35), length=1)
    project.hook(b + 37, PlaceBoundary(b + 40), length=3)
    project.hook(b + 40, Sm83LoadABytePreserveF(b + 41, b + 42), length=2)
    project.hook(b + 42, Sm83StoreAHighImmediate(0xBA, b + 44), length=2)
    project.hook(DELAY_FRAMES, DelayBoundary(), length=3)
    state = project.factory.blank_state(addr=b)
    set_assembly_registers(state, values)
    _setup(state, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=8)
    assert not manager.errored
    assert len(manager.found) == 2
    return [
        Endpoint(
            **assembly_registers(end),
            memory=_memory(end),
            ps=end.globals["ps"],
            df=end.globals["df"],
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_print_alphabet")
    place = project.loader.find_symbol("port_place_string")
    delay = project.loader.find_symbol("port_delay_frames")
    assert function is not None
    assert place is not None
    assert delay is not None
    project.hook(place.rebased_addr, NativePlace())
    project.hook(delay.rebased_addr, NativeDelay())
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, values, NATIVE_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    # -O2 may fold the case branch into a cmov single path with ITE
    # observables; the two assembly paths each overlap it below.
    assert 1 <= len(manager.deadended) <= 2
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=_memory(end, NATIVE_MEMORY),
            ps=end.globals["ps"],
            df=end.globals["df"],
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_print_alphabet_pathwise_equivalence() -> None:
    values = _inputs("print_alphabet")
    assert_pathwise_equivalent(
        _assembly(values), _native(values), (*REGISTERS, "memory", "ps", "df")
    )
