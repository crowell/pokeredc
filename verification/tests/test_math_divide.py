from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
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
    collect_returns,
    linked_bytes,
    rom_window,
    symbol_location,
)
from verification.harness.sm83_sweep import install_sm83_hooks


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification" / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
GB_STACK = 0xD000
GB_RETURN = 0xFFFF
NATIVE_STATE = 0x100000

# The wrapper lives in home ($38b9); homecall reaches _Divide in switchable
# bank $0d, so the emulated window exposes fixed bank 0 plus bank $0d at
# $4000-$7fff.
WINDOW_BANK = 0x0D

HRAM_DIVIDEND = 0xFF95  # four bytes; hQuotient aliases the same window
HRAM_DIVISOR = 0xFF99  # hRemainder aliases this byte
HRAM_BUFFER = 0xFF9A  # five hDivideBuffer bytes (no padding byte here)
HRAM_LOADED_ROM_BANK = 0xFFB8

# Offsets inside struct math_divide_state.
OFF_DIVIDEND = 8
OFF_DIVISOR = 12
OFF_BUFFER = 13
OFF_LOADED_ROM_BANK = 18

OBSERVABLES = REGISTERS + ("dividend", "divisor", "buffer", "loaded_rom_bank")

# Structural execution vectors: every real caller width b in {1,2,3,4} with
# divisor and dividend values chosen so each distinct loop shape of _Divide
# runs end to end: multi-pass subtraction, divisor one, boundary equality,
# zero dividend, the b==1 short circuit, and multi-window quotient carry-out.
# Registers except B stay fully symbolic in every vector.
VECTORS = (
    (2, 10, 0x00000063),
    (2, 1, 0x00000005),
    (2, 255, 0x000001FF),
    (2, 200, 0x000000C8),
    (2, 207, 0x00000000),
    (1, 60, 0x0000007B),
    (3, 7, 0x00123456),
    (3, 89, 0x00010000),
    (4, 100, 0x00123456),
    (4, 17, 0x00ABCDEF),
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
    dividend: claripy.ast.BV
    divisor: claripy.ast.BV
    buffer: claripy.ast.BV
    loaded_rom_bank: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


@lru_cache(maxsize=None)
def _asm_project() -> angr.Project:
    divide_location = symbol_location(SYMBOLS, "Divide")
    window_stream = rom_window(ROM, WINDOW_BANK)
    window = window_stream.getvalue()
    project = angr.Project(
        window_stream,
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": divide_location.address,
        },
    )
    wrapper_counts = install_sm83_hooks(
        project, window, divide_location.address, divide_location.address + 26
    )
    # ldh a,[hLoadedROMBank]; ld a,$0d; two ldh [..],a; two rROMB writes.
    assert wrapper_counts == {
        "0xf0": 1,
        "0x3e": 1,
        "0xe0": 2,
        "0xea": 2,
    }, wrapper_counts
    divide_body_location = symbol_location(SYMBOLS, "_Divide")
    body_counts = install_sm83_hooks(
        project,
        window,
        divide_body_location.address,
        divide_body_location.address + 136,
    )
    assert body_counts == {
        "0xaf": 2,
        "0x3e": 2,
        "0xfe": 2,
        "0xf0": 20,
        "0xe0": 24,
        "0xcb": 6,
        "0x91": 1,
        "0x99": 1,
        "0x5": 1,
        "0x1d": 1,
        "0x3c": 1,
    }, body_counts
    return project


def _inputs(tag: str, width: int) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(tag)
    values["b"] = claripy.BVV(width, 8)
    values["dividend"] = claripy.BVS(f"{tag}_dividend", 32)
    values["buffer"] = claripy.BVS(f"{tag}_buffer", 40)
    values["bank"] = claripy.BVS(f"{tag}_bank", 8)
    return values


def _store_assembly_memory(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    state.memory.store(HRAM_DIVIDEND, values["dividend"], endness="big")
    state.memory.store(HRAM_DIVISOR, values["divisor"])
    state.memory.store(HRAM_BUFFER, values["buffer"], endness="big")
    state.memory.store(HRAM_LOADED_ROM_BANK, values["bank"])


def _assembly_endpoint(values: dict[str, claripy.ast.BV]) -> Endpoint:
    project = _asm_project()
    location = symbol_location(SYMBOLS, "Divide")
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    _store_assembly_memory(state, values)
    state.regs.sp = claripy.BVV(GB_STACK, 16)
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    assert len(returned) == 1
    end = returned[0]
    return Endpoint(
        **assembly_registers(end),
        dividend=end.memory.load(HRAM_DIVIDEND, 4, endness="big"),
        divisor=end.memory.load(HRAM_DIVISOR, 1),
        buffer=end.memory.load(HRAM_BUFFER, 5, endness="big"),
        loaded_rom_bank=end.memory.load(HRAM_LOADED_ROM_BANK, 1),
        constraints=tuple(end.solver.constraints),
    )


@lru_cache(maxsize=None)
def _native_project() -> angr.Project:
    return angr.Project(NATIVE_ELF, auto_load_libs=False)


def _native_endpoint(project: angr.Project, values: dict[str, claripy.ast.BV]) -> Endpoint:
    function = project.loader.find_symbol("port_math_divide")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + OFF_DIVIDEND, values["dividend"], endness="big")
    state.memory.store(NATIVE_STATE + OFF_DIVISOR, values["divisor"])
    state.memory.store(NATIVE_STATE + OFF_BUFFER, values["buffer"], endness="big")
    state.memory.store(NATIVE_STATE + OFF_LOADED_ROM_BANK, values["bank"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    end = manager.deadended[0]
    return Endpoint(
        **native_registers(end, NATIVE_STATE),
        dividend=end.memory.load(NATIVE_STATE + OFF_DIVIDEND, 4, endness="big"),
        divisor=end.memory.load(NATIVE_STATE + OFF_DIVISOR, 1),
        buffer=end.memory.load(NATIVE_STATE + OFF_BUFFER, 5, endness="big"),
        loaded_rom_bank=end.memory.load(NATIVE_STATE + OFF_LOADED_ROM_BANK, 1),
        constraints=tuple(end.solver.constraints),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("vector", VECTORS)
def test_math_divide_full_pathwise_equivalence(vector: tuple[int, int, int]) -> None:
    width, divisor, dividend = vector
    tag = f"math_div_{width}_{divisor}_{dividend}"
    values = _inputs(tag, width)
    values["divisor"] = claripy.BVV(divisor, 8)
    values["dividend"] = claripy.BVV(dividend, 32)
    assembly = [_assembly_endpoint(values)]
    native = [_native_endpoint(_native_project(), values)]
    assert_pathwise_equivalent(assembly, native, OBSERVABLES)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_math_divide_exact_linked_bodies() -> None:
    divide_location = symbol_location(SYMBOLS, "Divide")
    expected_wrapper = bytes.fromhex(
        "e5d5c5f0b8f53e0de0b8ea0020cda57df1e0b8ea0020c1d1e1c9"
    )
    assert linked_bytes(ROM, divide_location, len(expected_wrapper)) == expected_wrapper
    divide_body_location = symbol_location(SYMBOLS, "_Divide")
    expected_body = bytes.fromhex(
        "afe09ae09be09ce09de09e3e095ff09a4ff0969157f0994ff09599380c"
        "e0957ae096f09e3ce09e18e578fe012845f09ecb27e09ef09dcb17e09d"
        "f09ccb17e09cf09bcb17e09b1d20163e085ff09ae099afe09af096e095f"
        "097e096f098e0977bfe01200105f099cb3fe099f09acb1fe09a189bf096"
        "e099f09ee098f09de097f09ce096f09be095c9"
    )
    assert linked_bytes(ROM, divide_body_location, len(expected_body)) == expected_body
