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
from verification.harness.sm83_shims import (
    Sm83AdcRegister,
    Sm83AddRegister,
    Sm83DecRegister,
    Sm83LoadAFromImmediate,
    Sm83LoadAHighImmediate,
    Sm83LoadAImmediate,
    Sm83RlRegister,
    Sm83SlaRegister,
    Sm83SrlRegister,
    Sm83StoreAHighImmediate,
    Sm83XorRegister,
)


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification" / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
GB_STACK = 0xD000
GB_RETURN = 0xFFFF
NATIVE_STATE = 0x100000

# The wrapper lives in home ($38ac, always mapped); callfar reaches _Multiply
# in switchable bank $0d, so the emulated window exposes fixed bank 0 plus
# bank $0d at $4000-$7fff.
WINDOW_BANK = 0x0D

HRAM_PRODUCT = 0xFF95  # four bytes; hMultiplicand aliases +1 through +3
HRAM_MULTIPLIER = 0xFF99
HRAM_BUFFER = 0xFF9B  # four bytes
HRAM_LOADED_ROM_BANK = 0xFFB8

# Offsets inside struct math_multiply_state.
OFF_PRODUCT = 8
OFF_MULTIPLIER = 12
OFF_BUFFER = 13
OFF_LOADED_ROM_BANK = 17

OBSERVABLES = REGISTERS + ("product", "multiplier", "buffer", "loaded_rom_bank")


class MapperBankWrite(angr.SimProcedure):
    """SM83 ``LD [rROMB], A`` mapper write; a hardware no-op in the flat
    memory model whose net effect (the save/restore of the loaded bank) is
    modeled directly by the port."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.jump(self._next_address)


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
    product: claripy.ast.BV
    multiplier: claripy.ast.BV
    buffer: claripy.ast.BV
    loaded_rom_bank: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _opcode_length(opcode: int) -> int:
    if opcode == 0xCB:
        return 2
    if opcode in (0x01, 0x21, 0xCD, 0xEA, 0xFA):
        return 3
    if opcode in (
        0x06, 0x0E, 0x16, 0x1E, 0x26, 0x2E, 0x36, 0x3E,
        0xE0, 0xF0, 0xFE,
        0x18, 0x20, 0x28, 0x30, 0x38,
    ):
        return 2
    return 1


_CB_SHIMS = {
    0x17: Sm83RlRegister,
    0x27: Sm83SlaRegister,
    0x3F: Sm83SrlRegister,
}


def _install_sm83_hooks(
    project: angr.Project, window: bytes, start: int, end: int
) -> dict[str, int]:
    """Linearly sweep straight-line linked code and shim every SM83-only or
    flag-relevant opcode site so execution follows SM83 semantics exactly."""
    counts: dict[str, int] = {}
    position = start
    while position < end:
        opcode = window[position]
        following = position + _opcode_length(opcode)
        shim = None
        length = following - position
        if opcode == 0xE0:
            shim = Sm83StoreAHighImmediate(window[position + 1], following)
        elif opcode == 0xF0:
            shim = Sm83LoadAHighImmediate(window[position + 1], following)
        elif opcode == 0xEA:
            shim = MapperBankWrite(following)
        elif opcode == 0xFA:
            address = (window[position + 1] << 8) | window[position + 2]
            shim = Sm83LoadAImmediate(address, following)
        elif opcode == 0x3E:
            shim = Sm83LoadAFromImmediate(position + 1, following)
        elif opcode == 0x81:
            shim = Sm83AddRegister("c", following)
        elif opcode == 0x89:
            shim = Sm83AdcRegister("c", following)
        elif opcode == 0x05:
            shim = Sm83DecRegister("b", following)
        elif opcode == 0xAF:
            shim = Sm83XorRegister("a", following)
        elif opcode == 0xCB:
            register_shim = _CB_SHIMS.get(window[position + 1])
            if register_shim is not None:
                shim = register_shim("a", following)
        if shim is not None:
            project.hook(position, shim, length=length)
            counts[hex(opcode)] = counts.get(hex(opcode), 0) + 1
        position = following
    return counts


@lru_cache(maxsize=None)
def _asm_project() -> tuple[angr.Project, bytes]:
    multiply_location = symbol_location(SYMBOLS, "Multiply")
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
            "entry_point": multiply_location.address,
        },
    )
    # Wrapper (all generic Z80 encodings): no hooks expected.
    wrapper_counts = _install_sm83_hooks(
        project, window, multiply_location.address, multiply_location.address + 13
    )
    assert not wrapper_counts
    bankswitch_location = symbol_location(SYMBOLS, "Bankswitch")
    bank_counts = _install_sm83_hooks(
        project, window, bankswitch_location.address, bankswitch_location.address + 22
    )
    # ldh a,[hLoadedROMBank]; two ldh [hLoadedROMBank],a; two rROMB writes.
    assert bank_counts == {"0xf0": 1, "0xe0": 2, "0xea": 2}, bank_counts
    multiply_body_location = symbol_location(SYMBOLS, "_Multiply")
    body_counts = _install_sm83_hooks(
        project,
        window,
        multiply_body_location.address,
        multiply_body_location.address + 100,
    )
    assert body_counts == {
        "0x3e": 1,
        "0xaf": 1,
        "0xcb": 5,
        "0xe0": 18,
        "0xf0": 17,
        "0x81": 1,
        "0x89": 3,
        "0x5": 1,
    }, body_counts
    return project, window


def _inputs(tag: str, multiplier: int) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(tag)
    values["product"] = claripy.BVS(f"{tag}_product", 32)
    values["buffer"] = claripy.BVS(f"{tag}_buffer", 32)
    values["bank"] = claripy.BVS(f"{tag}_bank", 8)
    values["multiplier"] = claripy.BVV(multiplier, 8)
    return values


def _store_assembly_memory(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    state.memory.store(HRAM_PRODUCT, values["product"], endness="big")
    state.memory.store(HRAM_MULTIPLIER, values["multiplier"])
    state.memory.store(HRAM_BUFFER, values["buffer"], endness="big")
    state.memory.store(HRAM_LOADED_ROM_BANK, values["bank"])


def _assembly_endpoint(values: dict[str, claripy.ast.BV]) -> Endpoint:
    project, _ = _asm_project()
    location = symbol_location(SYMBOLS, "Multiply")
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
        product=end.memory.load(HRAM_PRODUCT, 4, endness="big"),
        multiplier=end.memory.load(HRAM_MULTIPLIER, 1),
        buffer=end.memory.load(HRAM_BUFFER, 4, endness="big"),
        loaded_rom_bank=end.memory.load(HRAM_LOADED_ROM_BANK, 1),
        constraints=tuple(end.solver.constraints),
    )


def _native_project() -> angr.Project:
    return angr.Project(NATIVE_ELF, auto_load_libs=False)


def _native_endpoint(
    project: angr.Project, values: dict[str, claripy.ast.BV]
) -> Endpoint:
    function = project.loader.find_symbol("port_math_multiply")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + OFF_PRODUCT, values["product"], endness="big")
    state.memory.store(NATIVE_STATE + OFF_MULTIPLIER, values["multiplier"])
    state.memory.store(NATIVE_STATE + OFF_BUFFER, values["buffer"], endness="big")
    state.memory.store(NATIVE_STATE + OFF_LOADED_ROM_BANK, values["bank"])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    end = manager.deadended[0]
    return Endpoint(
        **native_registers(end, NATIVE_STATE),
        product=end.memory.load(NATIVE_STATE + OFF_PRODUCT, 4, endness="big"),
        multiplier=end.memory.load(NATIVE_STATE + OFF_MULTIPLIER, 1),
        buffer=end.memory.load(NATIVE_STATE + OFF_BUFFER, 4, endness="big"),
        loaded_rom_bank=end.memory.load(NATIVE_STATE + OFF_LOADED_ROM_BANK, 1),
        constraints=tuple(end.solver.constraints),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("multiplier", range(256))
def test_math_multiply_full_pathwise_equivalence(multiplier: int) -> None:
    tag = f"math_mul_{multiplier}"
    values = _inputs(tag, multiplier)
    assembly = [_assembly_endpoint(values)]
    native_project = _native_project()
    native = [_native_endpoint(native_project, values)]
    assert_pathwise_equivalent(assembly, native, OBSERVABLES)


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_math_multiply_exact_linked_bodies() -> None:
    multiply_location = symbol_location(SYMBOLS, "Multiply")
    expected_wrapper = bytes.fromhex("e5c521417d060dcdd635c1e1c9")
    assert linked_bytes(ROM, multiply_location, len(expected_wrapper)) == expected_wrapper
    bankswitch_location = symbol_location(SYMBOLS, "Bankswitch")
    expected_bankswitch = bytes.fromhex("f0b8f578e0b8ea002001e435c5e9c178e0b8ea0020c9")
    assert linked_bytes(ROM, bankswitch_location, len(expected_bankswitch)) == expected_bankswitch
    multiply_body_location = symbol_location(SYMBOLS, "_Multiply")
    expected_body = bytes.fromhex(
        "3e0847afe095e09be09ce09de09ef099cb3fe0993020f09e4ff09881e09"
        "ef09d4ff09789e09df09c4ff09689e09cf09b4ff09589e09b05281af098"
        "cb27e098f097cb17e097f096cb17e096f095cb17e09518bbf09ee098f09"
        "de097f09ce096f09be095c9"
    )
    assert (
        linked_bytes(ROM, multiply_body_location, len(expected_body)) == expected_body
    )
