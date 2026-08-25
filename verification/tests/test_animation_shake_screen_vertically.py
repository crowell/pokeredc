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
from verification.harness.rom import collect_returns, linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import (
    Sm83LoadAHighImmediate,
    Sm83LoadAImmediate,
    Sm83StoreAHighImmediate,
    Sm83StoreAImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
STACK = 0xD000
RETURN = 0xFFFF

WRAPPER_EXPECTED = bytes.fromhex("3e21c36d3e")
PREDEF_EXPECTED = bytes.fromhex(
    "ea4eccf0b8ea12cff53e13e0b8ea0020cd497efab7d0e0b8ea0020"
    "118d3ed5e9f1e0b8ea0020c9"
)
W_PREDEF_ID = 0xCC4E
W_PREDEF_HL = 0xCC4F
W_PREDEF_DE = 0xCC51
W_PREDEF_BC = 0xCC53
W_PREDEF_PARENT = 0xCF12
W_PREDEF_BANK = 0xD0B7
DISABLE_WY_UPDATE = 0xD0A0
MUTATE_WY = 0xFF96
WY = 0xFF4A
H_LOADED_ROM_BANK = 0xFFB8
R_ROMB = 0x2000
SAVED = (
    W_PREDEF_HL,
    W_PREDEF_HL + 1,
    W_PREDEF_DE,
    W_PREDEF_DE + 1,
    W_PREDEF_BC,
    W_PREDEF_BC + 1,
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
    state: claripy.ast.BV
    target_call: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _assembly_state(state: angr.SimState) -> claripy.ast.BV:
    memory = state.memory
    return claripy.Concat(
        *(memory.load(address, 1) for address in SAVED),
        memory.load(DISABLE_WY_UPDATE, 1),
        memory.load(MUTATE_WY, 1),
        memory.load(WY, 1),
        memory.load(W_PREDEF_ID, 1),
        memory.load(W_PREDEF_PARENT, 1),
        memory.load(W_PREDEF_BANK, 1),
        memory.load(H_LOADED_ROM_BANK, 1),
        memory.load(R_ROMB, 1),
    )


class AssemblyPointerSummary(angr.SimProcedure):
    """Complete proven GetPredefPointer transition for predef ID $21."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:
        registers = self.state.regs
        memory = self.state.memory
        for address, value in zip(
            SAVED,
            (registers.h, registers.l, registers.d, registers.e, registers.b, registers.c),
        ):
            memory.store(address, value)
        memory.store(W_PREDEF_BANK, claripy.BVV(0x12, 8))
        registers.a = claripy.BVV(0x40, 8)
        registers.f = claripy.BVV(0, 8)
        registers.d = claripy.BVV(0x7E, 8)
        registers.e = claripy.BVV(0xDE, 8)
        registers.h = claripy.BVV(0x40, 8)
        registers.l = claripy.BVV(0xFF, 8)
        self.jump(self._next_address)


class AssemblyVerticalTarget(angr.SimProcedure):
    """Arbitrary matching transition of the completely proved vertical predef."""

    def run(self) -> None:
        self.state.globals["target_call"] = claripy.Concat(
            *(assembly_registers(self.state)[name] for name in REGISTERS),
            _assembly_state(self.state),
        )
        for name in REGISTERS:
            setattr(self.state.regs, name, self.state.globals[f"target_out_{name}"])
        self.state.memory.store(
            DISABLE_WY_UPDATE, self.state.globals["target_out_disable"]
        )
        self.state.memory.store(MUTATE_WY, self.state.globals["target_out_mutate"])
        self.state.memory.store(WY, self.state.globals["target_out_wy"])
        return_address = self.state.memory.load(
            self.state.regs.sp, 2, endness="Iend_LE"
        )
        self.state.regs.sp += 2
        self.jump(return_address)


class NativeVerticalTarget(angr.SimProcedure):
    def run(self) -> None:
        address = self.state.regs.rdi
        self.state.globals["target_call"] = self.state.memory.load(address, 22)
        self.state.memory.store(
            address,
            claripy.Concat(
                *(self.state.globals[f"target_out_{name}"] for name in REGISTERS)
            ),
        )
        self.state.memory.store(address + 14, self.state.globals["target_out_disable"])
        self.state.memory.store(address + 15, self.state.globals["target_out_mutate"])
        self.state.memory.store(address + 16, self.state.globals["target_out_wy"])


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for name in (
        "disable",
        "mutate",
        "wy",
        "loaded_bank",
        "rom_bank",
        "target_out_disable",
        "target_out_mutate",
        "target_out_wy",
    ):
        values[name] = claripy.BVS(f"{prefix}_{name}", 8)
    for name in REGISTERS:
        if name == "f":
            values[f"target_out_{name}"] = claripy.Concat(
                claripy.BVS(f"{prefix}_target_out_flags", 4), claripy.BVV(0, 4)
            )
        else:
            values[f"target_out_{name}"] = claripy.BVS(
                f"{prefix}_target_out_{name}", 8
            )
    return values


def _setup_globals(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    state.globals["target_call"] = claripy.BVV(0, 22 * 8)
    for name in REGISTERS:
        state.globals[f"target_out_{name}"] = values[f"target_out_{name}"]
    for name in ("disable", "mutate", "wy"):
        state.globals[f"target_out_{name}"] = values[f"target_out_{name}"]


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    wrapper = symbol_location(SYMBOLS, "AnimationShakeScreenVertically")
    predef = symbol_location(SYMBOLS, "Predef")
    target = symbol_location(SYMBOLS, "PredefShakeScreenVertically")
    assert linked_bytes(ROM, wrapper, len(WRAPPER_EXPECTED)) == WRAPPER_EXPECTED
    assert linked_bytes(ROM, predef, len(PREDEF_EXPECTED)) == PREDEF_EXPECTED
    project = angr.Project(
        rom_window(ROM, wrapper.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": wrapper.address,
        },
    )
    base = predef.address
    project.hook(base, Sm83StoreAImmediate(W_PREDEF_ID, base + 3), length=3)
    project.hook(base + 3, Sm83LoadAHighImmediate(0xB8, base + 5), length=2)
    project.hook(base + 5, Sm83StoreAImmediate(W_PREDEF_PARENT, base + 8), length=3)
    project.hook(base + 11, Sm83StoreAHighImmediate(0xB8, base + 13), length=2)
    project.hook(base + 13, Sm83StoreAImmediate(R_ROMB, base + 16), length=3)
    project.hook(base + 16, AssemblyPointerSummary(base + 19), length=3)
    project.hook(base + 19, Sm83LoadAImmediate(W_PREDEF_BANK, base + 22), length=3)
    project.hook(base + 22, Sm83StoreAHighImmediate(0xB8, base + 24), length=2)
    project.hook(base + 24, Sm83StoreAImmediate(R_ROMB, base + 27), length=3)
    project.hook(base + 33, Sm83StoreAHighImmediate(0xB8, base + 35), length=2)
    project.hook(base + 35, Sm83StoreAImmediate(R_ROMB, base + 38), length=3)
    project.hook(target.address, AssemblyVerticalTarget(), length=1)

    state = project.factory.blank_state(addr=wrapper.address)
    set_assembly_registers(state, values)
    state.regs.sp = claripy.BVV(STACK, 16)
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    state.memory.store(DISABLE_WY_UPDATE, values["disable"])
    state.memory.store(MUTATE_WY, values["mutate"])
    state.memory.store(WY, values["wy"])
    state.memory.store(H_LOADED_ROM_BANK, values["loaded_bank"])
    state.memory.store(R_ROMB, values["rom_bank"])
    _setup_globals(state, values)
    ends = collect_returns(project, state, RETURN)
    assert len(ends) == 1
    return [
        Endpoint(
            **assembly_registers(end),
            state=_assembly_state(end),
            target_call=end.globals["target_call"],
            constraints=tuple(end.solver.constraints),
        )
        for end in ends
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_animation_shake_screen_vertically")
    target = project.loader.find_symbol("port_predef_shake_screen_vertically_private")
    assert function is not None and target is not None
    project.hook(target.rebased_addr, NativeVerticalTarget())
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 14, values["disable"])
    state.memory.store(NATIVE_STATE + 15, values["mutate"])
    state.memory.store(NATIVE_STATE + 16, values["wy"])
    state.memory.store(NATIVE_STATE + 20, values["loaded_bank"])
    state.memory.store(NATIVE_STATE + 21, values["rom_bank"])
    _setup_globals(state, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            state=end.memory.load(NATIVE_STATE + 8, 14),
            target_call=end.globals["target_call"],
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_animation_shake_screen_vertically_wrapper_pathwise_equivalence() -> None:
    values = _inputs("animation_shake_screen_vertically")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "state", "target_call"),
    )
