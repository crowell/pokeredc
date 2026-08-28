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
from verification.harness.rom import (
    linked_bytes, rom_window, sm83_flags_to_z80, symbol_location,
    z80_flags_to_sm83,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xEFFF
H_LOADED = 0xFFB8
R_ROMB = 0x2000
PRIZE_BANK = 0x14
PRIZE_POINTER = 0x671B
RETURN_H = 0x35
RETURN_L = 0xE4
EXPECTED = bytes.fromhex("0614211b67cdd635c3df29")


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
    callback_call: claripy.ast.BV
    hold_call: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _register_concat(state: angr.SimState) -> claripy.ast.BV:
    return claripy.Concat(*(assembly_registers(state)[name]
                            for name in REGISTERS))


class BankswitchBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        state = self.state
        state.globals["callback_call"] = claripy.Concat(
            claripy.BVV(PRIZE_BANK, 8),
            z80_flags_to_sm83(state.regs.f),
            claripy.BVV(RETURN_H, 8), claripy.BVV(RETURN_L, 8),
            state.regs.d, state.regs.e,
            claripy.BVV(PRIZE_POINTER >> 8, 8),
            claripy.BVV(PRIZE_POINTER & 0xff, 8),
            claripy.BVV(PRIZE_BANK, 8), claripy.BVV(PRIZE_BANK, 8),
        )
        callback = state.globals["callback"]
        for name in REGISTERS:
            setattr(state.regs, name,
                    sm83_flags_to_z80(callback[name]) if name == "f"
                    else callback[name])
        state.memory.store(H_LOADED, state.globals["callback_loaded"])
        state.memory.store(R_ROMB, state.globals["callback_mapper"])
        ret = state.memory.load(state.regs.sp, 2, endness="Iend_LE")
        state.regs.sp = state.regs.sp + 2
        state.regs.b = state.globals["loaded"]
        state.regs.c = state.globals["saved_f"]
        state.regs.a = state.regs.b
        state.memory.store(H_LOADED, state.globals["loaded"])
        state.memory.store(R_ROMB, state.globals["loaded"])
        self.jump(ret)


class HoldBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        if self.state.arch.name.startswith("AMD64"):
            pointer = self.state.regs.rdi
            self.state.globals["hold_call"] = claripy.Concat(*(
                self.state.memory.load(pointer + offset, 1)
                for offset in range(8)))
            for offset, name in enumerate(REGISTERS):
                self.state.memory.store(pointer + offset,
                                        self.state.globals[f"out_{name}"])
            return
        self.state.globals["hold_call"] = _register_concat(self.state)
        for name in REGISTERS:
            value = self.state.globals[f"out_{name}"]
            setattr(self.state.regs, name,
                    sm83_flags_to_z80(value) if name == "f" else value)
        self.inhibit_autoret = True
        self.jump(RETURN)


def _setup(state: angr.SimState, base: int,
           values: dict[str, claripy.ast.BV]) -> None:
    state.memory.store(base + H_LOADED, values["loaded"])
    state.memory.store(base + R_ROMB, values["romb"])
    state.memory.store(base + STACK, claripy.BVV(RETURN, 16),
                      endness="Iend_LE")
    for name in REGISTERS:
        state.globals[f"out_{name}"] = values[f"out_{name}"]
    state.globals["loaded"] = values["loaded"]
    state.globals["saved_f"] = values["f"]
    state.globals["callback"] = {
        name: values[f"callback_{name}"] for name in REGISTERS
    }
    state.globals["callback_loaded"] = values["callback_loaded"]
    state.globals["callback_mapper"] = values["callback_mapper"]


def _endpoint(state: angr.SimState, *, native: bool, base: int) -> Endpoint:
    return Endpoint(
        **(native_registers(state, NATIVE_STATE)
           if native else assembly_registers(state)),
        memory=(claripy.Concat(
            state.memory.load(base + H_LOADED, 1),
            state.memory.load(base + R_ROMB, 1),
        ) if not native else claripy.Concat(
            state.memory.load(NATIVE_STATE + 8, 1),
            state.memory.load(NATIVE_STATE + 9, 1),
        )),
        callback_call=(state.globals["callback_call"] if not native else
                       state.memory.load(NATIVE_STATE + 20, 10)),
        hold_call=state.globals["hold_call"],
        constraints=tuple(state.solver.constraints),
    )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "TextScript_GameCornerPrizeMenu")
    bankswitch = symbol_location(SYMBOLS, "Bankswitch")
    hold = symbol_location(SYMBOLS, "HoldTextDisplayOpen")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    project.hook(bankswitch.address, BankswitchBoundary(), length=22)
    project.hook(hold.address, HoldBoundary(), length=1)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.regs.sp = STACK
    _setup(state, 0, values)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN)
    assert not manager.errored and manager.found
    return [_endpoint(end, native=False, base=0) for end in manager.found]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol(
        "port_text_script_game_corner_prize_menu")
    hold = project.loader.find_symbol("port_hold_text_display_open")
    assert function is not None and hold is not None
    project.hook(hold.rebased_addr, HoldBoundary())
    state = project.factory.call_state(function.rebased_addr,
                                       NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8,
                       claripy.Concat(values["loaded"], values["romb"]))
    store_native_registers(
        state, NATIVE_STATE + 10,
        {name: values[f"callback_{name}"] for name in REGISTERS},
    )
    state.memory.store(NATIVE_STATE + 18,
                       claripy.Concat(values["callback_loaded"],
                                      values["callback_mapper"]))
    _setup(state, NATIVE_MEMORY, values)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and manager.deadended
    return [_endpoint(end, native=True, base=NATIVE_MEMORY)
            for end in manager.deadended]


@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),
                    reason="run `make red`")
def test_text_script_game_corner_prize_menu_pathwise_equivalence() -> None:
    values = symbolic_registers("game_corner_prize_menu")
    values["loaded"] = claripy.BVS("game_corner_loaded", 8)
    values["romb"] = claripy.BVS("game_corner_romb", 8)
    for name in REGISTERS:
        values[f"callback_{name}"] = (
            claripy.Concat(claripy.BVS("game_corner_callback_flags", 4),
                           claripy.BVV(0, 4))
            if name == "f" else
            claripy.BVS(f"game_corner_callback_{name}", 8)
        )
    values["callback_loaded"] = claripy.BVS("game_corner_callback_loaded", 8)
    values["callback_mapper"] = claripy.BVS("game_corner_callback_mapper", 8)
    for name in REGISTERS:
        values[f"out_{name}"] = (
            claripy.Concat(claripy.BVS("game_corner_out_flags", 4),
                           claripy.BVV(0, 4))
            if name == "f" else
            claripy.BVS(f"game_corner_out_{name}", 8)
        )
    assert_pathwise_equivalent(
        _assembly(values), _native(values),
        (*REGISTERS, "memory", "callback_call", "hold_call"),
    )
