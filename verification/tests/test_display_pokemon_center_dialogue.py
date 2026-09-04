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
)
from verification.harness.sm83_shims import (
    Sm83LoadAHighImmediate, Sm83StoreAHighImmediate,
    Sm83StoreAImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xEFFF
H_ITEM_PRICE = 0xFF8B
H_LOADED = 0xFFB8
R_ROMB = 0x2000
PRIVATE_POINTER = 0x705D
EXPECTED = bytes.fromhex(
    "afe08be08ce08d23f0b8f53e01e0b8ea0020cde66ff1e0b8ea0020c3d629"
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
    private_call: claripy.ast.BV
    after_call: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _register_concat(state: angr.SimState) -> claripy.ast.BV:
    return claripy.Concat(*(assembly_registers(state)[name]
                            for name in REGISTERS))


class PrivateBoundary(angr.SimProcedure):
    def run(self, register_address=None) -> None:  # type: ignore[override]
        if self.state.arch.name.startswith("AMD64"):
            pointer = self.state.regs.rdi
            self.state.globals["private_call"] = claripy.Concat(*(
                self.state.memory.load(pointer + offset, 1)
                for offset in range(8)))
            self.state.memory.store(pointer + 6,
                                    claripy.BVV(PRIVATE_POINTER >> 8, 8))
            self.state.memory.store(pointer + 7,
                                    claripy.BVV(PRIVATE_POINTER & 0xff, 8))
            return
        self.state.globals["private_call"] = _register_concat(self.state)
        self.state.regs.h = claripy.BVV(PRIVATE_POINTER >> 8, 8)
        self.state.regs.l = claripy.BVV(PRIVATE_POINTER & 0xff, 8)
        ret = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp = self.state.regs.sp + 2
        self.jump(ret)


class AfterBoundary(angr.SimProcedure):
    def run(self, register_address=None, memory_address=None) -> None:  # type: ignore[override]
        if self.state.arch.name.startswith("AMD64"):
            pointer = self.state.regs.rdi
            self.state.globals["after_call"] = claripy.Concat(*(
                self.state.memory.load(pointer + offset, 1)
                for offset in range(8)))
            for offset, name in enumerate(REGISTERS):
                self.state.memory.store(pointer + offset,
                                        self.state.globals[f"out_{name}"])
            return
        self.state.globals["after_call"] = _register_concat(self.state)
        for name in REGISTERS:
            value = self.state.globals[f"out_{name}"]
            setattr(self.state.regs, name,
                    sm83_flags_to_z80(value) if name == "f" else value)
        self.inhibit_autoret = True
        self.jump(RETURN)


def _setup(state: angr.SimState, base: int,
           values: dict[str, claripy.ast.BV]) -> None:
    state.memory.store(base + H_ITEM_PRICE,
                       claripy.Concat(values["price0"], values["price1"],
                                      values["price2"]))
    state.memory.store(base + H_LOADED, values["loaded"])
    state.memory.store(base + R_ROMB, values["romb"])
    state.memory.store(base + STACK, claripy.BVV(RETURN, 16),
                      endness="Iend_LE")
    for name in REGISTERS:
        state.globals[f"out_{name}"] = values[f"out_{name}"]


def _endpoint(state: angr.SimState, *, native: bool, base: int) -> Endpoint:
    return Endpoint(
        **(native_registers(state, NATIVE_STATE)
           if native else assembly_registers(state)),
        memory=claripy.Concat(
            state.memory.load(base + H_ITEM_PRICE, 3),
            state.memory.load(base + H_LOADED, 1),
            state.memory.load(base + R_ROMB, 1),
        ) if not native else claripy.Concat(
            state.memory.load(NATIVE_STATE + 8, 3),
            state.memory.load(NATIVE_STATE + 11, 1),
            state.memory.load(NATIVE_STATE + 12, 1),
        ),
        private_call=state.globals["private_call"],
        after_call=state.globals["after_call"],
        constraints=tuple(state.solver.constraints),
    )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "DisplayPokemonCenterDialogue")
    private = symbol_location(SYMBOLS, "DisplayPokemonCenterDialogue_")
    after = symbol_location(SYMBOLS, "AfterDisplayingTextID")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    project = angr.Project(
        rom_window(ROM, private.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    project.hook(private.address, PrivateBoundary(), length=1)
    project.hook(after.address, AfterBoundary(), length=1)
    for offset, address in ((1, H_ITEM_PRICE), (3, H_ITEM_PRICE + 1),
                            (5, H_ITEM_PRICE + 2), (13, H_LOADED),
                            (22, H_LOADED)):
        project.hook(location.address + offset,
                     Sm83StoreAHighImmediate(address,
                                             location.address + offset + 2),
                     length=2)
    project.hook(location.address + 15,
                 Sm83StoreAImmediate(R_ROMB, location.address + 18), length=3)
    project.hook(location.address + 24,
                 Sm83StoreAImmediate(R_ROMB, location.address + 27), length=3)
    project.hook(location.address + 8,
                 Sm83LoadAHighImmediate(H_LOADED, location.address + 10),
                 length=2)
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
    function = project.loader.find_symbol("port_display_pokemon_center_dialogue")
    private = project.loader.find_symbol("port_display_pokemon_center_dialogue_private")
    after = project.loader.find_symbol("port_after_displaying_text_id")
    assert function is not None and private is not None and after is not None
    project.hook(private.rebased_addr, PrivateBoundary())
    project.hook(after.rebased_addr, AfterBoundary())
    state = project.factory.call_state(function.rebased_addr,
                                       NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8,
                       claripy.Concat(values["price0"], values["price1"],
                                      values["price2"], values["loaded"],
                                      values["romb"]))
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
def test_display_pokemon_center_dialogue_pathwise_equivalence() -> None:
    values = symbolic_registers("display_pokemon_center_dialogue")
    for name in ("price0", "price1", "price2", "loaded", "romb"):
        values[name] = claripy.BVS(f"display_pokemon_center_{name}", 8)
    for name in REGISTERS:
        values[f"out_{name}"] = (
            claripy.Concat(claripy.BVS("display_pokemon_center_out_flags", 4),
                           claripy.BVV(0, 4))
            if name == "f" else
            claripy.BVS(f"display_pokemon_center_out_{name}", 8)
        )
    assert_pathwise_equivalent(
        _assembly(values), _native(values),
        (*REGISTERS, "memory", "private_call", "after_call"),
    )
