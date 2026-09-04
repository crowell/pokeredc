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
from verification.harness.sm83_shims import (
    Sm83LoadABytePreserveF, Sm83LoadAHighImmediate,
    Sm83StoreAHighImmediate, Sm83StoreAImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xEFFF
W_TEXTBOX = 0xD125
W_LIST_MENU = 0xCF94
W_UPDATE = 0xCFCB
W_ITEM_POINTER = 0xD128
W_ITEM_LIST = 0xCF7B
W_LIST_SCROLL = 0xCC36
W_SAVED_SCROLL = 0xD07E
W_BOUGHT_SOLD = 0xCF0A
W_CURRENT_MENU = 0xCC26
W_PLAYER_MON = 0xCC2F
W_PRINT_PRICES = 0xCF93
POKEMART_GREETING = 0x2A55
POKEMART_PRIVATE = 0x6C20
EXPECTED = bytes.fromhex(
    "e521552acd493ce123cd5a2a3e02ea94cff0b8f53e01e0b8ea0020"
    "cd206cf1e0b8ea0020c3d629"
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
    print_call: claripy.ast.BV
    load_call: claripy.ast.BV
    private_call: claripy.ast.BV
    after_call: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _register_concat(state: angr.SimState) -> claripy.ast.BV:
    return claripy.Concat(*(assembly_registers(state)[name]
                            for name in REGISTERS))


class PrintBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        if self.state.arch.name.startswith("AMD64"):
            pointer = self.state.regs.rdi
            memory = self.state.regs.rsi
            self.state.globals["print_call"] = claripy.Concat(*(
                self.state.memory.load(pointer + offset, 1)
                for offset in range(8)))
            self.state.memory.store(memory + W_TEXTBOX, claripy.BVV(1, 8))
            self.state.memory.store(pointer + 2, claripy.BVV(0xC4, 8))
            self.state.memory.store(pointer + 3, claripy.BVV(0xB9, 8))
            return
        self.state.globals["print_call"] = _register_concat(self.state)
        self.state.memory.store(W_TEXTBOX, claripy.BVV(1, 8))
        self.state.regs.b = claripy.BVV(0xC4, 8)
        self.state.regs.c = claripy.BVV(0xB9, 8)
        ret = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp = self.state.regs.sp + 2
        self.jump(ret)


class LoadBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        if self.state.arch.name.startswith("AMD64"):
            pointer = self.state.regs.rdi
            memory = self.state.regs.rsi
            self.state.globals["load_call"] = claripy.Concat(*(
                self.state.memory.load(pointer + offset, 1)
                for offset in range(8)))
            h = self.state.memory.load(pointer + 6, 1)
            l = self.state.memory.load(pointer + 7, 1)
            self.state.memory.store(pointer + 8, claripy.BVV(1, 8))
            self.state.memory.store(pointer + 9, h)
            self.state.memory.store(pointer + 10, l)
            for index in range(4):
                self.state.memory.store(memory + W_ITEM_LIST + index,
                                        self.state.globals[f"list_{index}"])
            for offset, name in enumerate(REGISTERS):
                value = self.state.globals[f"load_post_{name}"]
                self.state.memory.store(pointer + offset, value)
            self.state.memory.store(memory + W_UPDATE, claripy.BVV(1, 8))
            self.state.memory.store(memory + W_ITEM_POINTER, h)
            self.state.memory.store(memory + W_ITEM_POINTER + 1, l)
            return
        self.state.globals["load_call"] = _register_concat(self.state)
        h = self.state.regs.h
        l = self.state.regs.l
        self.state.memory.store(W_UPDATE, claripy.BVV(1, 8))
        self.state.memory.store(W_ITEM_POINTER, h)
        self.state.memory.store(W_ITEM_POINTER + 1, l)
        for index in range(4):
            self.state.memory.store(W_ITEM_LIST + index,
                                    self.state.globals[f"list_{index}"])
        for name in REGISTERS:
            value = self.state.globals[f"load_post_{name}"]
            setattr(self.state.regs, name,
                    sm83_flags_to_z80(value) if name == "f" else value)
        ret = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp = self.state.regs.sp + 2
        self.jump(ret)


class PrivateBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        if self.state.arch.name.startswith("AMD64"):
            pointer = self.state.regs.rdi
            self.state.globals["private_call"] = claripy.Concat(*(
                self.state.memory.load(pointer + offset, 1)
                for offset in range(15)))
            list_scroll = self.state.memory.load(pointer + 8, 1)
            self.state.memory.store(pointer + 0, claripy.BVV(0x13, 8))
            self.state.memory.store(pointer + 1, claripy.BVV(0, 8))
            self.state.memory.store(pointer + 8, claripy.BVV(0, 8))
            self.state.memory.store(pointer + 9, list_scroll)
            for offset, value in ((10, 0), (11, 0), (12, 0), (13, 1),
                                  (14, 0x13)):
                self.state.memory.store(pointer + offset,
                                        claripy.BVV(value, 8))
            return
        old_list_scroll = self.state.globals["private_list_scroll"]
        self.state.globals["private_call"] = claripy.Concat(
            _register_concat(self.state),
            self.state.globals["private_list_scroll"],
            self.state.globals["private_saved_scroll"],
            self.state.globals["private_bought_sold"],
            self.state.globals["private_current_menu"],
            self.state.globals["private_player_mon"],
            self.state.globals["private_print_prices"],
            self.state.globals["private_textbox"],
        )
        self.state.regs.a = claripy.BVV(0x13, 8)
        self.state.regs.f = claripy.BVV(0, 8)
        self.state.globals["private_list_scroll"] = claripy.BVV(0, 8)
        self.state.globals["private_saved_scroll"] = old_list_scroll
        self.state.globals["private_bought_sold"] = claripy.BVV(0, 8)
        self.state.globals["private_current_menu"] = claripy.BVV(0, 8)
        self.state.globals["private_player_mon"] = claripy.BVV(0, 8)
        self.state.globals["private_print_prices"] = claripy.BVV(1, 8)
        self.state.globals["private_textbox"] = claripy.BVV(0x13, 8)
        self.state.memory.store(W_LIST_SCROLL, claripy.BVV(0, 8))
        self.state.memory.store(W_SAVED_SCROLL, old_list_scroll)
        self.state.memory.store(W_BOUGHT_SOLD, claripy.BVV(0, 8))
        self.state.memory.store(W_CURRENT_MENU, claripy.BVV(0, 8))
        self.state.memory.store(W_PLAYER_MON, claripy.BVV(0, 8))
        self.state.memory.store(W_PRINT_PRICES, claripy.BVV(1, 8))
        self.state.memory.store(W_TEXTBOX, claripy.BVV(0x13, 8))
        ret = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp = self.state.regs.sp + 2
        self.jump(ret)


class AfterBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
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
    for address, name in ((W_TEXTBOX, "textbox"), (W_LIST_MENU, "list_menu"),
                          (W_UPDATE, "update"), (W_LIST_SCROLL, "private_list_scroll"),
                          (W_SAVED_SCROLL, "private_saved_scroll"),
                          (W_BOUGHT_SOLD, "private_bought_sold"),
                          (W_CURRENT_MENU, "private_current_menu"),
                          (W_PLAYER_MON, "private_player_mon"),
                          (W_PRINT_PRICES, "private_print_prices")):
        state.memory.store(base + address, values[name])
    state.memory.store(base + W_ITEM_POINTER,
                       claripy.Concat(values["item_ptr_h"], values["item_ptr_l"]))
    state.memory.store(base + W_ITEM_LIST,
                       claripy.Concat(*(values[f"list_{i}"] for i in range(4))))
    state.memory.store(base + STACK, claripy.BVV(RETURN, 16),
                      endness="Iend_LE")
    state.memory.store(base + 0xFFB8, values["loaded"])
    state.memory.store(base + 0x2000, values["romb"])
    state.globals["private_list_scroll"] = values["private_list_scroll"]
    state.globals["private_saved_scroll"] = values["private_saved_scroll"]
    state.globals["private_bought_sold"] = values["private_bought_sold"]
    state.globals["private_current_menu"] = values["private_current_menu"]
    state.globals["private_player_mon"] = values["private_player_mon"]
    state.globals["private_print_prices"] = values["private_print_prices"]
    state.globals["private_textbox"] = values["private_textbox"]
    for name in REGISTERS:
        state.globals[f"load_post_{name}"] = values[f"load_post_{name}"]
        state.globals[f"out_{name}"] = values[f"out_{name}"]
    for index in range(4):
        state.globals[f"list_{index}"] = values[f"list_{index}"]


def _endpoint(state: angr.SimState, *, native: bool) -> Endpoint:
    if native:
        memory = claripy.Concat(
            state.memory.load(NATIVE_MEMORY + W_TEXTBOX, 1),
            state.memory.load(NATIVE_MEMORY + W_LIST_MENU, 1),
            state.memory.load(NATIVE_MEMORY + W_UPDATE, 1),
            state.memory.load(NATIVE_MEMORY + W_ITEM_POINTER, 2),
            state.memory.load(NATIVE_MEMORY + W_ITEM_LIST, 4),
            state.memory.load(NATIVE_STATE + 11, 7),
            state.memory.load(NATIVE_STATE + 8, 2),
        )
        private_call = state.globals["private_call"]
    else:
        memory = claripy.Concat(
            state.memory.load(W_TEXTBOX, 1), state.memory.load(W_LIST_MENU, 1),
            state.memory.load(W_UPDATE, 1), state.memory.load(W_ITEM_POINTER, 2),
            state.memory.load(W_ITEM_LIST, 4),
            state.memory.load(W_LIST_SCROLL, 1), state.memory.load(W_SAVED_SCROLL, 1),
            state.memory.load(W_BOUGHT_SOLD, 1), state.memory.load(W_CURRENT_MENU, 1),
            state.memory.load(W_PLAYER_MON, 1), state.memory.load(W_PRINT_PRICES, 1),
            state.memory.load(W_TEXTBOX, 1),
            state.memory.load(0xFFB8, 1), state.memory.load(0x2000, 1),
        )
        private_call = state.globals["private_call"]
    return Endpoint(
        **(native_registers(state, NATIVE_STATE)
           if native else assembly_registers(state)),
        memory=memory,
        print_call=state.globals["print_call"],
        load_call=state.globals["load_call"],
        private_call=private_call,
        after_call=state.globals["after_call"],
        constraints=tuple(state.solver.constraints),
    )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "DisplayPokemartDialogue")
    print_text = symbol_location(SYMBOLS, "PrintText")
    load = symbol_location(SYMBOLS, "LoadItemList")
    private = symbol_location(SYMBOLS, "DisplayPokemartDialogue_")
    after = symbol_location(SYMBOLS, "AfterDisplayingTextID")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    project = angr.Project(
        rom_window(ROM, private.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    project.hook(print_text.address, PrintBoundary(), length=1)
    project.hook(load.address, LoadBoundary(), length=1)
    project.hook(private.address, PrivateBoundary(), length=1)
    project.hook(after.address, AfterBoundary(), length=1)
    project.hook(location.address + 14,
                 Sm83StoreAImmediate(W_LIST_MENU, location.address + 17),
                 length=3)
    project.hook(location.address + 17,
                 Sm83LoadAHighImmediate(0xFFB8, location.address + 19),
                 length=2)
    project.hook(location.address + 20,
                 Sm83LoadABytePreserveF(location.address + 21,
                                        location.address + 22),
                 length=2)
    project.hook(location.address + 22,
                 Sm83StoreAHighImmediate(0xFFB8, location.address + 24),
                 length=2)
    project.hook(location.address + 24,
                 Sm83StoreAImmediate(0x2000, location.address + 27),
                 length=3)
    project.hook(location.address + 31,
                 Sm83StoreAHighImmediate(0xFFB8, location.address + 33),
                 length=2)
    project.hook(location.address + 33,
                 Sm83StoreAImmediate(0x2000, location.address + 36),
                 length=3)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.regs.sp = STACK
    _setup(state, 0, values)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN)
    assert not manager.errored and manager.found
    return [_endpoint(end, native=False) for end in manager.found]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_display_pokemart_dialogue")
    print_text = project.loader.find_symbol("port_print_text")
    load = project.loader.find_symbol("port_load_item_list")
    private = project.loader.find_symbol("port_display_pokemart_dialogue_private")
    after = project.loader.find_symbol("port_after_displaying_text_id")
    assert function is not None and print_text is not None and load is not None
    assert private is not None and after is not None
    project.hook(print_text.rebased_addr, PrintBoundary())
    project.hook(load.rebased_addr, LoadBoundary())
    project.hook(private.rebased_addr, PrivateBoundary())
    project.hook(after.rebased_addr, AfterBoundary())
    state = project.factory.call_state(function.rebased_addr,
                                       NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8,
                       claripy.Concat(values["loaded"], values["romb"]))
    state.memory.store(NATIVE_STATE + 10, values["list_menu"])
    state.memory.store(NATIVE_STATE + 11,
                       claripy.Concat(*(values[name] for name in (
                           "private_list_scroll", "private_saved_scroll",
                           "private_bought_sold", "private_current_menu",
                           "private_player_mon", "private_print_prices",
                           "private_textbox"))))
    _setup(state, NATIVE_MEMORY, values)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and manager.deadended
    return [_endpoint(end, native=True) for end in manager.deadended]


@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),
                    reason="run `make red`")
def test_display_pokemart_dialogue_pathwise_equivalence() -> None:
    values = symbolic_registers("display_pokemart_dialogue")
    for name in ("textbox", "list_menu", "update", "item_ptr_h", "item_ptr_l",
                 "loaded", "romb", "private_list_scroll", "private_saved_scroll",
                 "private_bought_sold", "private_current_menu", "private_player_mon",
                 "private_print_prices", "private_textbox"):
        values[name] = claripy.BVS(f"display_pokemart_{name}", 8)
    for index in range(4):
        values[f"list_{index}"] = claripy.BVS(f"display_pokemart_list_{index}", 8)
    for name in REGISTERS:
        values[f"load_post_{name}"] = (
            claripy.Concat(claripy.BVS("display_pokemart_load_flags", 4),
                           claripy.BVV(0, 4)) if name == "f" else
            claripy.BVS(f"display_pokemart_load_{name}", 8))
        values[f"out_{name}"] = (
            claripy.Concat(claripy.BVS("display_pokemart_out_flags", 4),
                           claripy.BVV(0, 4)) if name == "f" else
            claripy.BVS(f"display_pokemart_out_{name}", 8))
    assert_pathwise_equivalent(
        _assembly(values), _native(values),
        (*REGISTERS, "memory", "print_call", "load_call", "private_call",
         "after_call"),
    )
