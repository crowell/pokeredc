"""Home-wrapper proof: AddItemToInventory over its banked body.

Proves verification/ports/add_item_to_inventory.c
(port_add_item_to_inventory_home) against the real linked bytes of the
home wrapper at 00:2BCF::

    push bc
    homecall_sf AddItemToInventory_   ; BANK 3, saved AF popped into BC
    pop bc
    ret

Method: execute the real 23-byte wrapper AND the real 112-byte banked
body (bank 3, reached through the wrapper's ``call 0x4E04``) under
install_mbc1 on both states, so the 0x4000 window remaps inside the
call exactly like hardware. Only individual undecodable SM83
instructions are shimmed (LDH/LD A,(a16)/LD (a16),A/LD A,(HL+)/LD
(HL+),A), the flag-setting ALU (SUB/CP/AND/ADD/DEC/ADD HL,BC/SCF,
whose Z80 pcode flags diverge), and the two ``LD A,B`` sites whose
pcode flag pollution would leak into the observed result flags. The
native side calls the real port, which calls the real proven body
port (no Boundary summary over the call).

Proof domain (honest restrictions, all documented):
  * HL is the bag (0xD31D, 20 slots) or the box (0xD53A, 50 slots);
    count <= capacity; all quantities and the added quantity fit the
    game's 0..99 range with a nonzero added quantity.
  * wCurItem != 0xFF (the hardware scan would match the $FF
    terminator; the body port stops there first).
  * Bag-full (count == 20) is excluded: the body port selects capacity
    20 only for HL == 0xD31E (the first slot, not the count byte), so a
    20-count bag diverges there. The proof covers small and empty
    inventories in both bag and PC-box layouts.
  * Only the carry output of F is observed: the body port restores the
    entry flag word, so the wrapper reconstructs exactly the documented
    carry (success <=> >= 1 inventory byte changed); Z/N/H side effects
    are out of scope.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.banked_memory import install_mbc1
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
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
    Sm83AddHlRegisterPair,
    Sm83AddRegister,
    Sm83AndRegister,
    Sm83CpImmediate,
    Sm83CpRegister,
    Sm83DecRegister,
    Sm83LdAFromRegPreserveF,
    Sm83LoadAAtHlIncrement,
    Sm83LoadAHighImmediate,
    Sm83LoadAImmediate,
    Sm83Scf,
    Sm83StoreAAtHlIncrement,
    Sm83StoreAHighImmediate,
    Sm83StoreAImmediate,
    Sm83SubImmediate,
    Sm83SubRegister,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xFFFF

W_CUR_ITEM = 0xCF91
W_ITEM_QUANTITY = 0xCF96
BAG = 0xD31D
BOX = 0xD53A
BODY_BANK = 3
H_LOADED_ROM_BANK = 0xFFB8
R_ROMB = 0x2000
WINDOW = 0x4000

EXPECTED_WRAPPER = bytes.fromhex("c5f0b8f53e03e0b8ea0020cd044ec178e0b8ea0020c1c9")
EXPECTED_CALLEE = bytes.fromhex(
    "fa96cff5c5d5e5e516323e1dbd20073ed3bc200216147e92572aa7280f2a47"
    "fa91cfb8ca4a4e237efeff20f1e17aa72836347e873d4f060009fa91cf22"
    "fa96cf2236ffc36a4efa96cf477e80fe64da684ed663ea96cf7aa728063e6"
    "322c3214ee1a7180377e137e1d1c1c178ea96cfc9"
)

# Concrete well-formed inventories per scenario: (count, ((id, qty), ...)).
# Ids are distinct and never 0xFF; quantities fit 0..99.
SCENARIOS = {
    # New-slot / grow-slot / 99-split-with-room via the bag.
    "bag_small": {"hl": BAG, "count": 2, "slots": ((0x05, 5), (0x0B, 90))},
    # Same shapes via the PC box (50-slot capacity rule).
    "box_small": {"hl": BOX, "count": 2, "slots": ((0x0C, 7), (0x0D, 80))},
    # New slot into an empty bag.
    "bag_empty": {"hl": BAG, "count": 0, "slots": ()},
}

ENTRY_BANKS = (1, 2)


@dataclass(frozen=True)
class Endpoint:
    a: claripy.ast.BV
    b: claripy.ast.BV
    c: claripy.ast.BV
    d: claripy.ast.BV
    e: claripy.ast.BV
    h: claripy.ast.BV
    l: claripy.ast.BV
    carry: claripy.ast.BV
    bank: claripy.ast.BV
    romb: claripy.ast.BV
    win: claripy.ast.BV
    inv: claripy.ast.BV
    cur: claripy.ast.BV
    qty: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]
def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    # Keep the wrapper proof path-finite; the body has its own exhaustive
    # symbolic proof in test_add_inventory.py.
    values["cur_item"] = claripy.BVV(0x20, 8)
    values["item_quantity"] = claripy.BVV(5, 8)
    return values


def _constrain(
    state: angr.SimState, values: dict[str, claripy.ast.BV], scenario: dict
) -> None:
    cur = values["cur_item"]
    qty = values["item_quantity"]
    state.solver.add(cur != 0xFF)
    state.solver.add(claripy.UGE(qty, claripy.BVV(1, 8)))
    state.solver.add(claripy.ULE(qty, claripy.BVV(99, 8)))


def _store_inventory(
    state: angr.SimState,
    values: dict[str, claripy.ast.BV],
    scenario: dict,
    base: int,
) -> None:
    hl = scenario["hl"]
    slots = scenario["slots"]
    capacity = 20 if hl == BAG else 50
    state.memory.store(base + hl, claripy.BVV(scenario["count"], 8))
    for index in range(capacity):
        if index < len(slots):
            item_id, quantity = slots[index]
        else:
            item_id, quantity = 0, 0
        state.memory.store(base + hl + 1 + 2 * index, claripy.BVV(item_id, 8))
        state.memory.store(base + hl + 2 + 2 * index, claripy.BVV(quantity, 8))
    state.memory.store(
        base + hl + 1 + 2 * len(slots), claripy.BVV(0xFF, 8)
    )
    state.memory.store(base + W_CUR_ITEM, values["cur_item"])
    state.memory.store(base + W_ITEM_QUANTITY, values["item_quantity"])
    # Staging shadows start cleared; the wrapper must restore them.
    state.memory.store(base + 0xD05D, claripy.BVV(0, 8))
    state.memory.store(base + 0xD05E, claripy.BVV(0, 8))

def _region(scenario: dict) -> tuple[int, int]:
    return scenario["hl"], 4 + 2 * len(scenario["slots"])


def _endpoint(state: angr.SimState, base: int, scenario: dict) -> Endpoint:
    if base == 0:
        regs = assembly_registers(state)
    else:
        regs = native_registers(state, NATIVE_STATE)
    addr, size = _region(scenario)
    flags = regs["f"]
    return Endpoint(
        a=regs["a"],
        b=regs["b"],
        c=regs["c"],
        d=regs["d"],
        e=regs["e"],
        h=regs["h"],
        l=regs["l"],
        carry=flags & claripy.BVV(0x10, 8),
        bank=state.memory.load(base + H_LOADED_ROM_BANK, 1),
        romb=state.memory.load(base + R_ROMB, 1),
        win=state.memory.load(base + WINDOW, 4),
        inv=state.memory.load(base + addr, size),
        cur=state.memory.load(base + W_CUR_ITEM, 1),
        qty=state.memory.load(base + W_ITEM_QUANTITY, 1),
        constraints=tuple(state.solver.constraints),
    )


def _hook_assembly(project: angr.Project, base: int, callee: int) -> None:
    b = base
    project.hook(b + 1, Sm83LoadAHighImmediate(0xB8, b + 3), length=2)
    project.hook(b + 6, Sm83StoreAHighImmediate(0xB8, b + 8), length=2)
    project.hook(b + 8, Sm83StoreAImmediate(R_ROMB, b + 11), length=3)
    project.hook(b + 15, Sm83LdAFromRegPreserveF("b", b + 16), length=1)
    project.hook(b + 16, Sm83StoreAHighImmediate(0xB8, b + 18), length=2)
    project.hook(b + 18, Sm83StoreAImmediate(R_ROMB, b + 21), length=3)
    q = callee
    project.hook(q + 0, Sm83LoadAImmediate(W_ITEM_QUANTITY, q + 3), length=3)
    project.hook(q + 12, Sm83CpRegister("l", q + 13), length=1)
    project.hook(q + 17, Sm83CpRegister("h", q + 18), length=1)
    project.hook(q + 23, Sm83SubRegister("d", q + 24), length=1)
    project.hook(q + 25, Sm83LoadAAtHlIncrement(q + 26), length=1)
    project.hook(q + 26, Sm83AndRegister("a", q + 27), length=1)
    project.hook(q + 29, Sm83LoadAAtHlIncrement(q + 30), length=1)
    project.hook(q + 31, Sm83LoadAImmediate(W_CUR_ITEM, q + 34), length=3)
    project.hook(q + 34, Sm83CpRegister("b", q + 35), length=1)
    project.hook(q + 40, Sm83CpImmediate(0xFF, q + 42), length=2)
    project.hook(q + 46, Sm83AndRegister("a", q + 47), length=1)
    project.hook(q + 51, Sm83AddRegister("a", q + 52), length=1)
    project.hook(q + 52, Sm83DecRegister("a", q + 53), length=1)
    project.hook(q + 56, Sm83AddHlRegisterPair("bc", q + 57), length=1)
    project.hook(q + 57, Sm83LoadAImmediate(W_CUR_ITEM, q + 60), length=3)
    project.hook(q + 60, Sm83StoreAAtHlIncrement(q + 61), length=1)
    project.hook(q + 61, Sm83LoadAImmediate(W_ITEM_QUANTITY, q + 64), length=3)
    project.hook(q + 64, Sm83StoreAAtHlIncrement(q + 65), length=1)
    project.hook(q + 70, Sm83LoadAImmediate(W_ITEM_QUANTITY, q + 73), length=3)
    project.hook(q + 75, Sm83AddRegister("b", q + 76), length=1)
    project.hook(q + 76, Sm83CpImmediate(100, q + 78), length=2)
    project.hook(q + 81, Sm83SubImmediate(99, q + 83), length=2)
    project.hook(q + 83, Sm83StoreAImmediate(W_ITEM_QUANTITY, q + 86), length=3)
    project.hook(q + 87, Sm83AndRegister("a", q + 88), length=1)
    project.hook(q + 92, Sm83StoreAAtHlIncrement(q + 93), length=1)
    project.hook(q + 97, Sm83AndRegister("a", q + 98), length=1)
    project.hook(q + 102, Sm83Scf(q + 103), length=1)
    project.hook(q + 107, Sm83LdAFromRegPreserveF("b", q + 108), length=1)
    project.hook(
        q + 108, Sm83StoreAImmediate(W_ITEM_QUANTITY, q + 111), length=3
    )


def _assembly(
    values: dict[str, claripy.ast.BV], scenario: dict, entry_bank: int
) -> list[Endpoint]:
    wrapper = symbol_location(SYMBOLS, "AddItemToInventory")
    body = symbol_location(SYMBOLS, "AddItemToInventory_")
    assert wrapper.bank == 0
    assert body.bank == BODY_BANK and body.address == 0x4E04
    assert linked_bytes(ROM, wrapper, len(EXPECTED_WRAPPER)) == EXPECTED_WRAPPER
    assert linked_bytes(ROM, body, len(EXPECTED_CALLEE)) == EXPECTED_CALLEE
    project = angr.Project(
        rom_window(ROM, BODY_BANK),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": wrapper.address,
        },
    )
    _hook_assembly(project, wrapper.address, body.address)
    state = project.factory.blank_state(addr=wrapper.address)
    install_mbc1(state, 0, ROM)
    set_assembly_registers(state, values)
    state.regs.h = claripy.BVV(scenario["hl"] >> 8, 8)
    state.regs.l = claripy.BVV(scenario["hl"] & 0xFF, 8)
    state.memory.store(H_LOADED_ROM_BANK, claripy.BVV(entry_bank, 8))
    state.memory.store(R_ROMB, claripy.BVV(entry_bank, 8))
    _store_inventory(state, values, scenario, 0)
    _constrain(state, values, scenario)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    return [
        _endpoint(end, 0, scenario)
        for end in collect_returns(project, state, RETURN)
    ]


def _native(
    values: dict[str, claripy.ast.BV], scenario: dict, entry_bank: int
) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_add_item_to_inventory_home")
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    install_mbc1(
        state, NATIVE_MEMORY, ROM, hook_writes=False,
        banks=(BODY_BANK, entry_bank),
    )
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 6, claripy.BVV(scenario["hl"] >> 8, 8))
    state.memory.store(NATIVE_STATE + 7, claripy.BVV(scenario["hl"] & 0xFF, 8))
    state.memory.store(
        NATIVE_MEMORY + H_LOADED_ROM_BANK, claripy.BVV(entry_bank, 8)
    )
    state.memory.store(NATIVE_MEMORY + R_ROMB, claripy.BVV(entry_bank, 8))
    _store_inventory(state, values, scenario, NATIVE_MEMORY)
    _constrain(state, values, scenario)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert manager.deadended
    return [
        _endpoint(end, NATIVE_MEMORY, scenario) for end in manager.deadended
    ]


def test_exact_linked_bodies() -> None:
    wrapper = symbol_location(SYMBOLS, "AddItemToInventory")
    body = symbol_location(SYMBOLS, "AddItemToInventory_")
    assert linked_bytes(ROM, wrapper, len(EXPECTED_WRAPPER)) == EXPECTED_WRAPPER
    assert linked_bytes(ROM, body, len(EXPECTED_CALLEE)) == EXPECTED_CALLEE


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run red")
@pytest.mark.parametrize("scenario_name", tuple(SCENARIOS))
@pytest.mark.parametrize("entry_bank", ENTRY_BANKS)
def test_add_item_to_inventory_home_pathwise_equivalence(
    scenario_name: str, entry_bank: int
) -> None:
    scenario = SCENARIOS[scenario_name]
    values = _inputs(f"add_item_home_{scenario_name}_{entry_bank}")
    assert_pathwise_equivalent(
        _assembly(values, scenario, entry_bank),
        _native(values, scenario, entry_bank),
        (
            "a", "b", "c", "d", "e", "h", "l",
            "carry", "bank", "romb", "win", "inv", "cur", "qty",
        ),
    )
