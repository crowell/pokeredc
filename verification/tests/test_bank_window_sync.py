"""Bank-aware proof memory: window-sync equivalence for MBC1 switches.

Proves the additive bank-aware model (verification/include/bank.h +
verification/harness/banked_memory.py):

1. ``test_bankswitch_home_window_sync``: the real linked BankswitchHome
   body, executed under MBC1 write hooks, observes the same registers,
   bank bytes, and sampled 0x4000-window bytes as the window-aware C
   port. A flat model would leave stale bank-1 bytes in the window.
2. ``test_bank_read_window_byte_mid_function_remap``: switch banks and
   read the window inside one call on both sides; the byte must come
   from the newly selected bank.
3. ``test_sram_bank_isolation``: SRAM enable + bank select + write +
   flush round-trips within one RAM bank on the C side.

Banks are concrete (1, 2, 5, 0->1-adjustment); window bytes are the
concrete ROM contents, so the comparisons stay cheap.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.banked_memory import (
    H_LOADED_ROM_BANK,
    MBC_RAM_BANK_OFF,
    MBC_RAM_ENABLE_OFF,
    MBC_STATE_BASE,
    ROM_WINDOW_BASE,
    SRAM_BACKING_BASE,
    SRAM_WINDOW_BASE,
    SRAM_WINDOW_SIZE,
    install_mbc1,
)
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
    REGISTERS,
    assembly_registers,
    native_registers,
    set_assembly_registers,
    store_native_registers,
)
from verification.harness.rom import collect_returns, linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import (
    Sm83LoadAHighImmediate,
    Sm83LoadAImmediate,
    Sm83StoreAHighImmediate,
    Sm83StoreAImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xFFFF

W_TEMP = 0xCF09
W_SAVED = 0xCF08
R_ROMB = 0x2000

HOME_BODY = bytes.fromhex("ea09cff0b8ea08cffa09cfe0b8ea0020c9")
# Sampled window offsets: edges, mid-window, and a few scattered points.
SAMPLES = (0x0000, 0x0001, 0x00FF, 0x1000, 0x1FFF, 0x2000, 0x2ABC, 0x3FFE, 0x3FFF)


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
    constraints: tuple[claripy.ast.Bool, ...]


def _sampled_window(state, base: int):
    return claripy.Concat(
        *(state.memory.load(base + ROM_WINDOW_BASE + off, 1) for off in SAMPLES)
    )


def _assembly_home(target_bank: int) -> list[Endpoint]:
    loc = symbol_location(SYMBOLS, "BankswitchHome")
    assert linked_bytes(ROM, loc, len(HOME_BODY)) == HOME_BODY
    project = angr.Project(
        rom_window(ROM, loc.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": loc.address,
        },
    )
    q = loc.address
    # Same SM83 seam shims as the proven register-only test; the stores
    # themselves stay real so the MBC1 hooks observe them.
    project.hook(q, Sm83StoreAImmediate(W_TEMP, q + 3), length=3)
    project.hook(q + 3, Sm83LoadAHighImmediate(H_LOADED_ROM_BANK, q + 5), length=2)
    project.hook(q + 5, Sm83StoreAImmediate(W_SAVED, q + 8), length=3)
    project.hook(q + 8, Sm83LoadAImmediate(W_TEMP, q + 11), length=3)
    project.hook(q + 11, Sm83StoreAHighImmediate(H_LOADED_ROM_BANK, q + 13), length=2)
    project.hook(q + 13, Sm83StoreAImmediate(R_ROMB, q + 16), length=3)
    state = project.factory.blank_state(addr=q)
    install_mbc1(state, 0, ROM)
    regs = {r: claripy.BVV(0, 8) for r in REGISTERS}
    regs["a"] = claripy.BVV(target_bank, 8)
    set_assembly_registers(state, regs)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    ends = collect_returns(project, state, RETURN)
    assert len(ends) == 1
    end = ends[0]
    return [
        Endpoint(
            **assembly_registers(end),
            state=claripy.Concat(
                end.memory.load(W_TEMP, 1),
                end.memory.load(W_SAVED, 1),
                end.memory.load(H_LOADED_ROM_BANK, 1),
                end.memory.load(R_ROMB, 1),
                _sampled_window(end, 0),
            ),
            constraints=tuple(end.solver.constraints),
        )
    ]


def _native_home(target_bank: int) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_bankswitch_home_window")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    regs = {r: claripy.BVV(0, 8) for r in REGISTERS}
    regs["a"] = claripy.BVV(target_bank, 8)
    store_native_registers(state, NATIVE_STATE, regs)
    install_mbc1(state, NATIVE_MEMORY, ROM, hook_writes=False, banks=(target_bank,))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    end = manager.deadended[0]
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            state=claripy.Concat(
                end.memory.load(NATIVE_MEMORY + W_TEMP, 1),
                end.memory.load(NATIVE_MEMORY + W_SAVED, 1),
                end.memory.load(NATIVE_MEMORY + H_LOADED_ROM_BANK, 1),
                end.memory.load(NATIVE_MEMORY + R_ROMB, 1),
                _sampled_window(end, NATIVE_MEMORY),
            ),
            constraints=tuple(end.solver.constraints),
        )
    ]


@pytest.mark.skipif(
    not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),
    reason="build artifacts missing",
)
@pytest.mark.parametrize("bank", (1, 2, 5, 0))
def test_bankswitch_home_window_sync(bank: int) -> None:
    """Real BankswitchHome remaps the window mid-call on both sides."""
    assert_pathwise_equivalent(
        _assembly_home(bank), _native_home(bank), (*REGISTERS, "state")
    )


def _assembly_probe(first: int, second: int, offset: int) -> list[Endpoint]:
    """Switch-read-switch-read sequence under MBC1 hooks.

    Hand-assembled from real SM83 (LD A,n / LD [rROMB],A / LD A,[HL] /
    LD D,A / ... / RET with HL preset); the two absolute stores use the
    standard SM83 store seam so the MBC1 hooks observe real stores.
    """
    loc = symbol_location(SYMBOLS, "BankswitchHome")
    project = angr.Project(
        rom_window(ROM, loc.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": 0x700,
        },
    )
    code = bytes(
        (0x3E, first, 0xEA, 0x00, 0x20, 0x7E, 0x57, 0x3E, second, 0xEA, 0x00, 0x20, 0x7E, 0xC9)
    )
    state = project.factory.blank_state(addr=0x700)
    install_mbc1(state, 0, ROM)
    for i, byte in enumerate(code):
        state.memory.store(0x700 + i, claripy.BVV(byte, 8))
    project.hook(0x702, Sm83StoreAImmediate(R_ROMB, 0x705), length=3)
    project.hook(0x709, Sm83StoreAImmediate(R_ROMB, 0x70C), length=3)
    # Match the native side's zeroed entry registers (B carries the final
    # bank on both sides: preserved input in C, untouched input here).
    set_assembly_registers(state, {r: claripy.BVV(0, 8) for r in REGISTERS})
    state.regs.b = claripy.BVV(second, 8)
    state.regs.h = claripy.BVV((ROM_WINDOW_BASE + offset) >> 8, 8)
    state.regs.l = claripy.BVV((ROM_WINDOW_BASE + offset) & 0xFF, 8)
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN)
    assert not manager.errored and len(manager.found) == 1
    end = manager.found[0]
    return [
        Endpoint(
            **assembly_registers(end),
            state=claripy.Concat(
                end.memory.load(H_LOADED_ROM_BANK, 1),
                end.memory.load(R_ROMB, 1),
            ),
            constraints=tuple(end.solver.constraints),
        )
    ]


def _run_probe_bank(bank: int, offset: int, base_state=None):
    """Run one port_bank_read_window_byte call; optionally seed memory."""
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_bank_read_window_byte")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    regs = {r: claripy.BVV(0, 8) for r in REGISTERS}
    regs["b"] = claripy.BVV(bank, 8)
    regs["h"] = claripy.BVV((ROM_WINDOW_BASE + offset) >> 8, 8)
    regs["l"] = claripy.BVV((ROM_WINDOW_BASE + offset) & 0xFF, 8)
    store_native_registers(state, NATIVE_STATE, regs)
    install_mbc1(state, NATIVE_MEMORY, ROM, hook_writes=False, banks=(bank,))
    if base_state is not None:
        for addr, size in (
            (ROM_WINDOW_BASE, 0x4000),
            (R_ROMB, 1),
            (H_LOADED_ROM_BANK, 1),
            (MBC_STATE_BASE, 5),
        ):
            state.memory.store(
                NATIVE_MEMORY + addr, base_state.memory.load(NATIVE_MEMORY + addr, size)
            )
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return manager.deadended[0]


def _native_probe(first: int, second: int, offset: int) -> list[Endpoint]:
    mid = _run_probe_bank(first, offset)
    first_regs = native_registers(mid, NATIVE_STATE)
    end = _run_probe_bank(second, offset, base_state=mid)
    final = native_registers(end, NATIVE_STATE)
    # D carries the first-bank byte so the equivalence covers both reads.
    final["d"] = first_regs["a"]
    return [
        Endpoint(
            **final,
            state=claripy.Concat(
                end.memory.load(NATIVE_MEMORY + H_LOADED_ROM_BANK, 1),
                end.memory.load(NATIVE_MEMORY + R_ROMB, 1),
            ),
            constraints=tuple(end.solver.constraints),
        )
    ]


@pytest.mark.skipif(
    not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),
    reason="build artifacts missing",
)
@pytest.mark.parametrize(
    "first,second,offset", ((1, 2, 0x0123), (2, 5, 0x3FFF), (5, 1, 0x0000))
)
def test_bank_read_window_byte_mid_function_remap(
    first: int, second: int, offset: int
) -> None:
    # Assembly D holds the first-bank byte, A the second-bank byte.
    assert_pathwise_equivalent(
        _assembly_probe(first, second, offset),
        _native_probe(first, second, offset),
        (*REGISTERS, "state"),
    )


def _native_sram(bank: int, offset: int, value: int):
    project = angr.Project(ELF, auto_load_libs=False)
    write_fn = project.loader.find_symbol("port_sram_write_probe")
    read_fn = project.loader.find_symbol("port_sram_read_probe")
    assert write_fn is not None and read_fn is not None
    state = project.factory.call_state(write_fn.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    regs = {r: claripy.BVV(0, 8) for r in REGISTERS}
    regs["b"] = claripy.BVV(bank, 8)
    regs["c"] = claripy.BVV(value, 8)
    regs["h"] = claripy.BVV((SRAM_WINDOW_BASE + offset) >> 8, 8)
    regs["l"] = claripy.BVV((SRAM_WINDOW_BASE + offset) & 0xFF, 8)
    store_native_registers(state, NATIVE_STATE, regs)
    install_mbc1(state, NATIVE_MEMORY, ROM, hook_writes=False)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    mid = manager.deadended[0]

    state2 = project.factory.call_state(read_fn.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    regs2 = {r: claripy.BVV(0, 8) for r in REGISTERS}
    regs2["b"] = claripy.BVV(bank, 8)
    regs2["h"] = claripy.BVV((SRAM_WINDOW_BASE + offset) >> 8, 8)
    regs2["l"] = claripy.BVV((SRAM_WINDOW_BASE + offset) & 0xFF, 8)
    store_native_registers(state2, NATIVE_STATE, regs2)
    install_mbc1(state2, NATIVE_MEMORY, ROM, hook_writes=False)
    for addr, size in (
        (SRAM_WINDOW_BASE, SRAM_WINDOW_SIZE),
        (MBC_STATE_BASE, 5),
        (SRAM_BACKING_BASE, 4 * SRAM_WINDOW_SIZE),
    ):
        state2.memory.store(
            NATIVE_MEMORY + addr, mid.memory.load(NATIVE_MEMORY + addr, size)
        )
    manager2 = project.factory.simulation_manager(state2)
    manager2.run()
    assert not manager2.errored and len(manager2.deadended) == 1
    end = manager2.deadended[0]
    return (
        end.solver.eval_one(native_registers(end, NATIVE_STATE)["a"]),
        end.solver.eval_one(
            end.memory.load(NATIVE_MEMORY + MBC_STATE_BASE + MBC_RAM_BANK_OFF, 1)
        ),
        end.solver.eval_one(
            end.memory.load(NATIVE_MEMORY + MBC_STATE_BASE + MBC_RAM_ENABLE_OFF, 1)
        ),
    )


@pytest.mark.skipif(
    not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),
    reason="build artifacts missing",
)
@pytest.mark.parametrize(
    "bank,offset,value", ((0, 0x0100, 0x42), (1, 0x1FFF, 0x99), (3, 0x0000, 0x00))
)
def test_sram_bank_isolation(bank: int, offset: int, value: int) -> None:
    """SRAM write+flush+read round-trips within one RAM bank."""
    byte, ram_bank, enabled = _native_sram(bank, offset, value)
    assert byte == value
    assert ram_bank == (bank & 0x03)
    assert enabled == 1


def test_exact_home_body() -> None:
    loc = symbol_location(SYMBOLS, "BankswitchHome")
    assert linked_bytes(ROM, loc, len(HOME_BODY)) == HOME_BODY
