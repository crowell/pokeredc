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
from verification.harness.rom import linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import (
    Sm83LoadAImmediate,
    Sm83StoreAImmediate,
    Sm83StoreAHighImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF
W_OPTIONS = 0xD355
H_JOY5 = 0xFFB5
H_AUTO = 0xFFBA
FIELDS = (0xCC26, 0xCC2A, 0xD358, 0xCD40, 0xCC24, 0xCC25,
          0xCD3D, 0xCD3E, 0xCD3F, W_OPTIONS, H_JOY5, H_AUTO)
EXPECTED = bytes.fromhex(
    "21a0c306030e12cd22192104c406030e12cd22192168c406030e12cd221921b5c3"
    "11c05fcd55192119c411de5fcd5519217dc411fd5fcd551921e2c4111860cd5519"
    "afea26ccea2acc3cea58d3ea40cd3e03ea24cccd4c60fa3dcdea25cc3e01e0ba"
    "cdd73d"
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
    constraints: tuple[claripy.ast.Bool, ...]


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for address in FIELDS:
        values[f"m_{address:04x}"] = claripy.BVS(f"{prefix}_m_{address:04x}", 8)
    values["m_fff6"] = claripy.BVS(f"{prefix}_m_fff6", 8)
    values["m_c3a0"] = claripy.BVS(f"{prefix}_m_c3a0", 8)
    return values


class Skip(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__(); self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.jump(self.next_address)


class SetCursor(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__(); self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        m = self.state.memory
        speed = m.load(W_OPTIONS, 1) & 0x3F
        m.store(0xCD3D, claripy.If(speed == 5, claripy.BVV(14, 8),
                                    claripy.If(speed == 3, claripy.BVV(7, 8), claripy.BVV(1, 8))))
        m.store(0xCD3E, claripy.If((m.load(W_OPTIONS, 1) & 0x80) != 0,
                                   claripy.BVV(10, 8), claripy.BVV(1, 8)))
        m.store(0xCD3F, claripy.If((m.load(W_OPTIONS, 1) & 0x40) != 0,
                                   claripy.BVV(10, 8), claripy.BVV(1, 8)))
        self.jump(self.next_address)


class CancelInput(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(2, 8)
        self.state.regs.b = claripy.BVV(2, 8)
        self.jump(symbol_location(SYMBOLS, "DisplayOptionMenu.exitMenu").address)


def _setup(state: angr.SimState, values: dict[str, claripy.ast.BV], base: int) -> None:
    for address in FIELDS:
        state.memory.store(base + address, values[f"m_{address:04x}"])
    state.memory.store(base + 0xFFF6, values["m_fff6"])
    state.memory.store(base + 0xC3A0, values["m_c3a0"])


def _endpoint(state: angr.SimState, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    regs = native_registers(state, NATIVE_STATE) if native else assembly_registers(state)
    return Endpoint(
        **regs,
        memory=claripy.Concat(*(state.memory.load(base + a, 1) for a in FIELDS)),
        constraints=tuple(state.solver.constraints),
    )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    loc = symbol_location(SYMBOLS, "DisplayOptionMenu")
    loop = symbol_location(SYMBOLS, "DisplayOptionMenu.loop")
    exit_menu = symbol_location(SYMBOLS, "DisplayOptionMenu.exitMenu")
    assert linked_bytes(ROM, loc, 0x65) == EXPECTED
    p = angr.Project(rom_window(ROM, loc.bank), auto_load_libs=False,
                     rebase_granularity=0x100,
                     main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                                "base_addr": 0, "entry_point": loc.address})
    b = loc.address
    for off, nxt in ((7, 10), (17, 20), (27, 30), (0x24, 0x27),
                     (0x2D, 0x30), (0x36, 0x39), (0x3F, 0x42)):
        p.hook(b + off, Skip(b + nxt), length=3)
    for off, address, nxt in ((0x43, 0xCC26, 0x46), (0x46, 0xCC2A, 0x49),
                              (0x4A, 0xD358, 0x4D), (0x4D, 0xCD40, 0x50),
                              (0x52, 0xCC24, 0x55)):
        p.hook(b + off, Sm83StoreAImmediate(address, b + nxt), length=3)
    p.hook(b + 0x55, SetCursor(b + 0x58), length=3)
    p.hook(b + 0x58, Sm83LoadAImmediate(0xCD3D, b + 0x5B), length=3)
    p.hook(b + 0x5B, Sm83StoreAImmediate(0xCC25, b + 0x5E), length=3)
    p.hook(b + 0x60, Sm83StoreAHighImmediate(0xBA, b + 0x62), length=2)
    p.hook(b + 0x62, Skip(loop.address), length=3)
    p.hook(loop.address, Skip(loop.address + 3), length=3)
    p.hook(loop.address + 3, Skip(loop.address + 6), length=3)
    p.hook(loop.address + 6, CancelInput(), length=14)
    p.hook(exit_menu.address + 2, Skip(exit_menu.address + 5), length=3)
    p.hook(exit_menu.address + 5, Skip(DONE), length=1)
    s = p.factory.blank_state(addr=b)
    set_assembly_registers(s, values); _setup(s, values, 0)
    s.memory.store(H_JOY5, claripy.BVV(2, 8))
    m = p.factory.simulation_manager(s); m.explore(find=DONE, num_find=1)
    assert not m.errored and len(m.found) == 1
    return [_endpoint(x, False) for x in m.found]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    p = angr.Project(ELF, auto_load_libs=False)
    f = p.loader.find_symbol("port_display_option_menu"); assert f is not None
    s = p.factory.call_state(f.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(s, NATIVE_STATE, values); _setup(s, values, NATIVE_MEMORY)
    s.memory.store(NATIVE_MEMORY + H_JOY5, claripy.BVV(2, 8))
    m = p.factory.simulation_manager(s); m.run()
    assert not m.errored and len(m.deadended) == 1
    return [_endpoint(x, True) for x in m.deadended]


@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_display_option_menu_cancel_pathwise_equivalence() -> None:
    values = _inputs("display_option_menu")
    values["m_d355"] = claripy.BVV(5, 8)
    assert_pathwise_equivalent(_assembly(values), _native(values), ("a", "b", "memory"))
