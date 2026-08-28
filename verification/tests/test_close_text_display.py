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
    collect_returns,
    rom_window,
    sm83_flags_to_z80,
    symbol_location,
    z80_flags_to_sm83,
)
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
STACK = 0xD000
RETURN = 0xEFFF

W_CUR_MAP = 0xD35E
W_MAP_PAL_OFFSET = 0xD35D
W_FONT_LOADED = 0xCFC4
W_STATUS_FLAGS6 = 0xD732
H_WY = 0xFFB0
H_AUTO = 0xFFBA
H_LOADED = 0xFFB8
R_ROMB = 0x2000
R_BGP = 0xFF47
R_OBP0 = 0xFF48
R_OBP1 = 0xFF49
SPRITE_ORIG = 0xC219
SPRITE_FACING = 0xC119
COUNT = 15


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
    calls: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class CallBoundary(angr.SimProcedure):
    def __init__(self, call_id: int, next_address: int) -> None:
        super().__init__()
        self.call_id = call_id
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["calls"] = (
            (self.state.globals.get("calls", claripy.BVV(0, 32)) << 4)
            | claripy.BVV(self.call_id, 32)
        )
        self.jump(self.next_address)


class NativeCallBoundary(angr.SimProcedure):
    def __init__(self, call_id: int) -> None:
        super().__init__()
        self.call_id = call_id

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["calls"] = (
            (self.state.globals.get("calls", claripy.BVV(0, 32)) << 4)
            | claripy.BVV(self.call_id, 32)
        )
        ret = self.state.memory.load(self.state.regs.sp, 8, endness="Iend_LE")
        self.state.regs.sp = self.state.regs.sp + 8
        self.jump(ret)


class NativeLoadGbPalBoundary(NativeCallBoundary):
    """Keep the proven palette helper's fetched values as its outputs."""

    def run(self) -> None:  # type: ignore[override]
        pointer = self.state.regs.rdi
        for output, fetched in ((12, 9), (13, 10), (14, 11)):
            value = self.state.memory.load(pointer + fetched, 1)
            self.state.memory.store(pointer + output, value)
        super().run()


class ReturnUpdateSprites(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.globals["calls"] = (
            (self.state.globals.get("calls", claripy.BVV(0, 32)) << 4)
            | claripy.BVV(7, 32)
        )
        self.inhibit_autoret = True
        self.jump(RETURN)


class ConditionalPlayerGraphicsCall(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        z_set = ((self.state.regs.f >> 6) & 1) == 1
        called = self.state.copy()
        skipped = self.state.copy()
        called.solver.add(z_set)
        skipped.solver.add(claripy.Not(z_set))
        called.globals["calls"] = (
            (called.globals.get("calls", claripy.BVV(0, 32)) << 4)
            | claripy.BVV(5, 32)
        )
        self.inhibit_autoret = True
        self.successors.add_successor(called, self.state.addr + 3, z_set, "Ijk_Boring")
        self.successors.add_successor(
            skipped, self.state.addr + 3, claripy.Not(z_set), "Ijk_Boring"
        )


class PopAF(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        sp = self.state.regs.sp
        self.state.regs.f = self.state.memory.load(sp, 1)
        self.state.regs.a = self.state.memory.load(sp + 1, 1)
        self.state.regs.sp = sp + 2
        self.jump(self.state.addr + 1)


class SetStatus(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(W_STATUS_FLAGS6, 1)
        self.jump(self.next_address)


class SetAImmediate(angr.SimProcedure):
    """SM83 ``ld a,n`` shim used to split an unsupported lifted block."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(5, 8)
        self.jump(self.next_address)


class BitFly(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        bit_set = (self.state.regs.a & 0x08) != 0
        canonical = claripy.If(
            bit_set,
            claripy.BVV(0x20, 8),
            claripy.BVV(0xA0, 8),
        )
        canonical = canonical | (z80_flags_to_sm83(self.state.regs.f) & 0x10)
        self.state.regs.f = sm83_flags_to_z80(canonical)
        self.jump(self.next_address)


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["saved_a"] = claripy.BVS(f"{prefix}_saved_a", 8)
    values["saved_f"] = claripy.Concat(
        claripy.BVS(f"{prefix}_saved_flags", 4), claripy.BVV(0, 4)
    )
    values["cur_map"] = claripy.BVS(f"{prefix}_cur_map", 8)
    values["status"] = claripy.BVV(0, 8)
    values["map_pal"] = claripy.BVS(f"{prefix}_map_pal", 8)
    values["font"] = claripy.BVS(f"{prefix}_font", 8)
    values["wy"] = claripy.BVS(f"{prefix}_wy", 8)
    values["auto"] = claripy.BVS(f"{prefix}_auto", 8)
    values["loaded"] = claripy.BVS(f"{prefix}_loaded", 8)
    values["romb"] = claripy.BVS(f"{prefix}_romb", 8)
    values["bgp"] = claripy.BVS(f"{prefix}_bgp", 8)
    values["obp0"] = claripy.BVS(f"{prefix}_obp0", 8)
    values["obp1"] = claripy.BVS(f"{prefix}_obp1", 8)
    for i in range(COUNT):
        values[f"orig{i}"] = claripy.BVS(f"{prefix}_orig{i}", 8)
        values[f"facing{i}"] = claripy.BVS(f"{prefix}_facing{i}", 8)
    return values


def _setup(state: angr.SimState, values: dict[str, claripy.ast.BV], base: int,
           fly: int) -> None:
    state.memory.store(base + W_CUR_MAP, values["cur_map"])
    state.memory.store(base + W_MAP_PAL_OFFSET, values["map_pal"])
    state.memory.store(base + W_FONT_LOADED, values["font"])
    state.memory.store(base + W_STATUS_FLAGS6, claripy.BVV(fly << 3, 8))
    state.memory.store(base + H_WY, values["wy"])
    state.memory.store(base + H_AUTO, values["auto"])
    state.memory.store(base + H_LOADED, values["loaded"])
    state.memory.store(base + R_ROMB, values["romb"])
    state.memory.store(base + R_BGP, values["bgp"])
    state.memory.store(base + R_OBP0, values["obp0"])
    state.memory.store(base + R_OBP1, values["obp1"])
    for i in range(COUNT):
        state.memory.store(base + SPRITE_ORIG + i * 16, values[f"orig{i}"])
        state.memory.store(base + SPRITE_FACING + i * 16, values[f"facing{i}"])


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        state.memory.load(base + H_WY, 1),
        state.memory.load(base + H_AUTO, 1),
        state.memory.load(base + H_LOADED, 1),
        state.memory.load(base + R_ROMB, 1),
        state.memory.load(base + R_BGP, 1),
        state.memory.load(base + R_OBP0, 1),
        state.memory.load(base + R_OBP1, 1),
        state.memory.load(base + W_FONT_LOADED, 1),
        *(state.memory.load(base + SPRITE_FACING + i * 16, 1) for i in range(COUNT)),
        *(state.memory.load(base + SPRITE_ORIG + i * 16, 1) for i in range(COUNT)),
    )


def _endpoint(state: angr.SimState, base: int, native: bool) -> Endpoint:
    return Endpoint(
        **(native_registers(state, NATIVE_STATE) if native else assembly_registers(state)),
        memory=_memory(state, base),
        calls=state.globals.get("calls", claripy.BVV(0, 32)),
        constraints=tuple(state.solver.constraints),
    )


def _assembly(values: dict[str, claripy.ast.BV], fly: int) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "CloseTextDisplay")
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    q = location.address
    project.hook(q, Sm83LoadAImmediate(W_CUR_MAP, q + 3), length=3)
    project.hook(q + 3, CallBoundary(1, q + 6), length=3)
    project.hook(q + 8, Sm83StoreAHighImmediate(0xB0, q + 10), length=2)
    project.hook(q + 10, CallBoundary(2, q + 13), length=3)
    project.hook(q + 13, CallBoundary(3, q + 16), length=3)
    project.hook(q + 17, Sm83StoreAHighImmediate(0xBA, q + 19), length=2)
    # Restore loop; p-code handles the individual register/memory operations.
    project.hook(q + 0x23, SetAImmediate(q + 0x25), length=2)
    project.hook(q + 0x25, Sm83StoreAHighImmediate(0xB8, q + 0x27), length=2)
    project.hook(q + 0x2A, CallBoundary(4, q + 0x2D), length=3)
    # Split before the bank-register store so the following CALL is a hook
    # boundary rather than an embedded instruction in one lifted block.
    project.hook(q + 0x27, Sm83StoreAImmediate(R_ROMB, q + 0x2A), length=3)
    project.hook(q + 0x32, Sm83LoadAImmediate(W_STATUS_FLAGS6, q + 0x35), length=3)
    project.hook(q + 0x35, BitFly(q + 0x37), length=2)
    # The conditional player-graphics call is taken only when BIT_FLY_WARP is clear.
    project.hook(q + 0x37, ConditionalPlayerGraphicsCall(), length=3)
    project.hook(q + 0x3A, CallBoundary(6, q + 0x3D), length=3)
    project.hook(q + 0x3D, PopAF(), length=1)
    project.hook(q + 0x3E, Sm83StoreAHighImmediate(0xB8, q + 0x40), length=2)
    project.hook(q + 0x40, Sm83StoreAImmediate(R_ROMB, q + 0x43), length=3)
    # Tail continuation is the real UpdateSprites target.
    update = symbol_location(SYMBOLS, "UpdateSprites")
    project.hook(update.address, ReturnUpdateSprites(), length=25)
    state = project.factory.blank_state(addr=q)
    set_assembly_registers(state, values)
    state.regs.sp = STACK
    state.memory.store(STACK, sm83_flags_to_z80(values["saved_f"]), endness="Iend_LE")
    state.memory.store(STACK + 1, values["saved_a"], endness="Iend_LE")
    _setup(state, values, 0, fly)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    ends = collect_returns(project, state, RETURN)
    return [_endpoint(end, 0, False) for end in ends]


def _native(values: dict[str, claripy.ast.BV], fly: int) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_close_text_display")
    assert function is not None
    symbols = {
        "port_switch_to_map_rom_bank": 1,
        "port_delay_frame": 2,
        "port_load_gb_pal": 3,
        "port_init_map_sprites": 4,
        "port_load_player_sprite_graphics": 5,
        "port_load_current_map_view": 6,
        "port_update_sprites": 7,
    }
    for name, call_id in symbols.items():
        symbol = project.loader.find_symbol(name)
        assert symbol is not None
        procedure = (NativeLoadGbPalBoundary(call_id)
                     if name == "port_load_gb_pal" else NativeCallBoundary(call_id))
        project.hook(symbol.rebased_addr, procedure)
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, values["saved_a"])
    state.memory.store(NATIVE_STATE + 9, values["saved_f"])
    state.memory.store(NATIVE_STATE + 10, values["map_pal"])
    state.memory.store(NATIVE_STATE + 11, values["bgp"])
    state.memory.store(NATIVE_STATE + 12, values["obp0"])
    state.memory.store(NATIVE_STATE + 13, values["obp1"])
    state.memory.store(NATIVE_STATE + 14, claripy.BVV(0, 8))
    _setup(state, values, NATIVE_MEMORY, fly)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [_endpoint(manager.deadended[0], NATIVE_MEMORY, True)]


@pytest.mark.skipif(not ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("fly", (0, 1))
def test_close_text_display_pathwise_equivalence(fly: int) -> None:
    values = _inputs(f"close_text_display_{fly}")
    assert_pathwise_equivalent(
        _assembly(values, fly), _native(values, fly),
        (*REGISTERS, "memory", "calls"),
    )
