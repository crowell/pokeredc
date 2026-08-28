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
    store_native_registers,
)
from verification.harness.rom import collect_returns, linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import (
    Sm83AddImmediate, Sm83AddRegister, Sm83AndImmediate, Sm83AndRegister,
    Sm83BitRegister, Sm83CpImmediate, Sm83CpRegister, Sm83DecRegister,
    Sm83LoadAAtHlIncrement, Sm83LoadAHighImmediate, Sm83LoadAImmediate,
    Sm83SlaRegister, Sm83SwapRegister,
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

W_UPDATE = 0xCFCB
W_SPRITE_STATE_DATA1 = 0xC100
W_SPRITE_STATE_DATA2 = 0xC200
W_SHADOW_OAM = 0xC300
H_SPRITE_OFFSET = 0xFF8F
H_OAM_OFFSET = 0xFF90
H_SCREEN_X = 0xFF91
H_SCREEN_Y = 0xFF92
H_PRIORITY = 0xFF94
H_MOVEMENT_FLAGS = 0xD736
W_SAVED_IMAGE = 0xD5CD
SPRITE_TABLE = 0x4000


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


class HideSpritesBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        for offset in range(0, 160, 4):
            self.state.memory.store(W_SHADOW_OAM + offset, claripy.BVV(0xA0, 8))
        self.state.regs.a = claripy.BVV(0xA0, 8)
        self.state.regs.f = claripy.BVV(0x42, 8)
        self.state.regs.b = claripy.BVV(0, 8)
        self.state.regs.d = claripy.BVV(0, 8)
        self.state.regs.e = claripy.BVV(4, 8)
        self.state.regs.h = claripy.BVV(0xC3, 8)
        self.state.regs.l = claripy.BVV(0xA0, 8)
        self.jump(RETURN)


class JumpBoundary(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__()
        self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.jump(self.target)


class LoadAAtDE(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__(); self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self.state.regs.de, 1)
        self.jump(self.target)


class BranchZ(angr.SimProcedure):
    def __init__(self, taken: int, fallthrough: int) -> None:
        super().__init__(); self.taken = taken; self.fallthrough = fallthrough

    def run(self) -> None:  # type: ignore[override]
        z = ((self.state.regs.f >> 6) & 1) == 1
        taken = self.state.copy(); fallthrough = self.state.copy()
        taken.solver.add(z); fallthrough.solver.add(claripy.Not(z))
        taken.regs.ip = claripy.BVV(self.taken, 16)
        fallthrough.regs.ip = claripy.BVV(self.fallthrough, 16)
        self.inhibit_autoret = True
        self.successors.add_successor(taken, self.taken, z, "Ijk_Boring")
        self.successors.add_successor(
            fallthrough, self.fallthrough, claripy.Not(z), "Ijk_Boring"
        )


class BranchNZ(BranchZ):
    def run(self) -> None:  # type: ignore[override]
        z = ((self.state.regs.f >> 6) & 1) == 0
        taken = self.state.copy(); fallthrough = self.state.copy()
        taken.solver.add(z); fallthrough.solver.add(claripy.Not(z))
        taken.regs.ip = claripy.BVV(self.taken, 16)
        fallthrough.regs.ip = claripy.BVV(self.fallthrough, 16)
        self.inhibit_autoret = True
        self.successors.add_successor(taken, self.taken, z, "Ijk_Boring")
        self.successors.add_successor(
            fallthrough, self.fallthrough, claripy.Not(z), "Ijk_Boring"
        )


class BranchC(angr.SimProcedure):
    def __init__(self, taken: int, fallthrough: int) -> None:
        super().__init__(); self.taken = taken; self.fallthrough = fallthrough

    def run(self) -> None:  # type: ignore[override]
        c = (self.state.regs.f & 1) == 1
        taken = self.state.copy(); fallthrough = self.state.copy()
        taken.solver.add(c); fallthrough.solver.add(claripy.Not(c))
        taken.regs.ip = claripy.BVV(self.taken, 16)
        fallthrough.regs.ip = claripy.BVV(self.fallthrough, 16)
        self.inhibit_autoret = True
        self.successors.add_successor(taken, self.taken, c, "Ijk_Boring")
        self.successors.add_successor(
            fallthrough, self.fallthrough, claripy.Not(c), "Ijk_Boring"
        )


class RetZ(BranchZ):
    pass


class StoreBAtHL(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__(); self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(self.state.regs.hl, self.state.regs.b)
        self.jump(self.target)


class LoadHAtHL(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__(); self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = self.state.memory.load(self.state.regs.hl, 1)
        self.jump(self.target)


class PopBC(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__(); self.target = target

    def run(self) -> None:  # type: ignore[override]
        sp = self.state.solver.eval(self.state.regs.sp)
        self.state.regs.c = self.state.memory.load(sp, 1)
        self.state.regs.b = self.state.memory.load(sp + 1, 1)
        self.state.regs.sp = claripy.BVV(sp + 2, 16)
        self.jump(self.target)


class PushBC(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__(); self.target = target

    def run(self) -> None:  # type: ignore[override]
        sp = self.state.solver.eval(self.state.regs.sp)
        self.state.memory.store(sp - 1, self.state.regs.b)
        self.state.memory.store(sp - 2, self.state.regs.c)
        self.state.regs.sp = claripy.BVV(sp - 2, 16)
        self.jump(self.target)


class PopDE(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__(); self.target = target

    def run(self) -> None:  # type: ignore[override]
        sp = self.state.solver.eval(self.state.regs.sp)
        self.state.regs.e = self.state.memory.load(sp, 1)
        self.state.regs.d = self.state.memory.load(sp + 1, 1)
        self.state.regs.sp = claripy.BVV(sp + 2, 16)
        self.jump(self.target)


class PushDE(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__(); self.target = target

    def run(self) -> None:  # type: ignore[override]
        sp = self.state.solver.eval(self.state.regs.sp)
        self.state.memory.store(sp - 1, self.state.regs.d)
        self.state.memory.store(sp - 2, self.state.regs.e)
        self.state.regs.sp = claripy.BVV(sp - 2, 16)
        self.jump(self.target)


class AddHLDE(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__(); self.target = target

    def run(self) -> None:  # type: ignore[override]
        left = self.state.regs.hl
        right = self.state.regs.de
        wide = claripy.ZeroExt(1, left) + claripy.ZeroExt(1, right)
        self.state.regs.hl = wide[15:0]
        self.state.regs.f = claripy.If(
            ((left & 0x0fff) + (right & 0x0fff)) > 0x0fff,
            claripy.BVV(0x20, 8), claripy.BVV(0, 8)
        ) | claripy.If(wide[16] == 1, claripy.BVV(0x10, 8), claripy.BVV(0, 8))
        self.jump(self.target)


class GetSpriteScreenXYBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        d = self.state.solver.eval(self.state.regs.d)
        e = self.state.solver.eval(self.state.regs.e)
        base = (d << 8) | e
        y = self.state.memory.load(base + 2, 1)
        x = self.state.memory.load(base + 4, 1)
        self.state.memory.store(H_SCREEN_Y, y)
        self.state.memory.store(H_SCREEN_X, x)
        y_adjusted = (y + 4) & 0xF0
        x_adjusted = x & 0xF0
        self.state.memory.store(base + 8, y_adjusted)
        self.state.memory.store(base + 9, x_adjusted)
        self.state.regs.e = claripy.BVV((e + 9) & 0xFF, 8)
        self.state.regs.a = x_adjusted
        self.state.regs.f = claripy.If(
            x_adjusted == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)
        )
        self.jump(self.state.addr + 3)


class Bit6A(angr.SimProcedure):
    def __init__(self, target: int) -> None:
        super().__init__(); self.target = target

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.f = claripy.If(
            (self.state.regs.a & 0x40) == 0,
            claripy.BVV(0x40, 8), claripy.BVV(0, 8)
        )
        self.jump(self.target)


def _setup(state: angr.SimState, base: int, *, enabled: int,
           offscreen: bool = False, visible: bool = False) -> None:
    state.memory.store(base + W_UPDATE, claripy.BVV(enabled, 8))
    state.memory.store(base + H_MOVEMENT_FLAGS, claripy.BVV(0, 8))
    state.memory.store(base + W_SPRITE_STATE_DATA2 + 5, claripy.BVV(0, 8))
    for address, value in ((H_SPRITE_OFFSET, 0x31), (H_OAM_OFFSET, 0x42),
                           (0xFF91, 0x53), (0xFF92, 0x64), (0xFF94, 0x75)):
        state.memory.store(base + address, claripy.BVV(value, 8))
    for offset in range(0, 0x100, 0x10):
        state.memory.store(base + W_SPRITE_STATE_DATA1 + offset,
                           claripy.BVV(0, 8))
    for offset, value in ((2, 0x22), (4, 0x33), (6, 0x44),
                          (10, 0x55), (11, 0x66)):
        state.memory.store(base + W_SPRITE_STATE_DATA1 + offset,
                           claripy.BVV(value, 8))
    state.memory.store(base + W_SAVED_IMAGE, claripy.BVV(0x77, 8))
    if offscreen:
        state.memory.store(base + W_SPRITE_STATE_DATA1, claripy.BVV(1, 8))
        state.memory.store(base + W_SPRITE_STATE_DATA1 + 2, claripy.BVV(0xFF, 8))
        state.memory.store(base + W_SPRITE_STATE_DATA1 + 4, claripy.BVV(0x2C, 8))
        state.memory.store(base + W_SPRITE_STATE_DATA1 + 6, claripy.BVV(0x3D, 8))
    if visible:
        state.memory.store(base + W_SPRITE_STATE_DATA1, claripy.BVV(1, 8))
        state.memory.store(base + W_SPRITE_STATE_DATA1 + 2, claripy.BVV(0, 8))
        state.memory.store(base + W_SPRITE_STATE_DATA1 + 4, claripy.BVV(0x2C, 8))
        state.memory.store(base + W_SPRITE_STATE_DATA1 + 6, claripy.BVV(0x3D, 8))
        for offset, value in enumerate((0x80, 0x40, 0x98, 0x40)):
            state.memory.store(base + SPRITE_TABLE + offset,
                               claripy.BVV(value, 8))
        for offset, value in enumerate((0, 1, 2, 3)):
            state.memory.store(base + 0x4080 + offset, claripy.BVV(value, 8))
        for offset, value in enumerate((0, 0, 0, 0, 8, 0, 2, 8, 0, 8, 8, 3)):
            state.memory.store(base + 0x4098 + offset, claripy.BVV(value, 8))
    for i in range(160):
        state.memory.store(base + W_SHADOW_OAM + i, claripy.BVV((i * 7 + 3) & 0xff, 8))


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    pieces = [state.memory.load(base + address, 1)
              for address in (W_UPDATE, H_SPRITE_OFFSET, H_OAM_OFFSET,
                              H_SCREEN_X, H_SCREEN_Y, H_PRIORITY,
                              H_MOVEMENT_FLAGS, W_SAVED_IMAGE)]
    pieces.extend(state.memory.load(base + W_SPRITE_STATE_DATA1 + offset, 1)
                  for offset in (0, 2, 4, 6, 10, 11))
    pieces.append(state.memory.load(base + W_SHADOW_OAM, 160))
    return claripy.Concat(*pieces)


def _endpoint(state: angr.SimState, *, native: bool, base: int) -> Endpoint:
    return Endpoint(
        **(native_registers(state, NATIVE_STATE) if native else assembly_registers(state)),
        memory=_memory(state, base), constraints=tuple(state.solver.constraints),
    )


def _assembly(values: dict[str, claripy.ast.BV], *, enabled: int,
              offscreen: bool, visible: bool) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "PrepareOAMData")
    tail = symbol_location(SYMBOLS, "GetSpriteScreenXY")
    assert linked_bytes(ROM, location, tail.address - location.address) == bytes.fromhex(
        "facbcf3d2809feffc0eacbcfc38d00afe090e08f16c1f08f5f1aa7caad4b1c1c1aeacdd5feff2005cdd14b1871fea03806e60fc6101802e60f6fd5147bc6055f1ae680e094d126000100402929092a4f2a472a666fcdd14bf0905f16c3f092c610861223f091c608861c121c0a03c547facdd5cb37e60ffe0b20043e7c1808cb27cb274fcb278180c112231c7ecb4f2803f094b623121ccb4728c27be090f08fc610fe00c2214bf0906f26c311040006a0fa36d7cb773ea028023e90bdc8701918fa"
    )
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    q = location.address
    project.hook(q + 0x00, Sm83LoadAImmediate(W_UPDATE, q + 0x03), length=3)
    project.hook(q + 0x03, Sm83DecRegister("a", q + 0x04), length=1)
    project.hook(q + 0x06, Sm83CpImmediate(0xff, q + 0x08), length=2)
    project.hook(q + 0x09, Sm83StoreAImmediate(W_UPDATE, q + 0x0c), length=3)
    project.hook(q + 0x0c, JumpBoundary(0x008D), length=3)
    project.hook(0x008D, HideSpritesBoundary(), length=1)
    if enabled == 1:
        project.hook(q + 0x10, Sm83StoreAHighImmediate(0x90, q + 0x12), length=2)
        project.hook(q + 0x12, Sm83StoreAHighImmediate(0x8F, q + 0x14), length=2)
        project.hook(q + 0x16, Sm83LoadAHighImmediate(0x8F, q + 0x18), length=2)
        project.hook(q + 0x19, LoadAAtDE(q + 0x1A), length=1)
        project.hook(q + 0x1A, Sm83AndRegister("a", q + 0x1B), length=1)
        project.hook(q + 0x1B, BranchZ(q + 0x9E, q + 0x1E), length=3)
        if offscreen or visible:
            project.hook(q + 0x20, LoadAAtDE(q + 0x21), length=1)
            project.hook(q + 0x21, Sm83StoreAImmediate(W_SAVED_IMAGE, q + 0x24), length=3)
            project.hook(q + 0x24, Sm83CpImmediate(0xFF, q + 0x26), length=2)
            project.hook(q + 0x26, BranchNZ(q + 0x2D, q + 0x28), length=2)
            project.hook(q + 0x28, GetSpriteScreenXYBoundary(), length=3)
            project.hook(q + 0x2B, JumpBoundary(q + 0x9E), length=2)
        if visible:
            project.hook(q + 0x2D, Sm83CpImmediate(0xA0, q + 0x2F), length=2)
            project.hook(q + 0x2F, BranchC(q + 0x37, q + 0x31), length=2)
            project.hook(q + 0x31, Sm83AndImmediate(0x0F, q + 0x33), length=2)
            project.hook(q + 0x3A, PushDE(q + 0x3B), length=1)
            project.hook(q + 0x40, LoadAAtDE(q + 0x41), length=1)
            project.hook(q + 0x41, Sm83AndImmediate(0x80, q + 0x43), length=2)
            project.hook(q + 0x43, Sm83StoreAHighImmediate(0x94, q + 0x45), length=2)
            project.hook(q + 0x45, PopDE(q + 0x46), length=1)
            project.hook(q + 0x4E, Sm83LoadAAtHlIncrement(q + 0x4F), length=1)
            project.hook(q + 0x50, Sm83LoadAAtHlIncrement(q + 0x51), length=1)
            project.hook(q + 0x52, Sm83LoadAAtHlIncrement(q + 0x53), length=1)
            project.hook(q + 0x53, LoadHAtHL(q + 0x54), length=1)
            project.hook(q + 0x55, GetSpriteScreenXYBoundary(), length=3)
            project.hook(q + 0x58, Sm83LoadAHighImmediate(0x90, q + 0x5A), length=2)
            project.hook(q + 0x5D, Sm83LoadAHighImmediate(0x92, q + 0x5F), length=2)
            project.hook(q + 0x64, Sm83LoadAHighImmediate(0x91, q + 0x66), length=2)
            project.hook(q + 0x70, Sm83LoadAImmediate(W_SAVED_IMAGE, q + 0x73), length=3)
            project.hook(q + 0x73, Sm83SwapRegister("a", q + 0x75), length=1)
            project.hook(q + 0x75, Sm83AndImmediate(0x0F, q + 0x77), length=2)
            project.hook(q + 0x76, Sm83CpRegister("b", q + 0x78), length=2)
            project.hook(q + 0x78, BranchNZ(q + 0x7E, q + 0x7A), length=2)
            for offset, target in ((0x7F, 0x81), (0x81, 0x83),
                                   (0x84, 0x86)):
                project.hook(q + offset, Sm83SlaRegister("a", q + target), length=2)
            project.hook(q + 0x86, Sm83AddRegister("c", q + 0x87), length=1)
            project.hook(q + 0x87, Sm83AddRegister("b", q + 0x88), length=1)
            project.hook(q + 0x6E, PushBC(q + 0x6F), length=1)
            project.hook(q + 0x88, PopBC(q + 0x89), length=1)
            project.hook(q + 0x8D, Sm83BitRegister(1, "a", q + 0x8F), length=2)
            project.hook(q + 0x8F, BranchZ(q + 0x94, q + 0x91), length=2)
            project.hook(q + 0x91, Sm83LoadAHighImmediate(0x94, q + 0x93), length=2)
            project.hook(q + 0x97, Sm83BitRegister(0, "a", q + 0x99), length=2)
            project.hook(q + 0x99, BranchZ(q + 0x5D, q + 0x9B), length=2)
            project.hook(q + 0x9C, Sm83StoreAHighImmediate(0x90, q + 0x9E), length=2)
        project.hook(q + 0x9E, Sm83LoadAHighImmediate(0x8F, q + 0xA0), length=2)
        project.hook(q + 0xA2, Sm83CpImmediate(0, q + 0xA4), length=2)
        project.hook(q + 0xA4, BranchNZ(q + 0x12, q + 0xA7), length=3)
        project.hook(q + 0xA7, Sm83LoadAHighImmediate(0x90, q + 0xA9), length=2)
        project.hook(q + 0xB1, Sm83LoadAImmediate(H_MOVEMENT_FLAGS, q + 0xB4), length=3)
        project.hook(q + 0xB4, Bit6A(q + 0xB6), length=2)
        project.hook(q + 0xB8, BranchZ(q + 0xBC, q + 0xBA), length=2)
        project.hook(q + 0xBC, Sm83CpRegister("l", q + 0xBD), length=1)
        project.hook(q + 0xBD, RetZ(RETURN, q + 0xBE), length=1)
        project.hook(q + 0xBE, StoreBAtHL(q + 0xBF), length=1)
        project.hook(q + 0xBF, AddHLDE(q + 0xC0), length=1)
        project.hook(q + 0xC0, JumpBoundary(q + 0xBC), length=2)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    _setup(state, 0, enabled=enabled, offscreen=offscreen, visible=visible)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    return [_endpoint(end, native=False, base=0)
            for end in collect_returns(project, state, RETURN)]


def _native(values: dict[str, claripy.ast.BV], *, enabled: int,
            offscreen: bool, visible: bool) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_prepare_oam_data")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, NATIVE_MEMORY, enabled=enabled, offscreen=offscreen,
           visible=visible)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and manager.deadended
    return [_endpoint(end, native=True, base=NATIVE_MEMORY)
            for end in manager.deadended]


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),
                    reason="build artifacts missing")
@pytest.mark.parametrize("enabled,offscreen,visible", (
    (0, False, False), (1, False, False), (1, True, False), (1, False, True),
))
def test_prepare_oam_data_pathwise_equivalence(
    enabled: int, offscreen: bool, visible: bool,
) -> None:
    values = {register: claripy.BVV((index * 13 + 1) & 0xff, 8)
              for index, register in enumerate(REGISTERS)}
    assert_pathwise_equivalent(
        _assembly(values, enabled=enabled, offscreen=offscreen, visible=visible),
        _native(values, enabled=enabled, offscreen=offscreen, visible=visible),
                               (*REGISTERS, "memory"))
