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
    Sm83CpImmediate, Sm83DecRegister, Sm83LoadAImmediate, Sm83StoreAImmediate,
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
W_SHADOW_OAM = 0xC300


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


def _setup(state: angr.SimState, base: int) -> None:
    state.memory.store(base + W_UPDATE, claripy.BVV(0, 8))
    for i in range(160):
        state.memory.store(base + W_SHADOW_OAM + i, claripy.BVV((i * 7 + 3) & 0xff, 8))


def _memory(state: angr.SimState, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        state.memory.load(base + W_UPDATE, 1),
        state.memory.load(base + W_SHADOW_OAM, 160),
    )


def _endpoint(state: angr.SimState, *, native: bool, base: int) -> Endpoint:
    return Endpoint(
        **(native_registers(state, NATIVE_STATE) if native else assembly_registers(state)),
        memory=_memory(state, base), constraints=tuple(state.solver.constraints),
    )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
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
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    _setup(state, 0)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    return [_endpoint(end, native=False, base=0)
            for end in collect_returns(project, state, RETURN)]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_prepare_oam_data")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, NATIVE_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and manager.deadended
    return [_endpoint(end, native=True, base=NATIVE_MEMORY)
            for end in manager.deadended]


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),
                    reason="build artifacts missing")
def test_prepare_oam_data_pathwise_equivalence() -> None:
    values = {register: claripy.BVV((index * 13 + 1) & 0xff, 8)
              for index, register in enumerate(REGISTERS)}
    assert_pathwise_equivalent(_assembly(values), _native(values),
                               (*REGISTERS, "memory"))
