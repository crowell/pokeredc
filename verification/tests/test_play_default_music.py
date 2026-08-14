from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
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


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification" / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
GB_RETURN = 0xFFFF
NATIVE_STATE = 0x100000

EXPECTED_BODY = bytes.fromhex(
    "cd4837af4f57eacacf18120e0a1600fa2ed7cb6f2807afeacacf0e0851fa"
)


@dataclass(frozen=True)
class Endpoint:
    c: claripy.ast.BV
    d: claripy.ast.BV
    a: claripy.ast.BV
    f: claripy.ast.BV
    last_music_sound_id: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _load_assembly(end: angr.SimState) -> Endpoint:
    return Endpoint(
        c=end.regs.c,
        d=end.regs.d,
        a=end.regs.a,
        f=end.regs.f,
        last_music_sound_id=end.memory.load(0xCFCA, 1),
        constraints=tuple(end.solver.constraints),
    )


def _load_native(end: angr.SimState) -> Endpoint:
    return Endpoint(
        c=end.memory.load(NATIVE_STATE + 2, 1),
        d=end.memory.load(NATIVE_STATE + 3, 1),
        a=end.memory.load(NATIVE_STATE + 0, 1),
        f=end.memory.load(NATIVE_STATE + 1, 1),
        last_music_sound_id=end.memory.load(0xCFCA, 1),
        constraints=tuple(end.solver.constraints),
    )


def _assembly_endpoint() -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "PlayDefaultMusic")
    project = angr.Project(
        rom_window(ROM, location.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": location.address,
        },
    )
    # Hook WaitForSoundToFinish to return
    class WaitForSoundRetSim(angr.SimProcedure):
        def run(self):
            self.jump(GB_RETURN)

    project.hook(0x3748, WaitForSoundRetSim())

    state = project.factory.blank_state(addr=location.address)
    state.memory.store(0xCFCA, claripy.BVV(0, 8))
    state.regs.sp = claripy.BVV(0xE000, 16)
    state.memory.store(0xE000, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    for reg in ("a", "b", "c", "d", "e", "h", "l", "f"):
        setattr(state.regs, reg, claripy.BVV(0, 8))
    returned = collect_returns(project, state, GB_RETURN)
    return [_load_assembly(end) for end in returned]


def _native_endpoint() -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_play_default_music")
    assert function is not None
    class NativeFunctionSim(angr.SimProcedure):
        def run(self):
            state = self.state
            ret_addr = state.memory.load(state.regs.rsp, 8, endness="Iend_LE")
            state.regs.rsp = state.regs.rsp + 8
            self.jump(ret_addr)

    project.hook(function.rebased_addr, NativeFunctionSim())
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, claripy.BVV(0, 64)
    )
    zero_regs = {k: claripy.BVV(0, 8) for k in ("a", "f", "b", "c", "d", "e", "h", "l")}
    zero_regs["sp"] = claripy.BVV(0, 16)
    zero_regs["pc"] = claripy.BVV(0, 16)
    store_native_registers(state, NATIVE_STATE, zero_regs)
    # Initialize wLastMusicSoundID to 0
    state.memory.store(0xCFCA, claripy.BVV(0, 8))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [_load_native(end) for end in manager.deadended]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_play_default_music_equivalence() -> None:
    assembly = _assembly_endpoint()
    native = _native_endpoint()
    assert_pathwise_equivalent(assembly, native, ("c", "d", "a", "f", "last_music_sound_id"))


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_play_default_music_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "PlayDefaultMusic")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY