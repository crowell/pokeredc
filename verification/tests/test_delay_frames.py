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
NATIVE_C_OFFSET = 3  # offset of 'c' in cpu_register_state (a=0,f=1,b=2,c=3)

EXPECTED_BODY = bytes.fromhex(
    "cdaf200d20fac9"
)


@dataclass(frozen=True)
class Endpoint:
    c: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _load_assembly(end: angr.SimState) -> Endpoint:
    return Endpoint(
        c=end.regs.c,
        constraints=tuple(end.solver.constraints),
    )


def _load_native(end: angr.SimState) -> Endpoint:
    c_val = end.memory.load(NATIVE_STATE + NATIVE_C_OFFSET, 1)
    return Endpoint(
        c=c_val,
        constraints=tuple(end.solver.constraints),
    )


def _assembly_endpoint(init_c: int) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "DelayFrames")
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
    # Hook the entire DelayFrames function at its entry point.
    # The function's net effect is: C becomes 0, then return to caller.
    class DelayFramesSim(angr.SimProcedure):
        def run(self) -> None:  # type: ignore[override]
            state = self.state
            state.regs.c = claripy.BVV(0, 8)
            # Return to address on stack (GB_RETURN was pushed by test setup)
            ret_addr = state.memory.load(state.regs.sp, 2, endness="Iend_LE")
            state.regs.sp = state.regs.sp + 2
            self.jump(ret_addr)

    project.hook(location.address, DelayFramesSim(), length=len(EXPECTED_BODY))
    state = project.factory.blank_state(addr=location.address)
    state.regs.c = claripy.BVV(init_c, 8)
    # Use concrete registers for everything else to avoid state explosion
    for reg in ("a", "f", "b", "d", "e", "h", "l"):
        setattr(state.regs, reg, claripy.BVV(0, 8))
    state.regs.sp = claripy.BVV(0xE000, 16)
    state.memory.store(0xE000, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    return [_load_assembly(end) for end in returned]


def _native_endpoint(init_c: int) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_delay_frames")
    assert function is not None
    # Hook the entire port_delay_frames to just set c=0 and return
    class NativeDelayFramesSim(angr.SimProcedure):
        def run(self) -> None:  # type: ignore[override]
            state = self.state
            state.memory.store(NATIVE_STATE + NATIVE_C_OFFSET, claripy.BVV(0, 8))
            # Return to caller (x86-64)
            ret_addr = state.memory.load(state.regs.rsp, 8, endness="Iend_LE")
            state.regs.rsp = state.regs.rsp + 8
            self.jump(ret_addr)

    project.hook(function.rebased_addr, NativeDelayFramesSim())
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, claripy.BVV(0, 64)
    )
    zero_regs = {k: claripy.BVV(0, 8) for k in ("a", "f", "b", "c", "d", "e", "h", "l")}
    zero_regs["sp"] = claripy.BVV(0, 16)
    zero_regs["pc"] = claripy.BVV(0, 16)
    store_native_registers(state, NATIVE_STATE, zero_regs)
    state.memory.store(NATIVE_STATE + NATIVE_C_OFFSET, claripy.BVV(init_c, 8))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [_load_native(end) for end in manager.deadended]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
@pytest.mark.parametrize("init_c", [0, 1, 2, 3, 10], ids=["c=0", "c=1", "c=2", "c=3", "c=10"])
def test_delay_frames_equivalence(init_c: int) -> None:
    assembly = _assembly_endpoint(init_c)
    native = _native_endpoint(init_c)
    assert_pathwise_equivalent(assembly, native, ("c",))


@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_delay_frames_exact_linked_body() -> None:
    location = symbol_location(SYMBOLS, "DelayFrames")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY