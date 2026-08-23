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
from verification.harness.rom import collect_returns, rom_window, symbol_location
from verification.harness.sm83_shims import (
    Sm83LoadAHighImmediate,
    Sm83StoreAHighImmediate,
)


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification" / "build" / "ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
GB_STACK = 0xD000
GB_RETURN = 0xFFFF
NATIVE_STATE = 0x100000

R_WX = 0xFF4B
R_BGP = 0xFF47


class DelayFrameInline(angr.SimProcedure):
    """Terminal transition of the independently proven DelayFrame."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x50, 8)
        self.jump(self._next_address)


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
    r_wx: claripy.ast.BV
    r_bgp: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _assembly_endpoint(
    inputs: dict[str, claripy.ast.BV],
) -> Endpoint:
    location = symbol_location(SYMBOLS, "MovePicLeft")
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
    base = location.address
    # Memory-access / external-call hooks only; arithmetic and control flow run
    # natively. Offsets verified from the disassembly of the linked body.
    project.hook(base + 0x02, Sm83StoreAHighImmediate(0x4B, base + 0x04), length=2)  # ldh [rWX],a
    project.hook(base + 0x04, DelayFrameInline(base + 0x07), length=3)  # call DelayFrame
    project.hook(base + 0x09, Sm83StoreAHighImmediate(0x47, base + 0x0B), length=2)  # ldh [rBGP],a
    project.hook(base + 0x0B, DelayFrameInline(base + 0x0E), length=3)  # call DelayFrame (loop)
    project.hook(base + 0x0E, Sm83LoadAHighImmediate(0x4B, base + 0x10), length=2)  # ldh a,[rWX]
    project.hook(base + 0x15, Sm83StoreAHighImmediate(0x4B, base + 0x17), length=2)  # ldh [rWX],a
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, inputs)
    state.regs.sp = claripy.BVV(GB_STACK, 16)
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    assert len(returned) == 1
    end = returned[0]
    return Endpoint(
        **assembly_registers(end),
        r_wx=end.memory.load(R_WX, 1),
        r_bgp=end.memory.load(R_BGP, 1),
        constraints=tuple(end.solver.constraints),
    )


def _native_endpoint(
    inputs: dict[str, claripy.ast.BV],
) -> Endpoint:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_move_pic_left")
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, claripy.BVV(0, 64)
    )
    store_native_registers(state, NATIVE_STATE, inputs)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    end = manager.deadended[0]
    return Endpoint(
        **native_registers(end, NATIVE_STATE),
        r_wx=end.memory.load(R_WX, 1),
        r_bgp=end.memory.load(R_BGP, 1),
        constraints=tuple(end.solver.constraints),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_move_pic_left_symbolic_equivalence() -> None:
    inputs = symbolic_registers("mpl")
    assembly = _assembly_endpoint(inputs)
    native = _native_endpoint(inputs)
    assert_pathwise_equivalent(
        [assembly],
        [native],
        ("a", "f", "b", "c", "d", "e", "h", "l", "r_wx", "r_bgp"),
    )
