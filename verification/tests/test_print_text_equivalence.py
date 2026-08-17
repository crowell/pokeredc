from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode
from pypcode import Context

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.rom import symbol_location, rom_window
from verification.harness.sm83_shims import Sm83StoreAImmediate

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
GB_STACK = 0xD000
GB_RETURN = 0xFFFF
NATIVE_STATE = 0x100000

W_TEXT_BOX_ID = 0xD125
# Continuation text pointer (HL) is an input that PrintText preserves.
HL = claripy.BVS("print_text_hl", 16)


@dataclass(frozen=True)
class Endpoint:
    wTextBox_id: claripy.ast.BV
    hl: claripy.ast.BV
    bc: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class SkipCall(angr.SimProcedure):
    """Replace a `call` with an unconditional jump past it (no-op sub-routine).

    DisplayTextBoxID / UpdateSprites / Delay3 are display-only and have no
    observable RAM effect for PrintText, so the native port models them as
    no-ops; the assembly hook must likewise skip them.
    """

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next = next_address

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.jump(self._next)


class DoRet(angr.SimProcedure):
    """Unconditional return: jump to the GB return sentinel."""

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.state.regs.sp = claripy.BVV(GB_STACK + 2, 16)
        self.jump(GB_RETURN)


def _assembly_endpoints() -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "PrintText")
    q = location.address
    project = angr.Project(
        rom_window(ROM, location.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": q,
        },
    )
    project.hook(q + 3, Sm83StoreAImmediate(W_TEXT_BOX_ID, q + 6), length=3)  # ld [wTextBoxID],a
    project.hook(q + 6, SkipCall(q + 9), length=3)  # call DisplayTextBoxID
    project.hook(q + 9, SkipCall(q + 12), length=3)  # call UpdateSprites
    project.hook(q + 12, SkipCall(q + 15), length=3)  # call Delay3
    project.hook(q + 19, DoRet(), length=3)  # jp TextCommandProcessor (tail boundary)

    state = project.factory.blank_state(addr=q)
    state.regs.sp = GB_STACK + 0x20
    state.regs.h = HL[15:8]
    state.regs.l = HL[7:0]

    from verification.harness.rom import collect_returns

    return [
        Endpoint(
            wTextBox_id=end.memory.load(W_TEXT_BOX_ID, 1),
            hl=end.regs.hl,
            bc=end.regs.bc,
            constraints=tuple(end.solver.constraints),
        )
        for end in collect_returns(project, state, GB_RETURN)
    ]


def _native_endpoints() -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    fn = project.loader.find_symbol("port_print_text")
    assert fn is not None
    state = project.factory.call_state(fn.rebased_addr, NATIVE_STATE, claripy.BVV(0, 64))
    state.memory.store(NATIVE_STATE + 6, HL[15:8])
    state.memory.store(NATIVE_STATE + 7, HL[7:0])
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            wTextBox_id=end.memory.load(W_TEXT_BOX_ID, 1),
            hl=claripy.Concat(
                end.memory.load(NATIVE_STATE + 6, 1),
                end.memory.load(NATIVE_STATE + 7, 1),
            ),
            bc=claripy.Concat(
                end.memory.load(NATIVE_STATE + 2, 1),
                end.memory.load(NATIVE_STATE + 3, 1),
            ),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run `make -C verification native`")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_print_text_symbolic_equivalence() -> None:
    assert_pathwise_equivalent(
        _assembly_endpoints(),
        _native_endpoints(),
        ("wTextBox_id", "hl", "bc"),
    )
