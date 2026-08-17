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

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
GB_STACK = 0xD000
GB_RETURN = 0xFFFF
NATIVE_STATE = 0x100000

W_TEXT_BOX_ID = 0xD125
MESSAGE_BOX = 0x01
BOX_COORD_BC = 0xC4B9  # bccoord 1, 14 (W_TILE_MAP + 14*20 + 1)


@dataclass(frozen=True)
class Endpoint:
    wTextBox_id: claripy.ast.BV
    hl: claripy.ast.BV
    bc: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class PrintTextInline(angr.SimProcedure):
    """Model the `jp PrintText` tail: wTextBoxID = MESSAGE_BOX, BC = (1,14).

    PrintText writes wTextBoxID and loads BC with the box coordinate, then
    hands HL (already loaded with the text pointer) to the renderer. Those are
    its only observable effects; the renderer tail is a boundary.
    """

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.state.memory.store(W_TEXT_BOX_ID, claripy.BVV(MESSAGE_BOX, 8))
        self.state.regs.bc = claripy.BVV(BOX_COORD_BC, 16)
        self.state.regs.sp = claripy.BVV(GB_STACK + 2, 16)
        self.jump(GB_RETURN)


def _assembly_endpoints() -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "PrintButItFailedText_")
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
    # `ld hl, ButItFailedText` (offset 0) is decoded natively; `jp PrintText`
    # (offset 3) is replaced by the inlined PrintText effect.
    project.hook(q + 3, PrintTextInline(), length=3)

    state = project.factory.blank_state(addr=q)
    state.regs.sp = GB_STACK + 0x20

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
    fn = project.loader.find_symbol("port_print_but_it_failed_text_")
    assert fn is not None
    state = project.factory.call_state(fn.rebased_addr, NATIVE_STATE, claripy.BVV(0, 64))
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
def test_print_but_it_failed_text__symbolic_equivalence() -> None:
    assert_pathwise_equivalent(
        _assembly_endpoints(),
        _native_endpoints(),
        ("wTextBox_id", "hl", "bc"),
    )
