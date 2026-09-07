"""Regression for the SM83 LD instruction adapters (loads preserve flags)."""
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.rom import rom_window
from verification.harness.sm83_shims import Sm83LoadAFromImmediate, Sm83LoadAFromRegister


@pytest.mark.parametrize("source", ["immediate", "e", "a"])
def test_ld_a_preserves_every_input_flag(source):
    root = Path(__file__).resolve().parents[2]
    project = angr.Project(rom_window(root / "pokered.gbc", 0),
        auto_load_libs=False, rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": 0x100})
    hook = (Sm83LoadAFromImmediate(0xC000, 0x102) if source == "immediate"
            else Sm83LoadAFromRegister(source, 0x102))
    project.hook(0x100, hook)
    state = project.factory.blank_state(addr=0x100)
    flags, value = claripy.BVS("input_flags", 8), claripy.BVS("source_byte", 8)
    state.regs.f = flags
    if source == "immediate": state.memory.store(0xC000, value)
    else: setattr(state.regs, source, value)
    results = project.factory.successors(state).flat_successors
    assert len(results) == 1
    end = results[0]
    assert not end.solver.satisfiable(extra_constraints=(end.regs.f != flags,))
    assert not end.solver.satisfiable(extra_constraints=(end.regs.a != value,))
