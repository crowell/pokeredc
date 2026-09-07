from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
    REGISTERS, assembly_registers, native_registers, set_assembly_registers,
    store_native_registers, symbolic_registers,
)
from verification.harness.rom import (
    collect_returns, linked_bytes, rom_window, sm83_flags_to_z80,
    symbol_location,
)
from verification.harness.sm83_shims import Sm83CpImmediate, Sm83LoadAImmediate

ROOT = Path(__file__).resolve().parents[2]
ROM, SYMBOLS = ROOT / "pokered.gbc", ROOT / "pokered.sym"
ELF = ROOT / "verification/build/ports.elf"
NS, MEMORY, WAIT, BALL, TIMINGS = 0x100000, 0x110000, 0x120000, 0x130000, 0x140000
STACK, RETURN, SPECIES = 0xD000, 0xFFFF, 0xCD3D
EXPECTED = bytes.fromhex("fa3dcdfeb02807feb12803fe99c01e010144721600c36a72")


@dataclass(frozen=True)
class Endpoint:
    state: claripy.ast.BV
    called: claripy.ast.BV
    call: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def state_vector(state, native):
    registers = native_registers(state, NS) if native else assembly_registers(state)
    base = NS if native else 0
    memory_base = MEMORY if native else 0
    fields = state.memory.load(base + 8, 3) if native else claripy.Concat(
        state.globals["ly"], state.globals["scx"], state.globals["title_ball_y"]
    )
    return claripy.Concat(
        *(registers[name] for name in REGISTERS), fields,
        state.memory.load(memory_base + SPECIES, 1),
    )


class AssemblyTitleScrollBody(angr.SimProcedure):
    def run(self):
        registers = assembly_registers(self.state)
        self.state.globals["called"] = claripy.BVV(1, 8)
        self.state.globals["call"] = claripy.Concat(
            *(registers[name] for name in REGISTERS),
            self.state.globals["ly"], self.state.globals["scx"],
            self.state.globals["title_ball_y"],
        )
        for name in REGISTERS:
            value = self.state.globals[f"post_{name}"]
            if name == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, name, value)
        for name in ("ly", "scx", "title_ball_y"):
            self.state.globals[name] = self.state.globals[f"post_{name}"]
        target = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp += 2
        self.inhibit_autoret = True
        self.jump(target)


class NativeTitleScrollBody(angr.SimProcedure):
    def run(self, state, wait_table, ball_table, timings):
        self.state.globals["called"] = claripy.BVV(1, 8)
        self.state.globals["call"] = self.state.memory.load(state, 11)
        self.state.solver.add(wait_table == WAIT, ball_table == BALL, timings == TIMINGS)
        for offset, name in enumerate(REGISTERS):
            self.state.memory.store(state + offset, self.state.globals[f"post_{name}"])
        for offset, name in enumerate(("ly", "scx", "title_ball_y"), 8):
            self.state.memory.store(state + offset, self.state.globals[f"post_{name}"])


def inputs():
    values = symbolic_registers("title_ball")
    values["species"] = claripy.BVS("title_ball_species", 8)
    for name in ("ly", "scx", "title_ball_y"):
        values[name] = claripy.BVS(f"title_ball_{name}", 8)
    for name in (*REGISTERS, "ly", "scx", "title_ball_y"):
        values[f"post_{name}"] = (
            claripy.Concat(claripy.BVS("title_ball_post_flags", 4), claripy.BVV(0, 4))
            if name == "f" else claripy.BVS(f"title_ball_post_{name}", 8)
        )
    return values


def setup(state, values):
    state.globals["called"] = claripy.BVV(0, 8)
    state.globals["call"] = claripy.BVV(0, 88)
    for name in ("ly", "scx", "title_ball_y"):
        state.globals[name] = values[name]
    for name in (*REGISTERS, "ly", "scx", "title_ball_y"):
        state.globals[f"post_{name}"] = values[f"post_{name}"]


def assembly(values):
    location = symbol_location(SYMBOLS, "TitleScreenAnimateBallIfStarterOut")
    body = symbol_location(SYMBOLS, "_TitleScroll")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    assert body.bank == location.bank and body.address == 0x726A
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False, rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    base = location.address
    project.hook(base, Sm83LoadAImmediate(SPECIES, base + 3), length=3)
    for offset, value in ((3, 0xB0), (7, 0xB1), (11, 0x99)):
        project.hook(base + offset, Sm83CpImmediate(value, base + offset + 2), length=2)
    project.hook(body.address, AssemblyTitleScrollBody())
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.memory.store(SPECIES, values["species"])
    state.regs.sp = claripy.BVV(STACK, 16)
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    setup(state, values)
    ends = collect_returns(project, state, RETURN)
    return [Endpoint(state_vector(end, False), end.globals["called"],
                     end.globals["call"], tuple(end.solver.constraints)) for end in ends]


def native(values):
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_title_screen_animate_ball_if_starter_out")
    body = project.loader.find_symbol("port_title_scroll_body")
    assert function is not None and body is not None
    project.hook(body.rebased_addr, NativeTitleScrollBody())
    state = project.factory.call_state(
        function.rebased_addr, NS, MEMORY, WAIT, BALL, TIMINGS
    )
    store_native_registers(state, NS, values)
    state.memory.store(NS + 8, claripy.Concat(
        values["ly"], values["scx"], values["title_ball_y"]
    ))
    state.memory.store(MEMORY + SPECIES, values["species"])
    setup(state, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and not manager.unconstrained
    return [Endpoint(state_vector(end, True), end.globals["called"],
                     end.globals["call"], tuple(end.solver.constraints))
            for end in manager.deadended]


@pytest.mark.skipif(not ELF.exists(), reason="run native")
def test_title_screen_animate_ball_if_starter_out_pathwise_equivalence():
    values = inputs()
    assert_pathwise_equivalent(
        assembly(values), native(values), ("state", "called", "call")
    )
