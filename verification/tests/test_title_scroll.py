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
    linked_bytes,
    rom_window,
    sm83_flags_to_z80,
    symbol_location,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
IN_TABLE = 0x110000
OUT_TABLE = 0x120000
BALL_TABLE = 0x130000
TIMINGS = 0x140000
DONE = 0xEFFF
EXPECTED_PREFIX = bytes.fromhex("7a01477216881e00a72007014f7216001e00")


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
    ly: claripy.ast.BV
    scx: claripy.ast.BV
    title_ball_y: claripy.ast.BV
    call: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class Sm83AndA(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.f = claripy.BVV(0x10, 8) | claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x40, 8),
            claripy.BVV(0, 8),
        )
        self.jump(self.continuation)


def _assembly_state(state: angr.SimState) -> claripy.ast.BV:
    registers = assembly_registers(state)
    return claripy.Concat(
        *(registers[name] for name in REGISTERS),
        state.globals["ly"],
        state.globals["scx"],
        state.globals["title_ball_y"],
    )


class AssemblyTitleScrollBody(angr.SimProcedure):
    """Arbitrary matching transition of the proven complete shared body."""

    def run(self) -> None:  # type: ignore[override]
        registers = assembly_registers(self.state)
        table_id = claripy.If(
            claripy.Concat(registers["b"], registers["c"]) == 0x7247,
            claripy.BVV(1, 8),
            claripy.BVV(2, 8),
        )
        self.state.globals["call"] = claripy.Concat(
            table_id,
            _assembly_state(self.state),
            claripy.BVV(BALL_TABLE, 64),
            claripy.BVV(TIMINGS, 64),
        )
        for register in REGISTERS:
            value = self.state.globals[f"body_{register}"]
            if register == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, register, value)
        for field in ("ly", "scx", "title_ball_y"):
            self.state.globals[field] = self.state.globals[f"body_{field}"]
        self.jump(DONE)


class NativeTitleScrollBody(angr.SimProcedure):
    def run(
        self,
        state: claripy.ast.BV,
        table: claripy.ast.BV,
        ball_table: claripy.ast.BV,
        timings: claripy.ast.BV,
    ) -> None:  # type: ignore[override]
        table_id = claripy.If(
            table == IN_TABLE, claripy.BVV(1, 8), claripy.BVV(2, 8)
        )
        self.state.globals["call"] = claripy.Concat(
            table_id,
            self.state.memory.load(state, 11),
            ball_table,
            timings,
        )
        for offset, register in enumerate(REGISTERS):
            self.state.memory.store(
                state + offset, self.state.globals[f"body_{register}"]
            )
        for offset, field in enumerate(("ly", "scx", "title_ball_y"), 8):
            self.state.memory.store(
                state + offset, self.state.globals[f"body_{field}"]
            )


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for field in ("ly", "scx", "title_ball_y"):
        values[field] = claripy.BVS(f"{prefix}_{field}", 8)
    for register in REGISTERS:
        values[f"body_{register}"] = (
            claripy.Concat(
                claripy.BVS(f"{prefix}_body_flags", 4),
                claripy.BVV(0, 4),
            )
            if register == "f"
            else claripy.BVS(f"{prefix}_body_{register}", 8)
        )
    for field in ("ly", "scx", "title_ball_y"):
        values[f"body_{field}"] = claripy.BVS(
            f"{prefix}_body_{field}", 8
        )
    return values


def _setup_globals(
    state: angr.SimState, values: dict[str, claripy.ast.BV]
) -> None:
    for field in ("ly", "scx", "title_ball_y"):
        state.globals[field] = values[field]
        state.globals[f"body_{field}"] = values[f"body_{field}"]
    for register in REGISTERS:
        state.globals[f"body_{register}"] = values[f"body_{register}"]
    state.globals["call"] = claripy.BVV(0, 224)


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "TitleScroll")
    body = symbol_location(SYMBOLS, "_TitleScroll")
    assert linked_bytes(ROM, location, len(EXPECTED_PREFIX)) == EXPECTED_PREFIX
    assert body.address == location.address + len(EXPECTED_PREFIX)
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
    project.hook(location.address + 8, Sm83AndA(location.address + 9), length=1)
    project.hook(body.address, AssemblyTitleScrollBody())
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    _setup_globals(state, values)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=2)
    assert not manager.errored and len(manager.found) == 2
    return [
        Endpoint(
            **assembly_registers(end),
            ly=end.globals["ly"],
            scx=end.globals["scx"],
            title_ball_y=end.globals["title_ball_y"],
            call=end.globals["call"],
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_title_scroll")
    body = project.loader.find_symbol("port_title_scroll_body")
    assert function is not None and body is not None
    project.hook(body.rebased_addr, NativeTitleScrollBody())
    state = project.factory.call_state(
        function.rebased_addr,
        NATIVE_STATE,
        IN_TABLE,
        OUT_TABLE,
        BALL_TABLE,
        TIMINGS,
    )
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(
        NATIVE_STATE + 8,
        claripy.Concat(
            values["ly"], values["scx"], values["title_ball_y"]
        ),
    )
    _setup_globals(state, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 2
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            ly=end.memory.load(NATIVE_STATE + 8, 1),
            scx=end.memory.load(NATIVE_STATE + 9, 1),
            title_ball_y=end.memory.load(NATIVE_STATE + 10, 1),
            call=end.globals["call"],
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(
    not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`"
)
def test_title_scroll_pathwise_equivalence() -> None:
    values = _inputs("title_scroll")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "ly", "scx", "title_ball_y", "call"),
    )
