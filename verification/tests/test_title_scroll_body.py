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
    collect_returns,
    linked_bytes,
    rom_window,
    sm83_flags_to_z80,
    symbol_location,
)
from verification.harness.sm83_shims import (
    Sm83AddRegister,
    Sm83DecRegister,
    Sm83SwapRegister,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
TABLE = 0x130000
BALL_TABLE = 0x140000
TIMINGS = 0x150000
BEFORE_BASE = 0x200000
AFTER_BASE = 0x300000
STACK = 0xD000
RETURN = 0xFFFF
EXPECTED_BODY = bytes.fromhex(
    "0aa7c803c547e60f4f78e6f0cb3747622e48cd927226002e88cd92727a8057"
    "cdc4720d20eac118d8"
)
TITLE_BALL_Y_TABLE = (0, 0x71, 0x6F, 0x6E, 0x6D, 0x6C, 0x6D, 0x6E,
                      0x6F, 0x71, 0x74, 0)
DOMAINS = (
    ("in", 0x7247, 0x88, 0, (0xA2, 0x94, 0x84, 0x63, 0x52, 0x31, 0x11, 0), 17),
    ("out", 0x724F, 0, 0, (0x12, 0x22, 0x32, 0x42, 0x52, 0x62, 0x83, 0x93, 0), 18),
    ("wait_ball", 0x7244, 0, 1, (0x05, 0x05, 0), 10),
)


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
    calls: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class Sm83And(angr.SimProcedure):
    def __init__(self, value: int, continuation: int) -> None:
        super().__init__()
        self.value = value
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a &= self.value
        self.state.regs.f = claripy.BVV(0x10, 8) | claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x40, 8),
            claripy.BVV(0, 8),
        )
        self.jump(self.continuation)


def _canonical_cp(left: claripy.ast.BV, right: claripy.ast.BV) -> claripy.ast.BV:
    flags = claripy.BVV(0x40, 8)
    flags |= claripy.If(left == right, claripy.BVV(0x80, 8), claripy.BVV(0, 8))
    flags |= claripy.If(
        (left & 0x0F).ULT(right & 0x0F),
        claripy.BVV(0x20, 8),
        claripy.BVV(0, 8),
    )
    flags |= claripy.If(left.ULT(right), claripy.BVV(0x10, 8), claripy.BVV(0, 8))
    return flags


def _canonical_inc(value: claripy.ast.BV) -> tuple[claripy.ast.BV, claripy.ast.BV]:
    result = value + 1
    flags = claripy.If(result == 0, claripy.BVV(0x80, 8), claripy.BVV(0, 8))
    flags |= claripy.If(
        (value & 0x0F) == 0x0F,
        claripy.BVV(0x20, 8),
        claripy.BVV(0, 8),
    )
    return result, flags


def _pop_return(state: angr.SimState) -> claripy.ast.BV:
    target = state.memory.load(state.regs.sp, 2, endness="Iend_LE")
    state.regs.sp += 2
    return target


class AssemblyScrollBetween(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        index = self.state.globals["scan_index"]
        registers = assembly_registers(self.state)
        post_ly = self.state.globals["post_ly"][index]
        self.state.solver.add(post_ly != registers["h"])
        self.state.globals["calls"] += (
            claripy.Concat(
                claripy.BVV(1, 8),
                *(registers[name] for name in REGISTERS),
                self.state.globals["ly"],
                self.state.globals["scx"],
                claripy.BVV(BEFORE_BASE + index * 0x100, 64),
                claripy.BVV(AFTER_BASE + index * 0x100, 64),
            ),
        )
        self.state.globals["scan_index"] = index + 1
        self.state.regs.a = post_ly
        self.state.regs.f = sm83_flags_to_z80(
            _canonical_cp(post_ly, registers["h"])
        )
        self.state.globals["ly"] = post_ly
        self.state.globals["scx"] = registers["h"]
        self.jump(_pop_return(self.state))


class NativeScrollBetween(angr.SimProcedure):
    def run(
        self,
        scanline: claripy.ast.BV,
        before: claripy.ast.BV,
        after: claripy.ast.BV,
    ) -> None:  # type: ignore[override]
        index = self.state.globals["scan_index"]
        registers = {
            name: self.state.memory.load(scanline + offset, 1)
            for offset, name in enumerate(REGISTERS)
        }
        post_ly = self.state.globals["post_ly"][index]
        self.state.solver.add(post_ly != registers["h"])
        self.state.globals["calls"] += (
            claripy.Concat(
                claripy.BVV(1, 8),
                *(registers[name] for name in REGISTERS),
                self.state.memory.load(scanline + 8, 1),
                self.state.memory.load(scanline + 9, 1),
                before,
                after,
            ),
        )
        self.state.globals["scan_index"] = index + 1
        self.state.memory.store(scanline, post_ly)
        self.state.memory.store(
            scanline + 1, _canonical_cp(post_ly, registers["h"])
        )
        self.state.memory.store(scanline + 8, post_ly)
        self.state.memory.store(scanline + 9, registers["h"])


class AssemblyGetTitleBallY(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        registers = assembly_registers(self.state)
        e = self.state.solver.eval(registers["e"])
        fetched = claripy.BVV(TITLE_BALL_Y_TABLE[e], 8)
        self.state.globals["calls"] += (
            claripy.Concat(
                claripy.BVV(2, 8),
                *(registers[name] for name in REGISTERS),
                self.state.globals["title_ball_y"],
                fetched,
            ),
        )
        self.state.regs.a = fetched
        flags = claripy.BVV(0xA0 if TITLE_BALL_Y_TABLE[e] == 0 else 0x20, 8)
        if TITLE_BALL_Y_TABLE[e] != 0:
            self.state.globals["title_ball_y"] = fetched
            result, flags = _canonical_inc(registers["e"])
            self.state.regs.e = result
        self.state.regs.f = sm83_flags_to_z80(flags)
        self.jump(_pop_return(self.state))


class NativeGetTitleBallY(angr.SimProcedure):
    def run(self, ball: claripy.ast.BV) -> None:  # type: ignore[override]
        registers = {
            name: self.state.memory.load(ball + offset, 1)
            for offset, name in enumerate(REGISTERS)
        }
        fetched = self.state.memory.load(ball + 9, 1)
        fetched_value = self.state.solver.eval(fetched)
        self.state.globals["calls"] += (
            claripy.Concat(
                claripy.BVV(2, 8), self.state.memory.load(ball, 10)
            ),
        )
        self.state.memory.store(ball, fetched)
        flags = claripy.BVV(0xA0 if fetched_value == 0 else 0x20, 8)
        if fetched_value != 0:
            self.state.memory.store(ball + 8, fetched)
            result, flags = _canonical_inc(registers["e"])
            self.state.memory.store(ball + 5, result)
        self.state.memory.store(ball + 1, flags)


def _inputs(prefix: str, bc: int, d: int, e: int, scan_count: int) -> dict[str, object]:
    values: dict[str, object] = symbolic_registers(prefix)
    values["b"] = claripy.BVV(bc >> 8, 8)
    values["c"] = claripy.BVV(bc & 0xFF, 8)
    values["d"] = claripy.BVV(d, 8)
    values["e"] = claripy.BVV(e, 8)
    values["ly"] = claripy.BVS(f"{prefix}_ly", 8)
    values["scx"] = claripy.BVS(f"{prefix}_scx", 8)
    values["title_ball_y"] = claripy.BVS(f"{prefix}_title_ball_y", 8)
    values["post_ly"] = tuple(
        claripy.BVS(f"{prefix}_post_ly_{index}", 8)
        for index in range(scan_count)
    )
    return values


def _setup_globals(state: angr.SimState, values: dict[str, object]) -> None:
    state.globals["ly"] = values["ly"]
    state.globals["scx"] = values["scx"]
    state.globals["title_ball_y"] = values["title_ball_y"]
    state.globals["post_ly"] = values["post_ly"]
    state.globals["scan_index"] = 0
    state.globals["calls"] = ()


def _assembly(values: dict[str, object]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "_TitleScroll")
    scroll_between = symbol_location(SYMBOLS, "_TitleScroll.ScrollBetween")
    get_ball = symbol_location(SYMBOLS, "GetTitleBallY")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY
    for symbol, expected in (
        ("TitleScroll_In", DOMAINS[0][4]),
        ("TitleScroll_Out", DOMAINS[1][4]),
        ("TitleScroll_WaitBall", DOMAINS[2][4]),
        ("TitleBallYTable", TITLE_BALL_Y_TABLE),
    ):
        assert linked_bytes(
            ROM, symbol_location(SYMBOLS, symbol), len(expected)
        ) == bytes(expected)
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
    project.hook(base + 1, Sm83And(0xFF, base + 2), length=1)
    project.hook(base + 6, Sm83And(0x0F, base + 8), length=2)
    project.hook(base + 10, Sm83And(0xF0, base + 12), length=2)
    project.hook(base + 12, Sm83SwapRegister("a", base + 14), length=2)
    project.hook(base + 29, Sm83AddRegister("b", base + 30), length=1)
    project.hook(base + 34, Sm83DecRegister("c", base + 35), length=1)
    project.hook(scroll_between.address, AssemblyScrollBetween())
    project.hook(get_ball.address, AssemblyGetTitleBallY())
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)  # type: ignore[arg-type]
    _setup_globals(state, values)
    state.regs.sp = claripy.BVV(STACK, 16)
    state.memory.store(
        STACK, claripy.BVV(RETURN, 16), endness="Iend_LE"
    )
    ends = collect_returns(project, state, RETURN)
    assert len(ends) == 1
    assert ends[0].globals["scan_index"] == len(values["post_ly"])
    return [
        Endpoint(
            **assembly_registers(end),
            ly=end.globals["ly"],
            scx=end.globals["scx"],
            title_ball_y=end.globals["title_ball_y"],
            calls=claripy.Concat(*end.globals["calls"]),
            constraints=tuple(end.solver.constraints),
        )
        for end in ends
    ]


def _native(
    values: dict[str, object], table: tuple[int, ...], scan_count: int
) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_title_scroll_body")
    scroll_between = project.loader.find_symbol(
        "port_title_scroll_scroll_between"
    )
    get_ball = project.loader.find_symbol("port_get_title_ball_y")
    assert function is not None and scroll_between is not None
    assert get_ball is not None
    project.hook(scroll_between.rebased_addr, NativeScrollBetween())
    project.hook(get_ball.rebased_addr, NativeGetTitleBallY())
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, TABLE, BALL_TABLE, TIMINGS
    )
    store_native_registers(state, NATIVE_STATE, values)  # type: ignore[arg-type]
    state.memory.store(
        NATIVE_STATE + 8,
        claripy.Concat(
            values["ly"], values["scx"], values["title_ball_y"]
        ),
    )
    state.memory.store(
        TABLE, claripy.Concat(*(claripy.BVV(value, 8) for value in table))
    )
    state.memory.store(
        BALL_TABLE,
        claripy.Concat(
            *(claripy.BVV(value, 8) for value in TITLE_BALL_Y_TABLE)
        ),
    )
    for index in range(scan_count):
        state.memory.store(
            TIMINGS + index * 16,
            claripy.BVV(BEFORE_BASE + index * 0x100, 64),
            endness="Iend_LE",
        )
        state.memory.store(
            TIMINGS + index * 16 + 8,
            claripy.BVV(AFTER_BASE + index * 0x100, 64),
            endness="Iend_LE",
        )
    _setup_globals(state, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    assert manager.deadended[0].globals["scan_index"] == scan_count
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            ly=end.memory.load(NATIVE_STATE + 8, 1),
            scx=end.memory.load(NATIVE_STATE + 9, 1),
            title_ball_y=end.memory.load(NATIVE_STATE + 10, 1),
            calls=claripy.Concat(*end.globals["calls"]),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(
    not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`"
)
@pytest.mark.parametrize(("name", "bc", "d", "e", "table", "iterations"), DOMAINS)
def test_title_scroll_body_pathwise_equivalence(
    name: str,
    bc: int,
    d: int,
    e: int,
    table: tuple[int, ...],
    iterations: int,
) -> None:
    scan_count = iterations * 2
    values = _inputs(f"title_scroll_body_{name}", bc, d, e, scan_count)
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values, table, scan_count),
        (*REGISTERS, "ly", "scx", "title_ball_y", "calls"),
    )
