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
from verification.harness.sm83_shims import Sm83StoreAHighImmediate, Sm83XorA

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
IN_TABLE = 0x110000
OUT_TABLE = 0x120000
BALL_TABLE = 0x130000
TIMINGS = 0x140000
STACK = 0xDFF0
RETURN = 0xEFFF
HWY = 0xFFB0
STATE_FIELDS = (
    "ly",
    "scx",
    "title_ball_y",
    "wy",
    "loaded_rom_bank",
    "mapper_bank",
)
CALLEE_FIELDS = ("ly", "scx", "title_ball_y")
EXPECTED = bytes.fromhex("1600060d215872cdd635afe0b0c9")


@dataclass(frozen=True)
class Endpoint:
    state: claripy.ast.BV
    call: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _assembly_state(state: angr.SimState) -> claripy.ast.BV:
    registers = assembly_registers(state)
    return claripy.Concat(
        *(registers[name] for name in REGISTERS),
        *(state.globals[name] for name in CALLEE_FIELDS),
        state.memory.load(HWY, 1),
        state.globals["loaded_rom_bank"],
        state.globals["mapper_bank"],
    )


class AssemblyBankswitchTitleScroll(angr.SimProcedure):
    """Composition of proven Bankswitch and TitleScroll transitions."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        entry = assembly_registers(self.state)
        saved_bank = self.state.globals["loaded_rom_bank"]
        saved_f = entry["f"]
        call_registers = dict(entry)
        call_registers.update(
            a=claripy.BVV(0x0D, 8),
            b=claripy.BVV(0x35, 8),
            c=claripy.BVV(0xE4, 8),
        )
        self.state.globals["loaded_rom_bank"] = claripy.BVV(0x0D, 8)
        self.state.globals["mapper_bank"] = claripy.BVV(0x0D, 8)
        self.state.globals["call"] = claripy.Concat(
            *(call_registers[name] for name in REGISTERS),
            *(self.state.globals[name] for name in CALLEE_FIELDS),
            self.state.globals["loaded_rom_bank"],
            self.state.globals["mapper_bank"],
            claripy.BVV(IN_TABLE, 64),
            claripy.BVV(OUT_TABLE, 64),
            claripy.BVV(BALL_TABLE, 64),
            claripy.BVV(TIMINGS, 64),
        )

        for register in REGISTERS:
            value = self.state.globals[f"callee_{register}"]
            if register == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, register, value)
        for field in CALLEE_FIELDS:
            self.state.globals[field] = self.state.globals[f"callee_{field}"]

        self.state.regs.a = saved_bank
        self.state.regs.b = saved_bank
        self.state.regs.c = saved_f
        self.state.globals["loaded_rom_bank"] = saved_bank
        self.state.globals["mapper_bank"] = saved_bank
        self.jump(self.next_address)


class NativeTitleScroll(angr.SimProcedure):
    def run(
        self,
        state: claripy.ast.BV,
        in_table: claripy.ast.BV,
        out_table: claripy.ast.BV,
        ball_table: claripy.ast.BV,
        timings: claripy.ast.BV,
    ) -> None:  # type: ignore[override]
        self.state.globals["call"] = claripy.Concat(
            self.state.memory.load(state, 11),
            self.state.memory.load(state + 12, 2),
            in_table,
            out_table,
            ball_table,
            timings,
        )
        for offset, register in enumerate(REGISTERS):
            self.state.memory.store(
                state + offset, self.state.globals[f"callee_{register}"]
            )
        for offset, field in enumerate(CALLEE_FIELDS, 8):
            self.state.memory.store(
                state + offset, self.state.globals[f"callee_{field}"]
            )


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for field in STATE_FIELDS:
        values[field] = claripy.BVS(f"{prefix}_{field}", 8)
    for register in REGISTERS:
        values[f"callee_{register}"] = (
            claripy.Concat(
                claripy.BVS(f"{prefix}_callee_flags", 4),
                claripy.BVV(0, 4),
            )
            if register == "f"
            else claripy.BVS(f"{prefix}_callee_{register}", 8)
        )
    for field in CALLEE_FIELDS:
        values[f"callee_{field}"] = claripy.BVS(
            f"{prefix}_callee_{field}", 8
        )
    return values


def _setup_globals(
    state: angr.SimState, values: dict[str, claripy.ast.BV]
) -> None:
    for field in ("ly", "scx", "title_ball_y", "loaded_rom_bank", "mapper_bank"):
        state.globals[field] = values[field]
    for register in REGISTERS:
        state.globals[f"callee_{register}"] = values[f"callee_{register}"]
    for field in CALLEE_FIELDS:
        state.globals[f"callee_{field}"] = values[f"callee_{field}"]
    state.globals["call"] = claripy.BVV(0, 360)


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "TitleScreenScrollInMon")
    bankswitch = symbol_location(SYMBOLS, "Bankswitch")
    title_scroll = symbol_location(SYMBOLS, "TitleScroll")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    assert bankswitch.address == 0x35D6
    assert title_scroll.bank == 0x0D and title_scroll.address == 0x7258
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
    project.hook(
        base + 7,
        AssemblyBankswitchTitleScroll(base + 10),
        length=3,
    )
    project.hook(base + 10, Sm83XorA(base + 11), length=1)
    project.hook(
        base + 11,
        Sm83StoreAHighImmediate(0xB0, base + 13),
        length=2,
    )
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    state.memory.store(HWY, values["wy"])
    _setup_globals(state, values)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN)
    assert not manager.errored and len(manager.found) == 1
    return [
        Endpoint(
            state=_assembly_state(end),
            call=end.globals["call"],
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_title_screen_scroll_in_mon")
    callee = project.loader.find_symbol("port_title_scroll")
    assert function is not None and callee is not None
    project.hook(callee.rebased_addr, NativeTitleScroll())
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
        claripy.Concat(*(values[field] for field in STATE_FIELDS)),
    )
    _setup_globals(state, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [
        Endpoint(
            state=end.memory.load(NATIVE_STATE, 14),
            call=end.globals["call"],
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(
    not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`"
)
def test_title_screen_scroll_in_mon_pathwise_equivalence() -> None:
    values = _inputs("title_screen_scroll_in_mon")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        ("state", "call"),
    )
