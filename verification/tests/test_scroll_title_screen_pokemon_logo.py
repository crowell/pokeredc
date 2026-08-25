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
    symbol_location,
)
from verification.harness.sm83_shims import Sm83AddRegister, Sm83DecRegister

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
STACK = 0xD000
RETURN = 0xFFFF
SCROLL_Y = 0xFF42
SCROLL_Y_OFFSET = 8
VBLANK_OFFSET = 9
OBSERVED_VBLANK_OFFSET = 10
EXPECTED_BODY = bytes.fromhex("cdaf200a82021d20f7c9")
GAMEPLAY_CALLS = (
    (0xFC, 16),
    (0x03, 4),
    (0xFD, 4),
    (0x02, 2),
    (0xFE, 2),
    (0x01, 2),
    (0xFF, 2),
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
    scroll_y: claripy.ast.BV
    vblank_occurred: claripy.ast.BV
    observed_vblank: claripy.ast.BV
    calls: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class AssemblyDelayFrame(angr.SimProcedure):
    """Complete transition of the independently proven DelayFrame."""

    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        registers = assembly_registers(self.state)
        self.state.globals["calls"] += (
            claripy.Concat(
                *(registers[name] for name in REGISTERS),
                self.state.memory.load(SCROLL_Y, 1),
                self.state.globals["vblank_occurred"],
                self.state.globals["observed_vblank"],
                claripy.BVV(0, 8),
            ),
        )
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x50, 8)
        self.state.globals["vblank_occurred"] = claripy.BVV(0, 8)
        self.state.globals["observed_vblank"] = claripy.BVV(0, 8)
        self.jump(self.continuation)


class NativeDelayFrame(angr.SimProcedure):
    def run(
        self, delay: claripy.ast.BV, observations: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        parent = self.state.globals["parent"]
        self.state.globals["calls"] += (
            claripy.Concat(
                self.state.memory.load(delay, 8),
                self.state.memory.load(parent + SCROLL_Y_OFFSET, 1),
                self.state.memory.load(delay + 8, 2),
                self.state.memory.load(observations, 1),
            ),
        )
        self.state.memory.store(delay, claripy.BVV(0, 8))
        self.state.memory.store(delay + 1, claripy.BVV(0xA0, 8))
        self.state.memory.store(delay + 8, claripy.BVV(0, 16))


def _inputs(prefix: str, d: int, e: int) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["b"] = claripy.BVV(0xFF, 8)
    values["c"] = claripy.BVV(0x42, 8)
    values["d"] = claripy.BVV(d, 8)
    values["e"] = claripy.BVV(e, 8)
    values["scroll_y"] = claripy.BVS(f"{prefix}_scroll_y", 8)
    values["vblank_occurred"] = claripy.BVS(
        f"{prefix}_vblank_occurred", 8
    )
    values["observed_vblank"] = claripy.BVS(
        f"{prefix}_observed_vblank", 8
    )
    return values


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(
        SYMBOLS, "DisplayTitleScreen.ScrollTitleScreenPokemonLogo"
    )
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY
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
    project.hook(base, AssemblyDelayFrame(base + 3), length=3)
    project.hook(base + 4, Sm83AddRegister("d", base + 5), length=1)
    project.hook(base + 6, Sm83DecRegister("e", base + 7), length=1)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.memory.store(SCROLL_Y, values["scroll_y"])
    state.globals["vblank_occurred"] = values["vblank_occurred"]
    state.globals["observed_vblank"] = values["observed_vblank"]
    state.globals["calls"] = ()
    state.regs.sp = claripy.BVV(STACK, 16)
    state.memory.store(
        STACK, claripy.BVV(RETURN, 16), endness="Iend_LE"
    )
    ends = collect_returns(project, state, RETURN)
    assert len(ends) == 1
    return [
        Endpoint(
            **assembly_registers(end),
            scroll_y=end.memory.load(SCROLL_Y, 1),
            vblank_occurred=end.globals["vblank_occurred"],
            observed_vblank=end.globals["observed_vblank"],
            calls=claripy.Concat(*end.globals["calls"]),
            constraints=tuple(end.solver.constraints),
        )
        for end in ends
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(
        "port_scroll_title_screen_pokemon_logo"
    )
    delay_frame = project.loader.find_symbol("port_delay_frame")
    assert function is not None and delay_frame is not None
    project.hook(delay_frame.rebased_addr, NativeDelayFrame())
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(
        NATIVE_STATE + SCROLL_Y_OFFSET,
        claripy.Concat(
            values["scroll_y"],
            values["vblank_occurred"],
            values["observed_vblank"],
        ),
    )
    state.globals["parent"] = claripy.BVV(NATIVE_STATE, 64)
    state.globals["calls"] = ()
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            scroll_y=end.memory.load(NATIVE_STATE + SCROLL_Y_OFFSET, 1),
            vblank_occurred=end.memory.load(
                NATIVE_STATE + VBLANK_OFFSET, 1
            ),
            observed_vblank=end.memory.load(
                NATIVE_STATE + OBSERVED_VBLANK_OFFSET, 1
            ),
            calls=claripy.Concat(*end.globals["calls"]),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(
    not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`"
)
@pytest.mark.parametrize(("d", "e"), GAMEPLAY_CALLS)
def test_scroll_title_screen_pokemon_logo_pathwise_equivalence(
    d: int, e: int
) -> None:
    values = _inputs(f"scroll_title_logo_{d:02x}_{e}", d, e)
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (
            *REGISTERS,
            "scroll_y",
            "vblank_occurred",
            "observed_vblank",
            "calls",
        ),
    )
