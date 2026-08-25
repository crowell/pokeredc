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
from verification.tests.test_copy_video_data_double import (
    ADDRESSES as VIDEO_ADDRESSES,
    FIELDS as VIDEO_FIELDS,
    ROMB,
)
from verification.tests.test_load_hud_tile_patterns import FAR_FIELDS

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF
MARKER = 0xC123
LCD_CONTROL = 0xFF40
EXPECTED = bytes.fromhex(
    "cdc036f04087381c21806011d0960118003e04cd2b182198601130970130"
    "003e04c32b1811806021d096010304cd8618119860213097010604c38618"
)
BANK_FIELDS = FAR_FIELDS[:3]


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
    far_state: claripy.ast.BV
    video_state: claripy.ast.BV
    lcd_control: claripy.ast.BV
    marker: claripy.ast.BV
    calls: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _post_key(kind: str, field: str) -> str:
    return f"{kind}_{field}"


def _assembly_video_state(state: angr.SimState) -> claripy.ast.BV:
    return claripy.Concat(
        *(
            state.globals["romb"]
            if address == ROMB
            else state.memory.load(address, 1)
            for address in VIDEO_ADDRESSES
        )
    )


def _native_video_state(
    state: angr.SimState, memory: claripy.ast.BV
) -> claripy.ast.BV:
    return claripy.Concat(
        *(state.memory.load(memory + address, 1) for address in VIDEO_ADDRESSES)
    )


def _write_assembly_registers(
    state: angr.SimState, values: dict[str, claripy.ast.BV], kind: str
) -> None:
    for register in REGISTERS:
        value = values[_post_key(kind, register)]
        if register == "f":
            value = sm83_flags_to_z80(value)
        setattr(state.regs, register, value)


def _write_assembly_video(
    state: angr.SimState, values: dict[str, claripy.ast.BV], kind: str
) -> None:
    for address, field in zip(VIDEO_ADDRESSES, VIDEO_FIELDS):
        value = values[_post_key(kind, field)]
        if address == ROMB:
            state.globals["romb"] = value
        else:
            state.memory.store(address, value)


class AssemblyHpSummary(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["calls"] += (
            claripy.Concat(
                claripy.BVV(1, 8),
                *(assembly_registers(self.state)[name] for name in REGISTERS),
                *(self.state.globals[field] for field in BANK_FIELDS),
                self.state.memory.load(LCD_CONTROL, 1),
                _assembly_video_state(self.state),
                self.state.memory.load(MARKER, 1),
            ),
        )
        _write_assembly_registers(self.state, self.state.globals, "hp")
        for field in BANK_FIELDS:
            self.state.globals[field] = self.state.globals[
                _post_key("hp", field)
            ]
        _write_assembly_video(self.state, self.state.globals, "hp")
        self.state.memory.store(
            MARKER, self.state.globals[_post_key("hp", "marker")]
        )
        self.jump(self.next_address)


class AssemblyHudSummary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.globals["calls"] += (
            claripy.Concat(
                claripy.BVV(2, 8),
                *(assembly_registers(self.state)[name] for name in REGISTERS),
                *(self.state.globals[field] for field in FAR_FIELDS),
                self.state.memory.load(LCD_CONTROL, 1),
                _assembly_video_state(self.state),
                self.state.memory.load(MARKER, 1),
            ),
        )
        _write_assembly_registers(self.state, self.state.globals, "hud")
        for field in FAR_FIELDS:
            self.state.globals[field] = self.state.globals[
                _post_key("hud", field)
            ]
        _write_assembly_video(self.state, self.state.globals, "hud")
        self.state.memory.store(
            MARKER, self.state.globals[_post_key("hud", "marker")]
        )
        self.jump(DONE)


class NativeHpSummary(angr.SimProcedure):
    def run(
        self, state: claripy.ast.BV, memory: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        self.state.globals["calls"] += (
            claripy.Concat(
                claripy.BVV(1, 8),
                self.state.memory.load(state, 12),
                _native_video_state(self.state, memory),
                self.state.memory.load(memory + MARKER, 1),
            ),
        )
        for offset, register in enumerate(REGISTERS):
            self.state.memory.store(
                state + offset,
                self.state.globals[_post_key("hp", register)],
            )
        for offset, field in enumerate(BANK_FIELDS, 8):
            self.state.memory.store(
                state + offset, self.state.globals[_post_key("hp", field)]
            )
        _write_native_video(self.state, memory, self.state.globals, "hp")
        self.state.memory.store(
            memory + MARKER, self.state.globals[_post_key("hp", "marker")]
        )


class NativeHudSummary(angr.SimProcedure):
    def run(
        self, state: claripy.ast.BV, memory: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        self.state.globals["calls"] += (
            claripy.Concat(
                claripy.BVV(2, 8),
                self.state.memory.load(state, 17),
                _native_video_state(self.state, memory),
                self.state.memory.load(memory + MARKER, 1),
            ),
        )
        for offset, register in enumerate(REGISTERS):
            self.state.memory.store(
                state + offset,
                self.state.globals[_post_key("hud", register)],
            )
        for offset, field in enumerate(FAR_FIELDS, 8):
            self.state.memory.store(
                state + offset, self.state.globals[_post_key("hud", field)]
            )
        _write_native_video(self.state, memory, self.state.globals, "hud")
        self.state.memory.store(
            memory + MARKER, self.state.globals[_post_key("hud", "marker")]
        )


def _write_native_video(
    state: angr.SimState,
    memory: claripy.ast.BV,
    values: dict[str, claripy.ast.BV],
    kind: str,
) -> None:
    for address, field in zip(VIDEO_ADDRESSES, VIDEO_FIELDS):
        state.memory.store(
            memory + address, values[_post_key(kind, field)]
        )


def _flag_value(name: str) -> claripy.ast.BV:
    return claripy.Concat(claripy.BVS(name, 4), claripy.BVV(0, 4))


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for field in FAR_FIELDS:
        values[field] = claripy.BVS(f"{prefix}_{field}", 8)
    values["lcd_control"] = claripy.BVS(f"{prefix}_lcd_control", 8)
    for field in VIDEO_FIELDS:
        values[field] = claripy.BVS(f"{prefix}_{field}", 8)
    values["marker"] = claripy.BVS(f"{prefix}_marker", 8)
    for kind, fields in (("hp", BANK_FIELDS), ("hud", FAR_FIELDS)):
        for register in REGISTERS:
            key = _post_key(kind, register)
            values[key] = (
                _flag_value(f"{prefix}_{key}")
                if register == "f"
                else claripy.BVS(f"{prefix}_{key}", 8)
            )
        for field in (*fields, *VIDEO_FIELDS, "marker"):
            key = _post_key(kind, field)
            values[key] = claripy.BVS(f"{prefix}_{key}", 8)
    return values


def _setup_globals(
    state: angr.SimState, values: dict[str, claripy.ast.BV]
) -> None:
    for field in FAR_FIELDS:
        state.globals[field] = values[field]
    state.globals["romb"] = values["romb"]
    state.globals["calls"] = ()
    for kind, fields in (("hp", BANK_FIELDS), ("hud", FAR_FIELDS)):
        for field in (*REGISTERS, *fields, *VIDEO_FIELDS, "marker"):
            key = _post_key(kind, field)
            state.globals[key] = values[key]


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(
        SYMBOLS, "LoadHudAndHpBarAndStatusTilePatterns"
    )
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
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
    project.hook(location.address, AssemblyHpSummary(location.address + 3), length=3)
    project.hook(location.address + 3, AssemblyHudSummary(), length=57)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    _setup_globals(state, values)
    state.memory.store(LCD_CONTROL, values["lcd_control"])
    for address, field in zip(VIDEO_ADDRESSES, VIDEO_FIELDS):
        if address != ROMB:
            state.memory.store(address, values[field])
    state.memory.store(MARKER, values["marker"])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=2)
    assert not manager.errored and len(manager.found) == 1
    return [_assembly_endpoint(end) for end in manager.found]


def _assembly_endpoint(end: angr.SimState) -> Endpoint:
    return Endpoint(
        **assembly_registers(end),
        far_state=claripy.Concat(*(end.globals[field] for field in FAR_FIELDS)),
        video_state=_assembly_video_state(end),
        lcd_control=end.memory.load(LCD_CONTROL, 1),
        marker=end.memory.load(MARKER, 1),
        calls=claripy.Concat(*end.globals["calls"]),
        constraints=tuple(end.solver.constraints),
    )


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(
        "port_load_hud_and_hp_bar_and_status_tile_patterns"
    )
    hp = project.loader.find_symbol("port_load_hp_bar_and_status_tile_patterns")
    hud = project.loader.find_symbol("port_load_hud_tile_patterns")
    assert function is not None and hp is not None and hud is not None
    project.hook(hp.rebased_addr, NativeHpSummary())
    project.hook(hud.rebased_addr, NativeHudSummary())
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    for offset, field in enumerate(FAR_FIELDS, 8):
        state.memory.store(NATIVE_STATE + offset, values[field])
    state.memory.store(NATIVE_STATE + 16, values["lcd_control"])
    for address, field in zip(VIDEO_ADDRESSES, VIDEO_FIELDS):
        state.memory.store(NATIVE_MEMORY + address, values[field])
    state.memory.store(NATIVE_MEMORY + MARKER, values["marker"])
    _setup_globals(state, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [_native_endpoint(end) for end in manager.deadended]


def _native_endpoint(end: angr.SimState) -> Endpoint:
    memory = claripy.BVV(NATIVE_MEMORY, 64)
    return Endpoint(
        **native_registers(end, NATIVE_STATE),
        far_state=end.memory.load(NATIVE_STATE + 8, len(FAR_FIELDS)),
        video_state=_native_video_state(end, memory),
        lcd_control=end.memory.load(NATIVE_STATE + 16, 1),
        marker=end.memory.load(NATIVE_MEMORY + MARKER, 1),
        calls=claripy.Concat(*end.globals["calls"]),
        constraints=tuple(end.solver.constraints),
    )


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(
    not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`"
)
def test_load_hud_and_hp_bar_and_status_tile_patterns_pathwise_equivalence() -> None:
    values = _inputs("load_hud_and_hp_bar_and_status_tile_patterns")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (
            *REGISTERS,
            "far_state",
            "video_state",
            "lcd_control",
            "marker",
            "calls",
        ),
    )
