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
from verification.harness.sm83_shims import Sm83AddRegister
from verification.tests.test_copy_video_data_double import (
    ADDRESSES as VIDEO_ADDRESSES,
    FIELDS as VIDEO_FIELDS,
    ROMB,
)
from verification.tests.test_load_text_box_tile_patterns import LoadLcdc

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
    "f04087381c21806011d0960118003e04cd2b182198601130970130003e04"
    "c32b1811806021d096010304cd8618119860213097010604c38618"
)
FAR_FIELDS = (
    "rom_bank_temp",
    "loaded_rom_bank",
    "mapper_bank",
    "saved_a",
    "saved_f",
    "memory0",
    "memory1",
    "memory2",
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
    far_state: claripy.ast.BV
    video_state: claripy.ast.BV
    lcd_control: claripy.ast.BV
    marker: claripy.ast.BV
    calls: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _post_key(kind: str, index: int, field: str) -> str:
    return f"{kind}{index}_{field}"


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


def _assembly_snapshot(state: angr.SimState, kind: int) -> claripy.ast.BV:
    registers = assembly_registers(state)
    return claripy.Concat(
        claripy.BVV(kind, 8),
        *(registers[name] for name in REGISTERS),
        *(state.globals[field] for field in FAR_FIELDS),
        state.memory.load(LCD_CONTROL, 1),
        _assembly_video_state(state),
        state.memory.load(MARKER, 1),
    )


class AssemblyTransferSummary(angr.SimProcedure):
    def __init__(self, kind: str, index: int, next_address: int) -> None:
        super().__init__()
        self.kind = kind
        self.index = index
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        kind_id = 1 if self.kind == "far" else 2
        self.state.globals["calls"] += (
            _assembly_snapshot(self.state, kind_id),
        )
        for register in REGISTERS:
            value = self.state.globals[
                _post_key(self.kind, self.index, register)
            ]
            if register == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, register, value)
        fields = FAR_FIELDS if self.kind == "far" else VIDEO_FIELDS
        for field in fields:
            value = self.state.globals[
                _post_key(self.kind, self.index, field)
            ]
            if self.kind == "far":
                self.state.globals[field] = value
            else:
                address = VIDEO_ADDRESSES[VIDEO_FIELDS.index(field)]
                if address == ROMB:
                    self.state.globals["romb"] = value
                else:
                    self.state.memory.store(address, value)
        self.state.memory.store(
            MARKER,
            self.state.globals[_post_key(self.kind, self.index, "marker")],
        )
        self.jump(self.next_address)


class NativeTransferSummary(angr.SimProcedure):
    def __init__(self, kind: str) -> None:
        super().__init__()
        self.kind = kind

    def run(
        self, state: claripy.ast.BV, memory: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        index = len(self.state.globals["calls"]) + 1
        kind_id = 1 if self.kind == "far" else 2
        snapshot = claripy.Concat(
            claripy.BVV(kind_id, 8),
            self.state.memory.load(state, 8),
            self.state.memory.load(state + 8, len(FAR_FIELDS)),
            self.state.memory.load(state + 16, 1),
            _native_video_state(self.state, memory),
            self.state.memory.load(memory + MARKER, 1),
        )
        self.state.globals["calls"] += (snapshot,)
        for offset, register in enumerate(REGISTERS):
            self.state.memory.store(
                state + offset,
                self.state.globals[_post_key(self.kind, index, register)],
            )
        fields = FAR_FIELDS if self.kind == "far" else VIDEO_FIELDS
        for field in fields:
            value = self.state.globals[_post_key(self.kind, index, field)]
            if self.kind == "far":
                self.state.memory.store(state + 8 + FAR_FIELDS.index(field), value)
            else:
                address = VIDEO_ADDRESSES[VIDEO_FIELDS.index(field)]
                self.state.memory.store(memory + address, value)
        self.state.memory.store(
            memory + MARKER,
            self.state.globals[_post_key(self.kind, index, "marker")],
        )


def _flag_value(name: str) -> claripy.ast.BV:
    return claripy.Concat(claripy.BVS(name, 4), claripy.BVV(0, 4))


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for field in FAR_FIELDS:
        values[field] = (
            _flag_value(f"{prefix}_{field}")
            if field == "saved_f"
            else claripy.BVS(f"{prefix}_{field}", 8)
        )
    values["lcd_control"] = claripy.BVS(f"{prefix}_lcd_control", 8)
    for field in VIDEO_FIELDS:
        values[field] = claripy.BVS(f"{prefix}_{field}", 8)
    values["marker"] = claripy.BVS(f"{prefix}_marker", 8)
    for kind, fields in (("far", FAR_FIELDS), ("video", VIDEO_FIELDS)):
        for index in (1, 2):
            for register in REGISTERS:
                key = _post_key(kind, index, register)
                values[key] = (
                    _flag_value(f"{prefix}_{key}")
                    if register == "f"
                    else claripy.BVS(f"{prefix}_{key}", 8)
                )
            for field in fields:
                key = _post_key(kind, index, field)
                values[key] = claripy.BVS(f"{prefix}_{key}", 8)
            key = _post_key(kind, index, "marker")
            values[key] = claripy.BVS(f"{prefix}_{key}", 8)
    return values


def _setup_globals(
    state: angr.SimState, values: dict[str, claripy.ast.BV]
) -> None:
    for field in FAR_FIELDS:
        state.globals[field] = values[field]
    state.globals["lcd_control"] = values["lcd_control"]
    state.globals["romb"] = values["romb"]
    state.globals["calls"] = ()
    for kind, fields in (("far", FAR_FIELDS), ("video", VIDEO_FIELDS)):
        for index in (1, 2):
            for field in (*REGISTERS, *fields, "marker"):
                key = _post_key(kind, index, field)
                state.globals[key] = values[key]


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "LoadHudTilePatterns")
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
    base = location.address
    project.hook(base, LoadLcdc(base + 2), length=2)
    project.hook(base + 2, Sm83AddRegister("a", base + 3), length=1)
    project.hook(
        base + 16, AssemblyTransferSummary("far", 1, base + 19), length=3
    )
    project.hook(
        base + 30, AssemblyTransferSummary("far", 2, DONE), length=3
    )
    project.hook(
        base + 42, AssemblyTransferSummary("video", 1, base + 45), length=3
    )
    project.hook(
        base + 54, AssemblyTransferSummary("video", 2, DONE), length=3
    )
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _setup_globals(state, values)
    state.memory.store(LCD_CONTROL, values["lcd_control"])
    for address, field in zip(VIDEO_ADDRESSES, VIDEO_FIELDS):
        if address != ROMB:
            state.memory.store(address, values[field])
    state.memory.store(MARKER, values["marker"])
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=10)
    assert not manager.errored and len(manager.found) == 2
    return [
        Endpoint(
            **assembly_registers(end),
            far_state=claripy.Concat(
                *(end.globals[field] for field in FAR_FIELDS)
            ),
            video_state=_assembly_video_state(end),
            lcd_control=end.memory.load(LCD_CONTROL, 1),
            marker=end.memory.load(MARKER, 1),
            calls=claripy.Concat(*end.globals["calls"]),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_load_hud_tile_patterns")
    far_copy = project.loader.find_symbol("port_far_copy_data_double")
    video_copy = project.loader.find_symbol("port_copy_video_data_double")
    assert function is not None and far_copy is not None and video_copy is not None
    project.hook(far_copy.rebased_addr, NativeTransferSummary("far"))
    project.hook(video_copy.rebased_addr, NativeTransferSummary("video"))
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
    assert not manager.errored and len(manager.deadended) == 2
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            far_state=end.memory.load(NATIVE_STATE + 8, len(FAR_FIELDS)),
            video_state=_native_video_state(
                end, claripy.BVV(NATIVE_MEMORY, 64)
            ),
            lcd_control=end.memory.load(NATIVE_STATE + 16, 1),
            marker=end.memory.load(NATIVE_MEMORY + MARKER, 1),
            calls=claripy.Concat(*end.globals["calls"]),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(
    not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`"
)
def test_load_hud_tile_patterns_pathwise_equivalence() -> None:
    values = _inputs("load_hud_tile_patterns")
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
