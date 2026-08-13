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
from verification.harness.sm83_shims import (
    Sm83CpRegister,
    Sm83LoadAImmediate,
    Sm83Scf,
    Sm83StoreAImmediate,
)


ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
GB_STACK = 0xD000
GB_RETURN = 0xFFFF


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
    memory: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class AndA(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.f = 0x10 | claripy.If(
            self.state.regs.a == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)
        )
        self.jump(self._next_address)


def addresses() -> tuple[int, int, int]:
    return tuple(
        symbol_location(SYMBOLS, name).address
        for name in (
            "wMapMusicROMBank",
            "wAudioROMBank",
            "wAudioSavedROMBank",
        )
    )


def inputs() -> dict[str, claripy.ast.BV]:
    values = symbolic_registers("compare_map_music_bank")
    for name in ("map_bank", "audio_bank", "saved_bank"):
        values[name] = claripy.BVS(f"music_{name}", 8)
    return values


def assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "CompareMapMusicBankWithCurrentBank")
    map_bank, audio_bank, saved_bank = addresses()
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
    project.hook(base, Sm83LoadAImmediate(map_bank, base + 3), length=3)
    project.hook(base + 4, Sm83LoadAImmediate(audio_bank, base + 7), length=3)
    project.hook(base + 7, Sm83CpRegister("e", base + 8), length=1)
    project.hook(
        base + 10, Sm83StoreAImmediate(saved_bank, base + 13), length=3
    )
    project.hook(base + 13, AndA(base + 14), length=1)
    project.hook(base + 16, AndA(base + 17), length=1)
    project.hook(
        base + 20, Sm83StoreAImmediate(audio_bank, base + 23), length=3
    )
    project.hook(
        base + 23, Sm83StoreAImmediate(saved_bank, base + 26), length=3
    )
    project.hook(base + 26, Sm83Scf(base + 27), length=1)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.memory.store(map_bank, values["map_bank"])
    state.memory.store(audio_bank, values["audio_bank"])
    state.memory.store(saved_bank, values["saved_bank"])
    state.regs.sp = GB_STACK
    state.memory.store(GB_STACK, claripy.BVV(GB_RETURN, 16), endness="Iend_LE")
    returned = collect_returns(project, state, GB_RETURN)
    return [
        Endpoint(
            **assembly_registers(end),
            memory=claripy.Concat(
                end.memory.load(map_bank, 1),
                end.memory.load(audio_bank, 1),
                end.memory.load(saved_bank, 1),
            ),
            constraints=tuple(end.solver.constraints),
        )
        for end in returned
    ]


def native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(
        "port_compare_map_music_bank_with_current_bank"
    )
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(
        NATIVE_STATE + 8,
        claripy.Concat(
            values["map_bank"], values["audio_bank"], values["saved_bank"]
        ),
    )
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            memory=end.memory.load(NATIVE_STATE + 8, 3),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="native port not built")
def test_symbolic_equivalence() -> None:
    values = inputs()
    assert_pathwise_equivalent(
        assembly(values), native(values), (*REGISTERS, "memory")
    )


def test_exact_body_and_addresses() -> None:
    location = symbol_location(SYMBOLS, "CompareMapMusicBankWithCurrentBank")
    assert addresses() == (0xD35C, 0xC0EF, 0xC0F0)
    assert linked_bytes(ROM, location, 28) == bytes.fromhex(
        "fa5cd35ffaefc0bb2005eaf0c0a7c979a77b2003eaefc0eaf0c037c9"
    )
