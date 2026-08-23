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
from verification.harness.rom import linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
DONE = 0xEFFF
EXPECTED = bytes.fromhex(
    "e5c54f06003e03cdbc35213d42097ee0e8cdcd35f0e8e0b8ea0020c1e1c9"
)
TABLE = bytes.fromhex(
    "0606060611060606071414010715151515161216151616161515161615161514"
    "151414141412170607110707071d071707171718171717071d07171214120707"
    "1717071712070717150717170717170707121107120712120717161717070718"
    "1811181818181818181d1d1d171d1d1d1d161d1d1d1d16181d18181512121212"
    "121212120712121212121212121718181818181818071707071d1d1d1d1d1d11"
    "1111111515111d1d1d1d1d1d1d1d061d17171707171717071212121207151212"
    "1107141206181111111111110101011616060606141514141411111211111211"
    "111111111d071d01111716181111111313111111111d1d1d"
)
FIELDS = ("map_rom_bank", "loaded_rom_bank", "mapper_bank", "home_temp", "home_saved_rom_bank")


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
    state: claripy.ast.BV
    calls: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class SavePair(angr.SimProcedure):
    def __init__(self, pair: str, next_address: int):
        super().__init__()
        self.pair = pair
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        for register in self.pair:
            self.state.globals[f"saved_{register}"] = getattr(self.state.regs, register)
        self.jump(self.next_address)


class RestorePair(angr.SimProcedure):
    def __init__(self, pair: str, next_address: int):
        super().__init__()
        self.pair = pair
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        for register in self.pair:
            setattr(self.state.regs, register, self.state.globals[f"saved_{register}"])
        self.jump(self.next_address)


class BankswitchHomeSummary(angr.SimProcedure):
    def __init__(self, next_address: int, native: bool = False):
        super().__init__()
        self.next_address = next_address
        self.native = native

    def run(self, state: claripy.ast.BV | None = None) -> None:  # type: ignore[override]
        if self.native:
            if state is None:
                state = self.state.regs.rdi
            self.state.globals["home_call"] = self.state.memory.load(state, 12)
            requested = self.state.memory.load(state, 1)
            loaded = self.state.memory.load(state + 9, 1)
            self.state.memory.store(state + 8, requested)
            self.state.memory.store(state + 10, loaded)
            self.state.memory.store(state, requested)
            self.state.memory.store(state + 9, requested)
            self.state.memory.store(state + 11, requested)
            return
        self.state.globals["home_call"] = claripy.Concat(
            *(assembly_registers(self.state)[register] for register in REGISTERS),
            self.state.globals["home_temp"],
            self.state.globals["loaded_rom_bank"],
            self.state.globals["home_saved_rom_bank"],
            self.state.globals["mapper_bank"],
        )
        loaded = self.state.globals["loaded_rom_bank"]
        self.state.globals["home_temp"] = self.state.regs.a
        self.state.globals["home_saved_rom_bank"] = loaded
        self.state.globals["loaded_rom_bank"] = self.state.regs.a
        self.state.globals["mapper_bank"] = self.state.regs.a
        self.jump(self.next_address)


class FetchBank(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        index = self.state.regs.c
        result = claripy.BVV(0, 8)
        for offset, value in enumerate(TABLE):
            result = claripy.If(index == offset, claripy.BVV(value, 8), result)
        self.state.regs.a = result
        self.jump(self.next_address)


class StoreMapBank(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.globals["map_rom_bank"] = self.state.regs.a
        self.jump(self.next_address)


class LoadMapBank(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals["map_rom_bank"]
        self.jump(self.next_address)


class StoreBank(angr.SimProcedure):
    def __init__(self, field: str, next_address: int):
        super().__init__()
        self.field = field
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.globals[self.field] = self.state.regs.a
        self.jump(self.next_address)


class BankswitchBackSummary(angr.SimProcedure):
    def __init__(self, next_address: int, native: bool = False):
        super().__init__()
        self.next_address = next_address
        self.native = native

    def run(self, state: claripy.ast.BV | None = None) -> None:  # type: ignore[override]
        if self.native:
            if state is None:
                state = self.state.regs.rdi
            self.state.globals["back_call"] = self.state.memory.load(state, 11)
            saved = self.state.memory.load(state + 8, 1)
            self.state.memory.store(state, saved)
            self.state.memory.store(state + 9, saved)
            self.state.memory.store(state + 10, saved)
            return
        self.state.globals["back_call"] = claripy.Concat(
            *(assembly_registers(self.state)[register] for register in REGISTERS),
            self.state.globals["home_saved_rom_bank"],
            self.state.globals["loaded_rom_bank"],
            self.state.globals["mapper_bank"],
        )
        saved = self.state.globals["home_saved_rom_bank"]
        self.state.regs.a = saved
        self.state.globals["loaded_rom_bank"] = saved
        self.state.globals["mapper_bank"] = saved
        self.jump(self.next_address)


class Finish(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(DONE)


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for field in FIELDS:
        values[field] = claripy.BVS(f"{prefix}_{field}", 8)
    return values


def _setup_globals(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    for field in FIELDS:
        state.globals[field] = values[field]
    state.globals["home_call"] = claripy.BVV(0, 96)
    state.globals["back_call"] = claripy.BVV(0, 88)


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "SwitchToMapRomBank")
    table_location = symbol_location(SYMBOLS, "MapHeaderBanks")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    assert linked_bytes(ROM, table_location, len(TABLE)) == TABLE
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0, "entry_point": location.address},
    )
    base = location.address
    project.hook(base, SavePair("hl", base + 1), length=1)
    project.hook(base + 1, SavePair("bc", base + 2), length=1)
    project.hook(base + 7, BankswitchHomeSummary(base + 10), length=3)
    project.hook(base + 13, Sm83AddHlRegisterPair("bc", base + 14), length=1)
    project.hook(base + 14, FetchBank(base + 15), length=1)
    project.hook(base + 15, StoreMapBank(base + 17), length=2)
    project.hook(base + 17, BankswitchBackSummary(base + 20), length=3)
    project.hook(base + 20, LoadMapBank(base + 22), length=2)
    project.hook(base + 22, StoreBank("loaded_rom_bank", base + 24), length=2)
    project.hook(base + 24, StoreBank("mapper_bank", base + 27), length=3)
    project.hook(base + 27, RestorePair("bc", base + 28), length=1)
    project.hook(base + 28, RestorePair("hl", base + 29), length=1)
    project.hook(base + 29, Finish(), length=1)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.solver.add(values["a"] < len(TABLE))
    _setup_globals(state, values)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE)
    assert not manager.errored
    return [
        Endpoint(
            **assembly_registers(end),
            state=claripy.Concat(*(end.globals[field] for field in FIELDS)),
            calls=claripy.Concat(end.globals["home_call"], end.globals["back_call"]),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_switch_to_map_rom_bank")
    home = project.loader.find_symbol("port_bankswitch_home")
    back = project.loader.find_symbol("port_bankswitch_back")
    assert function is not None and home is not None and back is not None
    project.hook(home.rebased_addr, BankswitchHomeSummary(0, True))
    project.hook(back.rebased_addr, BankswitchBackSummary(0, True))
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE)
    store_native_registers(state, NATIVE_STATE, values)
    state.solver.add(values["a"] < len(TABLE))
    for offset, field in enumerate(FIELDS, 8):
        state.memory.store(NATIVE_STATE + offset, values[field])
    _setup_globals(state, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            state=end.memory.load(NATIVE_STATE + 8, len(FIELDS)),
            calls=claripy.Concat(end.globals["home_call"], end.globals["back_call"]),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_switch_to_map_rom_bank_pathwise_equivalence() -> None:
    values = _inputs("switch_to_map_rom_bank")
    assert_pathwise_equivalent(
        _assembly(values), _native(values), (*REGISTERS, "state", "calls")
    )
