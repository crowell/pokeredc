from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
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
from verification.harness.sm83_shims import (
    Sm83AddHlRegisterPair,
    Sm83AddRegister,
    Sm83DecRegister,
    Sm83LoadAAtHlIncrement,
    Sm83LdAFromRegPreserveF,
    Sm83Rlca,
    Sm83StoreAImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x400000
DONE = 0xEFFF

CRY_DATA = 0x5446
CRY_DATA_BANK = 0x0E
CRY_DATA_SIZE = 190 * 3
W_FREQUENCY_MODIFIER = 0xC0F1
W_TEMPO_MODIFIER = 0xC0F2
W_BANKSWITCH_HOME_SAVED_ROM_BANK = 0xCF08
W_BANKSWITCH_HOME_TEMP = 0xCF09
H_LOADED_ROM_BANK = 0xFFB8
R_ROMB = 0x2000

EXPECTED = bytes.fromhex(
    "3d4f06002146540909093e0ecdbc352a472aeaf1c07eeaf2c0cdcd35780e14078081c9"
)
CRY_DATA_SHA256 = "62329ff48c608b529e0c031ab215662a6975c2ff00835713ddd38d2af6b47562"


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
    cry_data: claripy.ast.BV
    calls: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class LoadRegister(angr.SimProcedure):
    def __init__(self, destination: str, source: str, next_address: int):
        super().__init__()
        self.destination = destination
        self.source = source
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.destination, getattr(self.state.regs, self.source))
        self.jump(self.next_address)


class LoadRegisterImmediate(angr.SimProcedure):
    def __init__(self, register: str, value: int, next_address: int):
        super().__init__()
        self.register = register
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.register, claripy.BVV(self.value, 8))
        self.jump(self.next_address)


class LoadHlImmediate(angr.SimProcedure):
    def __init__(self, value: int, next_address: int):
        super().__init__()
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = claripy.BVV(self.value >> 8, 8)
        self.state.regs.l = claripy.BVV(self.value & 0xFF, 8)
        self.jump(self.next_address)


class LoadAAtHl(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self.state.regs.hl, 1)
        self.jump(self.next_address)


class BankswitchHomeSummary(angr.SimProcedure):
    """Exact transition of the independently proven BankswitchHome body."""

    def __init__(self, next_address: int):
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        registers = assembly_registers(self.state)
        self.state.globals["home_call"] = claripy.Concat(
            *(registers[register] for register in REGISTERS),
            self.state.memory.load(W_BANKSWITCH_HOME_TEMP, 1),
            self.state.memory.load(H_LOADED_ROM_BANK, 1),
            self.state.memory.load(W_BANKSWITCH_HOME_SAVED_ROM_BANK, 1),
            self.state.memory.load(R_ROMB, 1),
        )
        self.state.globals["home_count"] += 1
        requested = self.state.regs.a
        loaded = self.state.memory.load(H_LOADED_ROM_BANK, 1)
        self.state.memory.store(W_BANKSWITCH_HOME_TEMP, requested)
        self.state.regs.a = loaded
        self.state.memory.store(W_BANKSWITCH_HOME_SAVED_ROM_BANK, loaded)
        self.state.regs.a = requested
        self.state.memory.store(H_LOADED_ROM_BANK, requested)
        self.state.memory.store(R_ROMB, requested)
        self.jump(self.next_address)


class BankswitchBackSummary(angr.SimProcedure):
    """Exact transition of the independently proven BankswitchBack body."""

    def __init__(self, next_address: int):
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        registers = assembly_registers(self.state)
        self.state.globals["back_call"] = claripy.Concat(
            *(registers[register] for register in REGISTERS),
            self.state.memory.load(W_BANKSWITCH_HOME_SAVED_ROM_BANK, 1),
            self.state.memory.load(H_LOADED_ROM_BANK, 1),
            self.state.memory.load(R_ROMB, 1),
        )
        self.state.globals["back_count"] += 1
        saved = self.state.memory.load(W_BANKSWITCH_HOME_SAVED_ROM_BANK, 1)
        self.state.regs.a = saved
        self.state.memory.store(H_LOADED_ROM_BANK, saved)
        self.state.memory.store(R_ROMB, saved)
        self.jump(self.next_address)


class NativeBankswitchHomeSummary(angr.SimProcedure):
    def run(self, state: claripy.ast.BV) -> None:  # type: ignore[override]
        self.state.globals["home_call"] = self.state.memory.load(state, 12)
        self.state.globals["home_count"] += 1
        requested = self.state.memory.load(state, 1)
        loaded = self.state.memory.load(state + 9, 1)
        self.state.memory.store(state + 8, requested)
        self.state.memory.store(state, loaded)
        self.state.memory.store(state + 10, loaded)
        self.state.memory.store(state, requested)
        self.state.memory.store(state + 9, requested)
        self.state.memory.store(state + 11, requested)


class NativeBankswitchBackSummary(angr.SimProcedure):
    def run(self, state: claripy.ast.BV) -> None:  # type: ignore[override]
        self.state.globals["back_call"] = self.state.memory.load(state, 11)
        self.state.globals["back_count"] += 1
        saved = self.state.memory.load(state + 8, 1)
        self.state.memory.store(state, saved)
        self.state.memory.store(state + 9, saved)
        self.state.memory.store(state + 10, saved)


class Finish(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.jump(DONE)


def inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for name in ("home_temp", "loaded", "home_saved", "romb", "freq", "tempo"):
        values[name] = claripy.BVS(f"{prefix}_{name}", 8)
    return values


def setup(state: angr.SimState, values: dict[str, claripy.ast.BV], base: int = 0) -> None:
    state.solver.add(values["a"].UGE(1), values["a"].ULE(190))
    for address, name in (
        (W_BANKSWITCH_HOME_TEMP, "home_temp"),
        (H_LOADED_ROM_BANK, "loaded"),
        (W_BANKSWITCH_HOME_SAVED_ROM_BANK, "home_saved"),
        (R_ROMB, "romb"),
        (W_FREQUENCY_MODIFIER, "freq"),
        (W_TEMPO_MODIFIER, "tempo"),
    ):
        state.memory.store(base + address, values[name])
    state.globals["home_call"] = claripy.BVV(0, 96)
    state.globals["back_call"] = claripy.BVV(0, 88)
    state.globals["home_count"] = claripy.BVV(0, 8)
    state.globals["back_count"] = claripy.BVV(0, 8)


def endpoint(state: angr.SimState, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    registers = native_registers(state, NATIVE_STATE) if native else assembly_registers(state)
    memory = claripy.Concat(
        *(state.memory.load(base + address, 1) for address in (
            W_BANKSWITCH_HOME_TEMP,
            H_LOADED_ROM_BANK,
            W_BANKSWITCH_HOME_SAVED_ROM_BANK,
            R_ROMB,
            W_FREQUENCY_MODIFIER,
            W_TEMPO_MODIFIER,
        ))
    )
    return Endpoint(
        **registers,
        memory=memory,
        cry_data=state.memory.load(base + CRY_DATA, CRY_DATA_SIZE),
        calls=claripy.Concat(
            state.globals["home_call"],
            state.globals["back_call"],
            state.globals["home_count"],
            state.globals["back_count"],
        ),
        constraints=tuple(state.solver.constraints),
    )


def assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "GetCryData")
    cry_location = symbol_location(SYMBOLS, "CryData")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    cry_data = linked_bytes(ROM, cry_location, CRY_DATA_SIZE)
    assert (cry_location.bank, cry_location.address) == (CRY_DATA_BANK, CRY_DATA)
    assert sha256(cry_data).hexdigest() == CRY_DATA_SHA256
    project = angr.Project(
        rom_window(ROM, CRY_DATA_BANK),
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
    project.hook(base, Sm83DecRegister("a", base + 1), length=1)
    project.hook(base + 1, LoadRegister("c", "a", base + 2), length=1)
    project.hook(base + 2, LoadRegisterImmediate("b", 0, base + 4), length=2)
    project.hook(base + 4, LoadHlImmediate(CRY_DATA, base + 7), length=3)
    for offset in (7, 8, 9):
        project.hook(base + offset, Sm83AddHlRegisterPair("bc", base + offset + 1), length=1)
    project.hook(base + 10, LoadRegisterImmediate("a", CRY_DATA_BANK, base + 12), length=2)
    project.hook(base + 12, BankswitchHomeSummary(base + 15), length=3)
    project.hook(base + 15, Sm83LoadAAtHlIncrement(base + 16), length=1)
    project.hook(base + 16, LoadRegister("b", "a", base + 17), length=1)
    project.hook(base + 17, Sm83LoadAAtHlIncrement(base + 18), length=1)
    project.hook(base + 18, Sm83StoreAImmediate(W_FREQUENCY_MODIFIER, base + 21), length=3)
    project.hook(base + 21, LoadAAtHl(base + 22), length=1)
    project.hook(base + 22, Sm83StoreAImmediate(W_TEMPO_MODIFIER, base + 25), length=3)
    project.hook(base + 25, BankswitchBackSummary(base + 28), length=3)
    project.hook(base + 28, Sm83LdAFromRegPreserveF("b", base + 29), length=1)
    project.hook(base + 29, LoadRegisterImmediate("c", 0x14, base + 31), length=2)
    project.hook(base + 31, Sm83Rlca(base + 32), length=1)
    project.hook(base + 32, Sm83AddRegister("b", base + 33), length=1)
    project.hook(base + 33, Sm83AddRegister("c", base + 34), length=1)
    project.hook(base + 34, Finish(), length=1)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    setup(state, values)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE)
    assert not manager.errored and len(manager.found) == 1
    return [endpoint(end, False) for end in manager.found]


def native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    cry_data = linked_bytes(ROM, symbol_location(SYMBOLS, "CryData"), CRY_DATA_SIZE)
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_get_cry_data")
    home = project.loader.find_symbol("port_bankswitch_home")
    back = project.loader.find_symbol("port_bankswitch_back")
    assert function is not None and home is not None and back is not None
    project.hook(home.rebased_addr, NativeBankswitchHomeSummary())
    project.hook(back.rebased_addr, NativeBankswitchBackSummary())
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_MEMORY + CRY_DATA, cry_data)
    setup(state, values, NATIVE_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [endpoint(end, True) for end in manager.deadended]


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(), reason="build")
def test_get_cry_data_pathwise_equivalence() -> None:
    values = inputs("get_cry_data")
    assert_pathwise_equivalent(
        assembly(values), native(values), (*REGISTERS, "memory", "cry_data", "calls")
    )
