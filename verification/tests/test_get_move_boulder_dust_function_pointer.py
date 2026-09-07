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
from verification.harness.rom import collect_returns, linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import (
    Sm83AddHlRegisterPair, Sm83LoadAAtHlIncrement, Sm83LoadAImmediate,
    Sm83StoreAImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
ROM, SYMBOLS = ROOT / "pokered.gbc", ROOT / "pokered.sym"
ELF = ROOT / "verification/build/ports.elf"
NS, NM, TABLE, STACK, RETURN = 0x100000, 0x110000, 0x120000, 0xD000, 0xFFFF
FACING, ADJUST = 0xC109, 0xD08A
BODY = bytes.fromhex("fa09c121b05f4f0600092aea8ad02a5f2a666fe52190c31600195d54e1c9")
TABLE_BYTES = bytes.fromhex("ff0050530100505301013753ff013753")


@dataclass(frozen=True)
class Endpoint:
    registers: claripy.ast.BV
    memory: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class SetHL(angr.SimProcedure):
    def __init__(self, value, next_address):
        super().__init__()
        self.value, self.next_address = value, next_address

    def run(self):
        self.state.regs.hl = claripy.BVV(self.value, 16)
        self.jump(self.next_address)


class LoadHAtHL(angr.SimProcedure):
    def __init__(self, next_address):
        super().__init__()
        self.next_address = next_address

    def run(self):
        self.state.regs.h = self.state.memory.load(self.state.regs.hl, 1)
        self.jump(self.next_address)


class PushHL(angr.SimProcedure):
    def __init__(self, next_address):
        super().__init__()
        self.next_address = next_address

    def run(self):
        self.state.regs.sp -= 2
        self.state.memory.store(self.state.regs.sp, self.state.regs.hl, endness="Iend_LE")
        self.jump(self.next_address)


class PopHL(angr.SimProcedure):
    def __init__(self, next_address):
        super().__init__()
        self.next_address = next_address

    def run(self):
        self.state.regs.hl = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp += 2
        self.jump(self.next_address)


def endpoint(state, native):
    registers = native_registers(state, NS) if native else assembly_registers(state)
    base = NM if native else 0
    return Endpoint(
        claripy.Concat(*(registers[name] for name in REGISTERS)),
        claripy.Concat(state.memory.load(base + FACING, 1), state.memory.load(base + ADJUST, 1)),
        tuple(state.solver.constraints),
    )


def assembly(values, facing):
    location = symbol_location(SYMBOLS, "GetMoveBoulderDustFunctionPointer")
    table = symbol_location(SYMBOLS, "MoveBoulderDustFunctionPointerTable")
    assert linked_bytes(ROM, location, len(BODY)) == BODY
    assert linked_bytes(ROM, table, len(TABLE_BYTES)) == TABLE_BYTES
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False, rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    q = location.address
    project.hook(q, Sm83LoadAImmediate(FACING, q + 3), length=3)
    project.hook(q + 3, SetHL(table.address, q + 6), length=3)
    project.hook(q + 9, Sm83AddHlRegisterPair("bc", q + 10), length=1)
    project.hook(q + 10, Sm83LoadAAtHlIncrement(q + 11), length=1)
    project.hook(q + 11, Sm83StoreAImmediate(ADJUST, q + 14), length=3)
    project.hook(q + 14, Sm83LoadAAtHlIncrement(q + 15), length=1)
    project.hook(q + 16, Sm83LoadAAtHlIncrement(q + 17), length=1)
    project.hook(q + 17, LoadHAtHL(q + 18), length=1)
    project.hook(q + 19, PushHL(q + 20), length=1)
    project.hook(q + 20, SetHL(0xC390, q + 23), length=3)
    project.hook(q + 25, Sm83AddHlRegisterPair("de", q + 26), length=1)
    project.hook(q + 28, PopHL(q + 29), length=1)
    state = project.factory.blank_state(addr=q)
    set_assembly_registers(state, values)
    state.memory.store(FACING, claripy.BVV(facing, 8))
    state.memory.store(ADJUST, values["adjust"])
    state.regs.sp = claripy.BVV(STACK, 16)
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    ends = collect_returns(project, state, RETURN)
    assert len(ends) == 1
    return [endpoint(ends[0], False)]


def native(values, facing):
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_get_move_boulder_dust_function_pointer_memory")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NS, NM, TABLE)
    store_native_registers(state, NS, values)
    state.memory.store(NM + FACING, claripy.BVV(facing, 8))
    state.memory.store(NM + ADJUST, values["adjust"])
    state.memory.store(TABLE, TABLE_BYTES)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [endpoint(manager.deadended[0], True)]


@pytest.mark.skipif(not ELF.exists(), reason="run native")
@pytest.mark.parametrize("facing", (0, 4, 8, 12))
def test_get_move_boulder_dust_function_pointer_pathwise_equivalence(facing):
    values = symbolic_registers(f"boulder_dust_pointer_{facing}")
    values["adjust"] = claripy.BVS(f"boulder_dust_pointer_{facing}_adjust", 8)
    assert_pathwise_equivalent(
        assembly(values, facing), native(values, facing), ("registers", "memory")
    )
