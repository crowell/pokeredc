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
from verification.harness.rom import (
    collect_returns, linked_bytes, rom_window, symbol_location,
)
from verification.harness.sm83_shims import (
    Sm83AddHlRegisterPair, Sm83AddRegister, Sm83BitAtHl,
    Sm83LoadAHighImmediate, Sm83LoadAImmediate, Sm83ResAtHl,
    Sm83StoreAHighImmediate, Sm83StoreAImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
ROM, SYMBOLS = ROOT / "pokered.gbc", ROOT / "pokered.sym"
ELF = ROOT / "verification/build/ports.elf"
NS, NM, STACK, RETURN = 0x100000, 0x200000, 0xD000, 0xEFFF
POINTER_NUM, SCRIPT_BANK, FUNCTION_NUM = 0xCC57, 0xCC58, 0xCF10
MOVEMENT_FLAGS, LOADED_BANK, ROMB = 0xD736, 0xFFB8, 0x2000
BODY = bytes.fromhex(
    "2136d7cb46cb86202ffa57cca7c83d8716005f214031192a666ff0b8f5"
    "fa58cce0b8ea0020fa10cfcd973df1e0b8ea0020c9"
)
TABLES = (0x6442, 0x6510, 0x657D)
MEMORY = (POINTER_NUM, SCRIPT_BANK, FUNCTION_NUM, MOVEMENT_FLAGS,
          LOADED_BANK, ROMB)


@dataclass(frozen=True)
class Endpoint:
    registers: claripy.ast.BV
    memory: claripy.ast.BV
    trace: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def rv(registers):
    return claripy.Concat(*(registers[name] for name in REGISTERS))


def return_from_stack(procedure):
    target = procedure.state.memory.load(
        procedure.state.regs.sp, 2, endness="Iend_LE")
    procedure.state.regs.sp += 2
    procedure.inhibit_autoret = True
    procedure.jump(target)


class AndA(angr.SimProcedure):
    def __init__(self, next_address):
        super().__init__(); self.next_address = next_address

    def run(self):
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        self.jump(self.next_address)


class TableLow(angr.SimProcedure):
    def __init__(self, table, next_address):
        super().__init__(); self.table, self.next_address = table, next_address

    def run(self):
        self.state.regs.a = claripy.BVV(self.table & 0xFF, 8)
        self.state.regs.hl += 1
        self.jump(self.next_address)


class TableHigh(angr.SimProcedure):
    def __init__(self, table, next_address):
        super().__init__(); self.table, self.next_address = table, next_address

    def run(self):
        self.state.regs.h = claripy.BVV(self.table >> 8, 8)
        self.jump(self.next_address)


class AssemblyCall(angr.SimProcedure):
    def run(self):
        payload = claripy.Concat(
            rv(assembly_registers(self.state)), self.state.globals["fetched_low"],
            self.state.globals["fetched_high"], self.state.globals["callback_a"],
            self.state.globals["callback_f"],
        )
        self.state.globals["trace"] = (payload,)
        registers = assembly_registers(self.state)
        registers["a"] = self.state.globals["callback_a"]
        registers["f"] = self.state.globals["callback_f"]
        set_assembly_registers(self.state, registers)
        return_from_stack(self)


class NativeCall(angr.SimProcedure):
    def run(self, state, callback_a, callback_f):
        payload = claripy.Concat(
            rv(native_registers(self.state, state)),
            self.state.memory.load(state + 8, 1),
            self.state.memory.load(state + 9, 1), callback_a[7:0], callback_f[7:0],
        )
        self.state.globals["trace"] = (payload,)
        self.state.memory.store(state, callback_a[7:0])
        self.state.memory.store(state + 1, callback_f[7:0])


class AssemblyDoor(angr.SimProcedure):
    def run(self):
        self.state.regs.b = claripy.BVV(6, 8)
        self.state.regs.h = claripy.BVV(0x63, 8)
        self.state.regs.l = claripy.BVV(0xE0, 8)
        self.jump(RETURN)


def inputs(prefix):
    values = symbolic_registers(prefix)
    for name in ("script_bank", "function_num", "loaded_bank", "fetched_low",
                 "fetched_high", "callback_a", "callback_f"):
        values[name] = claripy.BVS(f"{prefix}_{name}", 8)
    return values


def setup(state, base, values, pointer_num, door):
    initial = {
        POINTER_NUM: pointer_num, SCRIPT_BANK: values["script_bank"],
        FUNCTION_NUM: values["function_num"], MOVEMENT_FLAGS: 1 if door else 0,
        LOADED_BANK: values["loaded_bank"], ROMB: values["loaded_bank"],
    }
    for address, value in initial.items():
        state.memory.store(base + address,
                           value if isinstance(value, claripy.ast.BV)
                           else claripy.BVV(value, 8))
    state.globals["trace"] = ()
    state.globals["fetched_low"] = values["fetched_low"]
    state.globals["fetched_high"] = values["fetched_high"]
    state.globals["callback_a"] = values["callback_a"]
    state.globals["callback_f"] = values["callback_f"]
    state.solver.add(values["callback_f"] & 0x0F == 0)


def endpoint(state, base, native):
    registers = native_registers(state, NS) if native else assembly_registers(state)
    trace = (claripy.Concat(*state.globals["trace"])
             if state.globals["trace"] else claripy.BVV(0, 1))
    return Endpoint(
        rv(registers),
        claripy.Concat(*(state.memory.load(base + address, 1) for address in MEMORY)),
        trace, tuple(state.solver.constraints),
    )


def assembly(values, pointer_num, door):
    location = symbol_location(SYMBOLS, "RunNPCMovementScript")
    assert linked_bytes(ROM, location, len(BODY)) == BODY
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100, main_opts={"backend": "blob",
        "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0,
        "entry_point": location.address})
    q = location.address
    project.hook(q + 3, Sm83BitAtHl(0, q + 5), length=2)
    project.hook(q + 5, Sm83ResAtHl(0, q + 7), length=2)
    project.hook(q + 9, Sm83LoadAImmediate(POINTER_NUM, q + 12), length=3)
    project.hook(q + 12, AndA(q + 13), length=1)
    project.hook(q + 15, Sm83AddRegister("a", q + 16), length=1)
    project.hook(q + 22, Sm83AddHlRegisterPair("de", q + 23), length=1)
    if pointer_num:
        table = TABLES[pointer_num - 1]
        project.hook(q + 23, TableLow(table, q + 24), length=1)
        project.hook(q + 24, TableHigh(table, q + 25), length=1)
    project.hook(q + 26, Sm83LoadAHighImmediate(0xB8, q + 28), length=2)
    project.hook(q + 29, Sm83LoadAImmediate(SCRIPT_BANK, q + 32), length=3)
    project.hook(q + 32, Sm83StoreAHighImmediate(0xB8, q + 34), length=2)
    project.hook(q + 34, Sm83StoreAImmediate(ROMB, q + 37), length=3)
    project.hook(q + 37, Sm83LoadAImmediate(FUNCTION_NUM, q + 40), length=3)
    project.hook(symbol_location(SYMBOLS, "CallFunctionInTable").address,
                 AssemblyCall())
    project.hook(q + 44, Sm83StoreAHighImmediate(0xB8, q + 46), length=2)
    project.hook(q + 46, Sm83StoreAImmediate(ROMB, q + 49), length=3)
    project.hook(symbol_location(
        SYMBOLS, "RunNPCMovementScript.playerStepOutFromDoor").address,
        AssemblyDoor())
    state = project.factory.blank_state(addr=q)
    set_assembly_registers(state, values)
    state.regs.sp = claripy.BVV(STACK, 16)
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    setup(state, 0, values, pointer_num, door)
    ends = collect_returns(project, state, RETURN)
    assert len(ends) == 1
    return [endpoint(ends[0], 0, False)]


def native(values, pointer_num, door):
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_run_npc_movement_script"); assert function
    callee = project.loader.find_symbol("port_call_function_in_table"); assert callee
    project.hook(callee.rebased_addr, NativeCall())
    state = project.factory.call_state(
        function.rebased_addr, NS, NM, values["fetched_low"],
        values["fetched_high"], values["callback_a"], values["callback_f"])
    store_native_registers(state, NS, values)
    setup(state, NM, values, pointer_num, door)
    manager = project.factory.simulation_manager(state); manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [endpoint(manager.deadended[0], NM, True)]


@pytest.mark.skipif(not ELF.exists(), reason="run native")
@pytest.mark.parametrize("pointer_num,door", ((0, False), (0, True),
                                                (1, False), (2, False),
                                                (3, False)))
def test_run_npc_movement_script_pathwise_equivalence(pointer_num, door):
    values = inputs(f"npc_movement_{pointer_num}_{door}")
    assert_pathwise_equivalent(
        assembly(values, pointer_num, door), native(values, pointer_num, door),
        ("registers", "memory", "trace"),
    )
