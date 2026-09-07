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
from verification.harness.sm83_shims import Sm83BitRegister, Sm83LoadAImmediate

ROOT = Path(__file__).resolve().parents[2]
ROM, SYMBOLS = ROOT / "pokered.gbc", ROOT / "pokered.sym"
ELF = ROOT / "verification/build/ports.elf"
NS, NM, STACK, RETURN = 0x100000, 0x200000, 0xD000, 0xEFFF
ASM_CALLBACK, NATIVE_CALLBACK = 0x5000, 0x700000
MISC, HOME_SAVED, HOME_TEMP = 0xCD60, 0xCF08, 0xCF09
CUR_MAP, SCRIPT_PTR, MARKER = 0xD35E, 0xD36E, 0xD500
LOADED, SAVED, MAP_BANK, ROMB = 0xFFB8, 0xFFB9, 0xFFE8, 0x2000
BODY = bytes.fromhex(
    "e5d5c50603212572cdd635fa60cdcb4f2808060321b572cdd635c1d1e1cd"
    "0e31fa5ed3cdbc12216ed32a666f114c10d5e9c9"
)
MEMORY = (MISC, HOME_SAVED, HOME_TEMP, CUR_MAP, SCRIPT_PTR, SCRIPT_PTR + 1,
          MARKER, LOADED, SAVED, MAP_BANK, ROMB)


@dataclass(frozen=True)
class Endpoint:
    registers: claripy.ast.BV
    memory: claripy.ast.BV
    trace: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def rv(registers):
    return claripy.Concat(*(registers[name] for name in REGISTERS))


def byte_at(value, index, size=8):
    high = size * 8 - index * 8 - 1
    return value[high:high - 7]


def set_asm_regs(state, value):
    registers = {name: byte_at(value, index) for index, name in enumerate(REGISTERS)}
    set_assembly_registers(state, registers)


def set_native_regs(state, pointer, value):
    for index in range(8):
        state.memory.store(pointer + index, byte_at(value, index))


def memv(state, base):
    return claripy.Concat(*(state.memory.load(base + address, 1) for address in MEMORY))


def record(state, tag, registers, base):
    state.globals["trace"] += (claripy.Concat(claripy.BVV(tag, 8),
                                               rv(registers), memv(state, base)),)


def return_from_stack(procedure):
    target = procedure.state.memory.load(procedure.state.regs.sp, 2, endness="Iend_LE")
    procedure.state.regs.sp += 2
    procedure.inhibit_autoret = True
    procedure.jump(target)


class AssemblyBankswitch(angr.SimProcedure):
    def run(self):
        before = assembly_registers(self.state)
        saved_bank, saved_flags = self.state.memory.load(LOADED, 1), before["f"]
        target = self.state.solver.eval(self.state.regs.hl)
        tag = 1 if target == 0x7225 else 2
        callee = dict(before)
        callee.update(a=claripy.BVV(3, 8), b=claripy.BVV(0x35, 8),
                      c=claripy.BVV(0xE4, 8), h=claripy.BVV(target >> 8, 8),
                      l=claripy.BVV(target & 0xFF, 8))
        self.state.memory.store(LOADED, claripy.BVV(3, 8))
        self.state.memory.store(ROMB, claripy.BVV(3, 8))
        record(self.state, tag, callee, 0)
        set_asm_regs(self.state, self.state.globals["try_post" if tag == 1 else "dust_post"])
        if tag == 1:
            self.state.memory.store(MISC, claripy.BVV(self.state.globals["dust"], 8))
        self.state.regs.b = saved_bank
        set_assembly_registers(self.state, {**assembly_registers(self.state), "c": saved_flags})
        self.state.regs.a = saved_bank
        self.state.memory.store(LOADED, saved_bank)
        self.state.memory.store(ROMB, saved_bank)
        return_from_stack(self)


class NativeBoulder(angr.SimProcedure):
    def __init__(self, tag):
        super().__init__(); self.tag = tag

    def run(self, registers, memory):
        record(self.state, self.tag, native_registers(self.state, registers), NM)
        set_native_regs(self.state, registers,
                        self.state.globals["try_post" if self.tag == 1 else "dust_post"])
        if self.tag == 1:
            self.state.memory.store(memory + MISC,
                                    claripy.BVV(self.state.globals["dust"], 8))


class AssemblyNPC(angr.SimProcedure):
    def run(self):
        record(self.state, 3, assembly_registers(self.state), 0)
        set_asm_regs(self.state, self.state.globals["npc_post"])
        return_from_stack(self)


class NativeNPC(angr.SimProcedure):
    def run(self, registers, memory, *_args):
        record(self.state, 3, native_registers(self.state, registers), NM)
        set_native_regs(self.state, registers, self.state.globals["npc_post"])


class AssemblySwitch(angr.SimProcedure):
    def run(self):
        record(self.state, 4, assembly_registers(self.state), 0)
        set_asm_regs(self.state, self.state.globals["switch_post"])
        for index, address in enumerate((MAP_BANK, LOADED, ROMB, HOME_TEMP, HOME_SAVED)):
            self.state.memory.store(address, byte_at(self.state.globals["switch_memory"], index, 5))
        return_from_stack(self)


class NativeSwitch(angr.SimProcedure):
    def run(self, state):
        record(self.state, 4, native_registers(self.state, state), NM)
        set_native_regs(self.state, state, self.state.globals["switch_post"])
        self.state.memory.store(state + 8, self.state.globals["switch_memory"])


class ReadPointer(angr.SimProcedure):
    def __init__(self, next_address):
        super().__init__(); self.next_address = next_address

    def run(self):
        self.state.regs.a = self.state.memory.load(SCRIPT_PTR, 1)
        self.state.regs.hl += 1
        self.state.regs.h = self.state.memory.load(SCRIPT_PTR + 1, 1)
        self.state.regs.l = self.state.regs.a
        self.jump(self.next_address)


class AssemblyCallback(angr.SimProcedure):
    def run(self):
        record(self.state, 5, assembly_registers(self.state), 0)
        set_asm_regs(self.state, self.state.globals["callback_post"])
        self.state.memory.store(MARKER, self.state.globals["callback_marker"])
        return_from_stack(self)


class NativeCallback(angr.SimProcedure):
    def run(self, registers, memory):
        record(self.state, 5, native_registers(self.state, registers), NM)
        set_native_regs(self.state, registers, self.state.globals["callback_post"])
        self.state.memory.store(memory + MARKER, self.state.globals["callback_marker"])


def inputs(prefix):
    values = symbolic_registers(prefix)
    for name, bits in (("try_post", 64), ("dust_post", 64), ("npc_post", 64),
                       ("switch_post", 64), ("switch_memory", 40),
                       ("callback_post", 64), ("callback_marker", 8),
                       ("loaded", 8), ("saved", 8), ("map_bank", 8),
                       ("home_saved", 8), ("home_temp", 8), ("cur_map", 8)):
        values[name] = claripy.BVS(f"{prefix}_{name}", bits)
    return values


def setup(state, base, values, dust):
    initial = {MISC: 0, HOME_SAVED: values["home_saved"], HOME_TEMP: values["home_temp"],
               CUR_MAP: values["cur_map"], SCRIPT_PTR: ASM_CALLBACK & 0xFF,
               SCRIPT_PTR + 1: ASM_CALLBACK >> 8, MARKER: 0, LOADED: values["loaded"],
               SAVED: values["saved"], MAP_BANK: values["map_bank"], ROMB: values["loaded"]}
    for address, value in initial.items():
        state.memory.store(base + address, value if isinstance(value, claripy.ast.BV)
                           else claripy.BVV(value, 8))
    state.globals["trace"] = (); state.globals["dust"] = dust
    for name in ("try_post", "dust_post", "npc_post", "switch_post",
                 "switch_memory", "callback_post", "callback_marker"):
        state.globals[name] = values[name]
    for name in ("try_post", "dust_post", "npc_post", "switch_post", "callback_post"):
        state.solver.add(byte_at(values[name], 1) & 0x0F == 0)


def endpoint(state, base, native):
    registers = native_registers(state, NS) if native else assembly_registers(state)
    return Endpoint(rv(registers), memv(state, base), claripy.Concat(*state.globals["trace"]),
                    tuple(state.solver.constraints))


def assembly(values, dust):
    location = symbol_location(SYMBOLS, "RunMapScript")
    assert linked_bytes(ROM, location, len(BODY)) == BODY
    project = angr.Project(rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100, main_opts={"backend": "blob",
        "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0,
        "entry_point": location.address})
    q = location.address
    project.hook(symbol_location(SYMBOLS, "Bankswitch").address, AssemblyBankswitch())
    project.hook(q + 11, Sm83LoadAImmediate(MISC, q + 14), length=3)
    project.hook(q + 14, Sm83BitRegister(1, "a", q + 16), length=2)
    project.hook(symbol_location(SYMBOLS, "RunNPCMovementScript").address, AssemblyNPC())
    project.hook(q + 32, Sm83LoadAImmediate(CUR_MAP, q + 35), length=3)
    project.hook(symbol_location(SYMBOLS, "SwitchToMapRomBank").address, AssemblySwitch())
    project.hook(q + 41, ReadPointer(q + 44), length=3)
    project.hook(ASM_CALLBACK, AssemblyCallback())
    state = project.factory.blank_state(addr=q)
    set_assembly_registers(state, values); state.regs.sp = claripy.BVV(STACK, 16)
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    setup(state, 0, values, dust)
    ends = collect_returns(project, state, RETURN); assert len(ends) == 1
    return [endpoint(ends[0], 0, False)]


def native(values, dust):
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_run_map_script"); assert function
    for name, procedure in (("port_try_pushing_boulder", NativeBoulder(1)),
                            ("port_do_boulder_dust_animation", NativeBoulder(2)),
                            ("port_run_npc_movement_script", NativeNPC()),
                            ("port_switch_to_map_rom_bank", NativeSwitch())):
        symbol = project.loader.find_symbol(name); assert symbol
        project.hook(symbol.rebased_addr, procedure)
    project.hook(NATIVE_CALLBACK, NativeCallback())
    state = project.factory.call_state(
        function.rebased_addr, NS, NM, 0, 0, 0, 0, NATIVE_CALLBACK)
    store_native_registers(state, NS, values); setup(state, NM, values, dust)
    manager = project.factory.simulation_manager(state); manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [endpoint(manager.deadended[0], NM, True)]


@pytest.mark.skipif(not ELF.exists(), reason="run native")
@pytest.mark.parametrize("dust", (0, 2))
def test_run_map_script_pathwise_equivalence(dust):
    values = inputs(f"run_map_{dust}")
    assert_pathwise_equivalent(assembly(values, dust), native(values, dust),
                               ("registers", "memory", "trace"))
