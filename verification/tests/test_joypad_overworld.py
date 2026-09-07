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
    Sm83AddRegister, Sm83AndImmediate, Sm83AndRegister, Sm83BitRegister,
    Sm83CpImmediate, Sm83DecAtHl, Sm83IncRegister, Sm83LoadAHighImmediate,
    Sm83LoadAImmediate, Sm83ResAtHl, Sm83StoreAHighImmediate,
    Sm83StoreAImmediate, Sm83XorA,
)

ROOT = Path(__file__).resolve().parents[2]
ROM, SYMBOLS = ROOT / "pokered.gbc", ROOT / "pokered.sym"
ELF = ROOT / "verification/build/ports.elf"
NS, NM, STACK, RETURN = 0x100000, 0x200000, 0xD000, 0xEFFF
YSTEP, XSTEP, SIM_END, SIM_INDEX = 0xC103, 0xC105, 0xCCD3, 0xCD38
UNUSED_INDEX, OVERRIDE, JOY_IGNORE = 0xCD3A, 0xCD3B, 0xCD6B
STATUS5, STATUS7, MOVEMENT, CUR_MAP = 0xD730, 0xD733, 0xD736, 0xD35E
RELEASED, PRESSED, HELD = 0xFFB2, 0xFFB3, 0xFFB4
SIM_SIZE = 0xFF
BODY = bytes.fromhex(
    "afea03c1ea05c1cd1b10cd9a01fa33d7cb5f2011fa5ed3fe1c200af0b4e6f32004"
    "3e80e0b4fa30d7cb7fc8f0b447fa3bcda0c02138cd357efeff281221d3cc856f3001"
    "247ee0b4a7c0e0b3e0b2c9afea3acdea38cdead3ccea6bcde0b42136d77ee6f87721"
    "30d7cbbec9"
)
SCALARS = (YSTEP, XSTEP, SIM_INDEX, UNUSED_INDEX, OVERRIDE, JOY_IGNORE,
           STATUS5, STATUS7, MOVEMENT, CUR_MAP, RELEASED, PRESSED, HELD)


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
    set_assembly_registers(state, {
        name: byte_at(value, index) for index, name in enumerate(REGISTERS)
    })


def set_native_regs(state, pointer, value):
    for index in range(8):
        state.memory.store(pointer + index, byte_at(value, index))


def memory_vector(state, base):
    return claripy.Concat(
        *(state.memory.load(base + address, 1) for address in SCALARS),
        state.memory.load(base + SIM_END, SIM_SIZE),
    )


def trace_call(state, tag, registers, base):
    state.globals["trace"] += (claripy.Concat(
        claripy.BVV(tag, 8), rv(registers),
        *(state.memory.load(base + address, 1) for address in SCALARS)),)


def return_from_stack(procedure):
    target = procedure.state.memory.load(procedure.state.regs.sp, 2, endness="Iend_LE")
    procedure.state.regs.sp += 2
    procedure.inhibit_autoret = True
    procedure.jump(target)


class AssemblyMap(angr.SimProcedure):
    def run(self):
        trace_call(self.state, 1, assembly_registers(self.state), 0)
        set_asm_regs(self.state, self.state.globals["map_post"])
        return_from_stack(self)


class NativeMap(angr.SimProcedure):
    def run(self, registers, _memory, *_args):
        trace_call(self.state, 1, native_registers(self.state, registers), NM)
        set_native_regs(self.state, registers, self.state.globals["map_post"])


class AssemblyJoypad(angr.SimProcedure):
    def run(self):
        trace_call(self.state, 2, assembly_registers(self.state), 0)
        set_asm_regs(self.state, self.state.globals["joy_post"])
        return_from_stack(self)


class NativeJoypad(angr.SimProcedure):
    def run(self, registers, _memory):
        trace_call(self.state, 2, native_registers(self.state, registers), NM)
        set_native_regs(self.state, registers, self.state.globals["joy_post"])


class LoadAtHl(angr.SimProcedure):
    def __init__(self, next_address):
        super().__init__(); self.next_address = next_address

    def run(self):
        self.state.regs.a = self.state.memory.load(self.state.regs.hl, 1)
        self.jump(self.next_address)


class StoreAtHl(angr.SimProcedure):
    def __init__(self, next_address):
        super().__init__(); self.next_address = next_address

    def run(self):
        self.state.memory.store(self.state.regs.hl, self.state.regs.a)
        self.jump(self.next_address)


def inputs(prefix):
    values = symbolic_registers(prefix)
    values["map_post"] = claripy.BVS(f"{prefix}_map_post", 64)
    values["joy_post"] = claripy.BVS(f"{prefix}_joy_post", 64)
    values["sim_data"] = claripy.BVS(f"{prefix}_sim_data", SIM_SIZE * 8)
    return values


def setup(state, base, values, *, status7, cur_map, held, status5,
          override, index, fetched):
    state.memory.store(base + SIM_END, values["sim_data"])
    initial = {
        YSTEP: 0x91, XSTEP: 0x92, SIM_INDEX: index,
        UNUSED_INDEX: 0x93, OVERRIDE: override, JOY_IGNORE: 0x94,
        STATUS5: status5, STATUS7: status7, MOVEMENT: 0xFF,
        CUR_MAP: cur_map, RELEASED: 0x95, PRESSED: 0x96, HELD: held,
    }
    for address, value in initial.items():
        state.memory.store(base + address, claripy.BVV(value, 8))
    if index != 0:
        address = (SIM_END + ((index - 1) & 0xFF)) & 0xFFFF
        if address not in SCALARS:
            state.memory.store(base + address, claripy.BVV(fetched, 8))
    state.globals["trace"] = ()
    state.globals["map_post"] = values["map_post"]
    state.globals["joy_post"] = values["joy_post"]
    state.solver.add(byte_at(values["map_post"], 1) & 0x0F == 0)
    state.solver.add(byte_at(values["joy_post"], 1) & 0x0F == 0)


def endpoint(state, base, native):
    registers = native_registers(state, NS) if native else assembly_registers(state)
    return Endpoint(rv(registers), memory_vector(state, base),
                    claripy.Concat(*state.globals["trace"]),
                    tuple(state.solver.constraints))


def assembly(values, scenario):
    location = symbol_location(SYMBOLS, "JoypadOverworld")
    assert linked_bytes(ROM, location, len(BODY)) == BODY
    project = angr.Project(rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100, main_opts={"backend": "blob",
        "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0,
        "entry_point": location.address})
    q = location.address
    project.hook(q, Sm83XorA(q + 1), length=1)
    project.hook(q + 1, Sm83StoreAImmediate(YSTEP, q + 4), length=3)
    project.hook(q + 4, Sm83StoreAImmediate(XSTEP, q + 7), length=3)
    project.hook(symbol_location(SYMBOLS, "RunMapScript").address, AssemblyMap())
    project.hook(symbol_location(SYMBOLS, "Joypad").address, AssemblyJoypad())
    project.hook(q + 13, Sm83LoadAImmediate(STATUS7, q + 16), length=3)
    project.hook(q + 16, Sm83BitRegister(3, "a", q + 18), length=2)
    project.hook(q + 20, Sm83LoadAImmediate(CUR_MAP, q + 23), length=3)
    project.hook(q + 23, Sm83CpImmediate(0x1C, q + 25), length=2)
    project.hook(q + 27, Sm83LoadAHighImmediate(0xB4, q + 29), length=2)
    project.hook(q + 29, Sm83AndImmediate(0xF3, q + 31), length=2)
    project.hook(q + 35, Sm83StoreAHighImmediate(0xB4, q + 37), length=2)
    project.hook(q + 37, Sm83LoadAImmediate(STATUS5, q + 40), length=3)
    project.hook(q + 40, Sm83BitRegister(7, "a", q + 42), length=2)
    project.hook(q + 43, Sm83LoadAHighImmediate(0xB4, q + 45), length=2)
    project.hook(q + 46, Sm83LoadAImmediate(OVERRIDE, q + 49), length=3)
    project.hook(q + 49, Sm83AndRegister("b", q + 50), length=1)
    project.hook(q + 54, Sm83DecAtHl(q + 55), length=1)
    project.hook(q + 55, LoadAtHl(q + 56), length=1)
    project.hook(q + 56, Sm83CpImmediate(0xFF, q + 58), length=2)
    project.hook(q + 63, Sm83AddRegister("l", q + 64), length=1)
    project.hook(q + 67, Sm83IncRegister("h", q + 68), length=1)
    project.hook(q + 68, LoadAtHl(q + 69), length=1)
    project.hook(q + 69, Sm83StoreAHighImmediate(0xB4, q + 71), length=2)
    project.hook(q + 71, Sm83AndRegister("a", q + 72), length=1)
    project.hook(q + 73, Sm83StoreAHighImmediate(0xB3, q + 75), length=2)
    project.hook(q + 75, Sm83StoreAHighImmediate(0xB2, q + 77), length=2)
    project.hook(q + 78, Sm83XorA(q + 79), length=1)
    for offset, address in ((79, UNUSED_INDEX), (82, SIM_INDEX), (85, SIM_END),
                            (88, JOY_IGNORE)):
        project.hook(q + offset, Sm83StoreAImmediate(address, q + offset + 3), length=3)
    project.hook(q + 91, Sm83StoreAHighImmediate(0xB4, q + 93), length=2)
    project.hook(q + 96, LoadAtHl(q + 97), length=1)
    project.hook(q + 97, Sm83AndImmediate(0xF8, q + 99), length=2)
    project.hook(q + 99, StoreAtHl(q + 100), length=1)
    project.hook(q + 103, Sm83ResAtHl(7, q + 105), length=2)
    state = project.factory.blank_state(addr=q)
    set_assembly_registers(state, values); state.regs.sp = claripy.BVV(STACK, 16)
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    setup(state, 0, values, **scenario)
    ends = collect_returns(project, state, RETURN); assert len(ends) == 1
    return [endpoint(ends[0], 0, False)]


def native(values, scenario):
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_joypad_overworld"); assert function
    for name, procedure in (("port_run_map_script", NativeMap()),
                            ("port_joypad_homecall", NativeJoypad())):
        symbol = project.loader.find_symbol(name); assert symbol
        project.hook(symbol.rebased_addr, procedure)
    state = project.factory.call_state(function.rebased_addr, NS, NM, 0, 0, 0, 0, 0)
    store_native_registers(state, NS, values); setup(state, NM, values, **scenario)
    manager = project.factory.simulation_manager(state); manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [endpoint(manager.deadended[0], NM, True)]


CASES = (
    dict(status7=8, cur_map=0x1C, held=0, status5=0, override=0, index=7, fetched=1),
    dict(status7=0, cur_map=1, held=0, status5=0, override=0, index=7, fetched=1),
    dict(status7=0, cur_map=0x1C, held=1, status5=0, override=0, index=7, fetched=1),
    dict(status7=0, cur_map=0x1C, held=0, status5=0, override=0, index=7, fetched=1),
    dict(status7=8, cur_map=1, held=2, status5=0x80, override=2, index=7, fetched=1),
    dict(status7=8, cur_map=1, held=0, status5=0x80, override=0, index=0, fetched=1),
    dict(status7=8, cur_map=1, held=0, status5=0x80, override=0, index=1, fetched=1),
    dict(status7=8, cur_map=1, held=0, status5=0x80, override=0, index=1, fetched=0),
    dict(status7=8, cur_map=1, held=0, status5=0x80, override=0, index=46, fetched=1),
    dict(status7=8, cur_map=1, held=0, status5=0x80, override=0, index=255, fetched=1),
)


@pytest.mark.skipif(not ELF.exists(), reason="run native")
@pytest.mark.parametrize("scenario", CASES)
def test_joypad_overworld_pathwise_equivalence(scenario):
    values = inputs(f"joypad_overworld_{CASES.index(scenario)}")
    assert_pathwise_equivalent(assembly(values, scenario), native(values, scenario),
                               ("registers", "memory", "trace"))


@pytest.mark.skipif(not ELF.exists(), reason="run native")
@pytest.mark.parametrize("index", range(256))
def test_joypad_overworld_all_simulated_indices(index):
    scenario = dict(status7=8, cur_map=1, held=0, status5=0x80,
                    override=0, index=index, fetched=0x5A)
    values = inputs(f"joypad_overworld_index_{index}")
    assert_pathwise_equivalent(assembly(values, scenario), native(values, scenario),
                               ("registers", "memory", "trace"))
