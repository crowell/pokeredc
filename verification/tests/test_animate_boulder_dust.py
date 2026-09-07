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
    collect_returns, linked_bytes, rom_window, sm83_flags_to_z80,
    symbol_location,
)
from verification.harness.sm83_shims import (
    Sm83AddHlRegisterPair, Sm83DecRegister,
    Sm83LoadAAtHlIncrement, Sm83LoadAHighImmediate, Sm83LoadAImmediate,
    Sm83StoreAHighImmediate, Sm83StoreAImmediate,
    Sm83XorImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
ROM, SYMBOLS = ROOT / "pokered.gbc", ROOT / "pokered.sym"
ELF = ROOT / "verification/build/ports.elf"
NS, NM, STACK, RETURN = 0x100000, 0x110000, 0xD000, 0xFFFF
FACING, WHICH, UPDATE, COORD, OBP1, BANK, ROMB = 0xC109, 0xCD50, 0xCFCB, 0xD08A, 0xFF49, 0xFFB8, 0x2000
OAM_BASE, OAM_SIZE = 0xC38F, 17
BODY = bytes.fromhex(
    "3e01ea50cdfacbcff53effeacbcf3ee4e049cdc05f0603215570cdd6350e08c5"
    "cd925f017e5fc50e04e9f049ee64e049cdd73dc10d20e8f1eacbcfc39709"
)
TABLE = bytes.fromhex("ff0050530100505301013753ff013753")


@dataclass(frozen=True)
class Endpoint:
    registers: claripy.ast.BV
    memory: claripy.ast.BV
    trace: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def watched(state, base):
    return claripy.Concat(
        *(state.memory.load(base + address, 1) for address in
          (FACING, WHICH, UPDATE, COORD, OBP1, BANK, ROMB)),
        state.memory.load(base + OAM_BASE, OAM_SIZE),
    )


def record(state, tag, registers, base):
    state.globals["tags"] += (tag,)
    state.globals["trace"] += (
        claripy.Concat(claripy.BVV(tag, 8),
                       *(registers[name] for name in REGISTERS), watched(state, base)),
    )


def set_assembly_post(state, index):
    for name in REGISTERS:
        value = state.globals[f"post_{index}_{name}"]
        if name == "f":
            value = sm83_flags_to_z80(value)
        setattr(state.regs, name, value)


def set_native_post(state, pointer, index):
    for offset, name in enumerate(REGISTERS):
        state.memory.store(pointer + offset, state.globals[f"post_{index}_{name}"])


class AssemblyBoundary(angr.SimProcedure):
    def __init__(self, tag, index, tail=False, write_oam=False):
        super().__init__()
        self.tag, self.index, self.tail, self.write_oam = tag, index, tail, write_oam

    def run(self):
        record(self.state, self.tag, assembly_registers(self.state), 0)
        set_assembly_post(self.state, self.index)
        if self.write_oam:
            self.state.memory.store(OAM_BASE, self.state.globals["post_oam"])
        if self.tail:
            target = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
            self.state.regs.sp += 2
            self.inhibit_autoret = True
            self.jump(target)


class NativeBoundary(angr.SimProcedure):
    def __init__(self, tag, index, write_oam=False):
        super().__init__()
        self.tag, self.index, self.write_oam = tag, index, write_oam

    def run(self, registers, memory, *unused):
        record(self.state, self.tag, native_registers(self.state, registers), memory)
        set_native_post(self.state, registers, self.index)
        if self.write_oam:
            self.state.memory.store(memory + OAM_BASE, self.state.globals["post_oam"])


class AssemblyFarWrite(angr.SimProcedure):
    def __init__(self, next_address):
        super().__init__(); self.next_address = next_address

    def run(self):
        saved_bank = self.state.memory.load(BANK, 1)
        saved_flags = assembly_registers(self.state)["f"]
        self.state.regs.a = claripy.BVV(3, 8)
        self.state.memory.store(BANK, claripy.BVV(3, 8))
        self.state.memory.store(ROMB, claripy.BVV(3, 8))
        self.state.regs.b = claripy.BVV(0x35, 8)
        self.state.regs.c = claripy.BVV(0xE4, 8)
        record(self.state, 2, assembly_registers(self.state), 0)
        set_assembly_post(self.state, 1)
        self.state.memory.store(OAM_BASE, self.state.globals["post_oam"])
        self.state.regs.b = saved_bank
        self.state.regs.c = saved_flags
        self.state.regs.a = saved_bank
        self.state.memory.store(BANK, saved_bank)
        self.state.memory.store(ROMB, saved_bank)
        self.jump(self.next_address)


def record_adjust(state, registers, adjustment, oam):
    state.globals["tags"] += (5,)
    state.globals["trace"] += (
        claripy.Concat(claripy.BVV(5, 8),
                       *(registers[name] for name in REGISTERS), adjustment, oam),
    )


class AssemblyAdjust(angr.SimProcedure):
    def run(self):
        registers = assembly_registers(self.state)
        de = self.state.solver.eval(claripy.Concat(registers["d"], registers["e"]))
        base = (de - 1) & 0xFFFF
        record_adjust(self.state, registers, self.state.memory.load(COORD, 1),
                      self.state.memory.load(base, 16))
        for name in REGISTERS:
            value = self.state.globals[f"adjust_post_{name}"]
            if name == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, name, value)
        self.state.memory.store(base, self.state.globals["adjust_post_oam"])
        target = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp += 2
        self.inhibit_autoret = True
        self.jump(target)


class NativeAdjust(angr.SimProcedure):
    def run(self, pointer):
        registers = native_registers(self.state, pointer)
        record_adjust(self.state, registers, self.state.memory.load(pointer + 8, 1),
                      self.state.memory.load(pointer + 9, 16))
        for offset, name in enumerate(REGISTERS):
            self.state.memory.store(pointer + offset,
                                    self.state.globals[f"adjust_post_{name}"])
        self.state.memory.store(pointer + 9, self.state.globals["adjust_post_oam"])


class SetHL(angr.SimProcedure):
    def __init__(self, value, next_address):
        super().__init__(); self.value, self.next_address = value, next_address
    def run(self):
        self.state.regs.hl = claripy.BVV(self.value, 16); self.jump(self.next_address)


class LoadHAtHL(angr.SimProcedure):
    def __init__(self, next_address):
        super().__init__(); self.next_address = next_address
    def run(self):
        self.state.regs.h = self.state.memory.load(self.state.regs.hl, 1); self.jump(self.next_address)


class PushPair(angr.SimProcedure):
    def __init__(self, hi, lo, next_address):
        super().__init__(); self.hi, self.lo, self.next_address = hi, lo, next_address
    def run(self):
        self.state.regs.sp -= 2
        self.state.memory.store(self.state.regs.sp, getattr(self.state.regs, self.lo))
        self.state.memory.store(self.state.regs.sp + 1, getattr(self.state.regs, self.hi))
        self.jump(self.next_address)


class PopPair(angr.SimProcedure):
    def __init__(self, hi, lo, next_address):
        super().__init__(); self.hi, self.lo, self.next_address = hi, lo, next_address
    def run(self):
        setattr(self.state.regs, self.lo, self.state.memory.load(self.state.regs.sp, 1))
        setattr(self.state.regs, self.hi, self.state.memory.load(self.state.regs.sp + 1, 1))
        self.state.regs.sp += 2; self.jump(self.next_address)


def setup_globals(state, values):
    state.globals["trace"] = ()
    state.globals["tags"] = ()
    state.globals["post_oam"] = values["post_oam"]
    state.globals["adjust_post_oam"] = values["adjust_post_oam"]
    for name in REGISTERS:
        state.globals[f"adjust_post_{name}"] = values[f"adjust_post_{name}"]
    for index in range(11):
        for name in REGISTERS:
            state.globals[f"post_{index}_{name}"] = values[f"post_{index}_{name}"]


def setup_memory(state, base, values, facing):
    for address in (WHICH, UPDATE, COORD, OBP1, BANK, ROMB):
        state.memory.store(base + address, values[f"m{address:x}"])
    state.memory.store(base + FACING, claripy.BVV(facing, 8))
    state.memory.store(base + OAM_BASE, values["oam"])


def hook_pointer(project):
    q = symbol_location(SYMBOLS, "GetMoveBoulderDustFunctionPointer").address
    table = symbol_location(SYMBOLS, "MoveBoulderDustFunctionPointerTable").address
    project.hook(q, Sm83LoadAImmediate(FACING, q + 3), length=3)
    project.hook(q + 3, SetHL(table, q + 6), length=3)
    project.hook(q + 9, Sm83AddHlRegisterPair("bc", q + 10), length=1)
    project.hook(q + 10, Sm83LoadAAtHlIncrement(q + 11), length=1)
    project.hook(q + 11, Sm83StoreAImmediate(COORD, q + 14), length=3)
    project.hook(q + 14, Sm83LoadAAtHlIncrement(q + 15), length=1)
    project.hook(q + 16, Sm83LoadAAtHlIncrement(q + 17), length=1)
    project.hook(q + 17, LoadHAtHL(q + 18), length=1)
    project.hook(q + 19, PushPair("h", "l", q + 20), length=1)
    project.hook(q + 20, SetHL(0xC390, q + 23), length=3)
    project.hook(q + 25, Sm83AddHlRegisterPair("de", q + 26), length=1)
    project.hook(q + 28, PopPair("h", "l", q + 29), length=1)


def assembly(values, facing):
    location = symbol_location(SYMBOLS, "AnimateBoulderDust")
    assert linked_bytes(ROM, location, len(BODY)) == BODY
    assert linked_bytes(ROM, symbol_location(SYMBOLS, "MoveBoulderDustFunctionPointerTable"), 16) == TABLE
    project = angr.Project(rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100, main_opts={"backend": "blob",
        "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0,
        "entry_point": location.address})
    q = location.address
    project.hook(q + 2, Sm83StoreAImmediate(WHICH, q + 5), length=3)
    project.hook(q + 5, Sm83LoadAImmediate(UPDATE, q + 8), length=3)
    project.hook(q + 8, PushPair("a", "f", q + 9), length=1)
    project.hook(q + 11, Sm83StoreAImmediate(UPDATE, q + 14), length=3)
    project.hook(q + 16, Sm83StoreAHighImmediate(0x49, q + 18), length=2)
    project.hook(q + 23, SetHL(0x7055, q + 26), length=3)
    project.hook(symbol_location(SYMBOLS, "LoadSmokeTileFourTimes").address,
                 AssemblyBoundary(1, 0, tail=True))
    project.hook(q + 26, AssemblyFarWrite(q + 29), length=3)
    project.hook(q + 31, PushPair("b", "c", q + 32), length=1)
    project.hook(q + 38, PushPair("b", "c", q + 39), length=1)
    project.hook(q + 42, Sm83LoadAHighImmediate(0x49, q + 44), length=2)
    project.hook(q + 44, Sm83XorImmediate(0x64, q + 46), length=2)
    project.hook(q + 46, Sm83StoreAHighImmediate(0x49, q + 48), length=2)
    project.hook(symbol_location(SYMBOLS, "Delay3").address,
                 AssemblyBoundary(3, 2, tail=True))
    project.hook(q + 51, PopPair("b", "c", q + 52), length=1)
    project.hook(q + 52, Sm83DecRegister("c", q + 53), length=1)
    project.hook(q + 55, PopPair("a", "f", q + 56), length=1)
    project.hook(q + 56, Sm83StoreAImmediate(UPDATE, q + 59), length=3)
    project.hook(symbol_location(SYMBOLS, "LoadPlayerSpriteGraphics").address,
                 AssemblyBoundary(4, 10, tail=True))
    hook_pointer(project)
    project.hook(symbol_location(SYMBOLS, "AdjustOAMBlockYPos").address,
                 AssemblyAdjust())
    project.hook(symbol_location(SYMBOLS, "AdjustOAMBlockXPos").address,
                 AssemblyAdjust())
    state = project.factory.blank_state(addr=q)
    set_assembly_registers(state, values); setup_memory(state, 0, values, facing)
    state.regs.sp = claripy.BVV(STACK, 16)
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    setup_globals(state, values)
    ends = collect_returns(project, state, RETURN)
    assert len(ends) == 1
    end = ends[0]
    assert end.globals["tags"] == (1, 2, 5, 3, 5, 3, 5, 3, 5, 3,
                                    5, 3, 5, 3, 5, 3, 5, 3, 4)
    return [Endpoint(claripy.Concat(*(assembly_registers(end)[n] for n in REGISTERS)),
                     watched(end, 0), claripy.Concat(*end.globals["trace"]),
                     tuple(end.solver.constraints))]


def native(values, facing):
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_animate_boulder_dust")
    names = ("port_load_smoke_tile_four_times",
             "port_write_cut_or_boulder_dust_animation_oam_block",
             "port_delay3", "port_load_player_sprite_graphics")
    assert function is not None
    for name, proc in zip(names, (NativeBoundary(1, 0), NativeBoundary(2, 1, True),
                                  NativeBoundary(3, 2), NativeBoundary(4, 10))):
        symbol = project.loader.find_symbol(name); assert symbol is not None
        project.hook(symbol.rebased_addr, proc)
    for name in ("port_adjust_oam_block_y_pos", "port_adjust_oam_block_x_pos"):
        symbol = project.loader.find_symbol(name); assert symbol is not None
        project.hook(symbol.rebased_addr, NativeAdjust())
    state = project.factory.call_state(function.rebased_addr, NS, NM)
    store_native_registers(state, NS, values); setup_memory(state, NM, values, facing)
    setup_globals(state, values)
    manager = project.factory.simulation_manager(state); manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    end = manager.deadended[0]
    assert end.globals["tags"] == (1, 2, 5, 3, 5, 3, 5, 3, 5, 3,
                                    5, 3, 5, 3, 5, 3, 5, 3, 4)
    return [Endpoint(claripy.Concat(*(native_registers(end, NS)[n] for n in REGISTERS)),
                     watched(end, NM), claripy.Concat(*end.globals["trace"]),
                     tuple(end.solver.constraints))]


@pytest.mark.skipif(not ELF.exists(), reason="run native")
@pytest.mark.parametrize("facing", (0, 4, 8, 12))
def test_animate_boulder_dust_pathwise_equivalence(facing):
    values = symbolic_registers(f"animate_boulder_{facing}")
    for address in (WHICH, UPDATE, COORD, OBP1, BANK, ROMB):
        values[f"m{address:x}"] = claripy.BVS(f"animate_boulder_{facing}_m{address:x}", 8)
    values["oam"] = claripy.BVS(f"animate_boulder_{facing}_oam", OAM_SIZE * 8)
    values["post_oam"] = claripy.BVS(f"animate_boulder_{facing}_post_oam", OAM_SIZE * 8)
    values["adjust_post_oam"] = claripy.BVS(
        f"animate_boulder_{facing}_adjust_post_oam", 128)
    for name in REGISTERS:
        values[f"adjust_post_{name}"] = (
            claripy.Concat(claripy.BVS("animate_boulder_adjust_post_flags", 4), claripy.BVV(0, 4))
            if name == "f" else claripy.BVS(f"animate_boulder_adjust_post_{name}", 8)
        )
    for index in range(11):
        for name in REGISTERS:
            values[f"post_{index}_{name}"] = (
                claripy.Concat(claripy.BVS(f"animate_boulder_post_{index}_flags", 4), claripy.BVV(0, 4))
                if name == "f" else claripy.BVS(f"animate_boulder_post_{index}_{name}", 8)
            )
    assembly_ends = assembly(values, facing)
    native_ends = native(values, facing)
    assert assembly_ends[0].trace.size() == native_ends[0].trace.size()
    for byte in range(assembly_ends[0].trace.size() // 8):
        solver = claripy.Solver()
        solver.add(assembly_ends[0].constraints, native_ends[0].constraints)
        high = assembly_ends[0].trace.size() - byte * 8 - 1
        solver.add(assembly_ends[0].trace[high:high - 7] !=
                   native_ends[0].trace[high:high - 7])
        assert not solver.satisfiable(), f"trace byte {byte} differs"
    assert_pathwise_equivalent(assembly_ends, native_ends,
                               ("registers", "memory", "trace"))
