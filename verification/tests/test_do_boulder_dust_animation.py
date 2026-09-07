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
    Sm83BitRegister, Sm83LoadAImmediate, Sm83SetAtHl,
    Sm83StoreAHighImmediate, Sm83StoreAImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
ROM, SYMBOLS = ROOT / "pokered.gbc", ROOT / "pokered.sym"
ELF = ROOT / "verification/build/ports.elf"
NS, NM, STACK, RETURN = 0x100000, 0x110000, 0xD000, 0xFFFF
CHANNELS, NEW_SOUND, AUDIO_BANK, AUDIO_SAVED = 0xC026, 0xC0EE, 0xC0EF, 0xC0F0
MISC, JOY_IGNORE = 0xCD60, 0xCD6B
FADE, FADE_RELOAD, FADE_COUNTER, LAST_MUSIC = 0xCFC7, 0xCFC8, 0xCFC9, 0xCFCA
WHICH, UPDATE, COORD, LOW_HEALTH = 0xCD50, 0xCFCB, 0xD08A, 0xD083
BOULDER, STATUS5 = 0xD718, 0xD730
SPRITE, JOY_RELEASED, JOY_PRESSED, JOY_HELD = 0xFF8C, 0xFFB2, 0xFFB3, 0xFFB4
BANK, SAVED_BANK, OBP1, ROMB = 0xFFB8, 0xFFB9, 0xFF49, 0x2000
OAM_BASE, OAM_SIZE = 0xC38F, 17
MOVE_BASE, MOVE_SIZE = 0xD4E4, 0xFF
BODY = bytes.fromhex(
    "fa30d7cb47c021545f061ecdd635cd3440ea6bcdcddd72cbfefa18d7e08c"
    "cd583536103eacc3b123"
)
FINAL_BYTES = (
    CHANNELS, CHANNELS + 1, CHANNELS + 2, CHANNELS + 3,
    NEW_SOUND, AUDIO_BANK, AUDIO_SAVED, MISC, JOY_IGNORE,
    FADE, FADE_RELOAD, FADE_COUNTER, LAST_MUSIC, WHICH, UPDATE, COORD,
    LOW_HEALTH, BOULDER, STATUS5, SPRITE, JOY_RELEASED, JOY_PRESSED,
    JOY_HELD, BANK, SAVED_BANK, OBP1, ROMB,
)
ANIMATE_BYTES = (WHICH, UPDATE, COORD, OBP1)


@dataclass(frozen=True)
class Endpoint:
    registers: claripy.ast.BV
    memory: claripy.ast.BV
    trace: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def byte_at(value, index, size):
    high = size * 8 - index * 8 - 1
    return value[high:high - 7]


def registers_vector(registers):
    return claripy.Concat(*(registers[name] for name in REGISTERS))


def final_memory(state, base):
    return claripy.Concat(
        *(state.memory.load(base + address, 1) for address in FINAL_BYTES),
        state.memory.load(base + OAM_BASE, OAM_SIZE),
        state.memory.load(base + MOVE_BASE, MOVE_SIZE),
    )


def animate_memory(state, base):
    return claripy.Concat(
        *(state.memory.load(base + address, 1) for address in ANIMATE_BYTES),
        state.memory.load(base + OAM_BASE, OAM_SIZE),
    )


def record(state, tag, payload):
    state.globals["tags"] += (tag,)
    state.globals["trace"] += (claripy.Concat(claripy.BVV(tag, 8), payload),)


def set_assembly_registers_from_vector(state, value):
    for index, name in enumerate(REGISTERS):
        byte = byte_at(value, index, len(REGISTERS))
        setattr(state.regs, name,
                sm83_flags_to_z80(byte) if name == "f" else byte)


def store_native_register_vector(state, pointer, value):
    for index in range(len(REGISTERS)):
        state.memory.store(pointer + index, byte_at(value, index, len(REGISTERS)))


def set_animate_post(state, base, assembly_side):
    post = state.globals["animate_post_registers"]
    if assembly_side:
        set_assembly_registers_from_vector(state, post)
    else:
        store_native_register_vector(state, state.globals["native_registers"], post)
    for index, address in enumerate(ANIMATE_BYTES):
        state.memory.store(base + address,
                           byte_at(state.globals["animate_post_bytes"], index,
                                   len(ANIMATE_BYTES)))
    state.memory.store(base + OAM_BASE, state.globals["animate_post_oam"])


class AssemblyAnimate(angr.SimProcedure):
    def __init__(self, next_address):
        super().__init__(); self.next_address = next_address

    def run(self):
        saved_bank = self.state.memory.load(BANK, 1)
        saved_flags = assembly_registers(self.state)["f"]
        self.state.regs.a = claripy.BVV(0x1E, 8)
        self.state.memory.store(BANK, self.state.regs.a)
        self.state.memory.store(ROMB, self.state.regs.a)
        self.state.regs.b = claripy.BVV(0x35, 8)
        self.state.regs.c = claripy.BVV(0xE4, 8)
        record(self.state, 1, claripy.Concat(
            registers_vector(assembly_registers(self.state)),
            animate_memory(self.state, 0)))
        set_animate_post(self.state, 0, True)
        self.state.regs.b = saved_bank
        self.state.regs.c = saved_flags
        self.state.regs.a = saved_bank
        self.state.memory.store(BANK, saved_bank)
        self.state.memory.store(ROMB, saved_bank)
        self.jump(self.next_address)


class NativeAnimate(angr.SimProcedure):
    def run(self, registers, memory):
        self.state.globals["native_registers"] = registers
        record(self.state, 1, claripy.Concat(
            registers_vector(native_registers(self.state, registers)),
            animate_memory(self.state, memory)))
        set_animate_post(self.state, memory, False)


class AssemblyDiscard(angr.SimProcedure):
    def __init__(self, next_address):
        super().__init__(); self.next_address = next_address

    def run(self):
        record(self.state, 2, claripy.Concat(
            registers_vector(assembly_registers(self.state)),
            self.state.memory.load(JOY_HELD, 1),
            self.state.memory.load(JOY_PRESSED, 1),
            self.state.memory.load(JOY_RELEASED, 1)))
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0x80, 8))
        for address in (JOY_HELD, JOY_PRESSED, JOY_RELEASED):
            self.state.memory.store(address, claripy.BVV(0, 8))
        self.jump(self.next_address)


class NativeDiscard(angr.SimProcedure):
    def run(self, state):
        record(self.state, 2, self.state.memory.load(state, 11))
        self.state.memory.store(state, claripy.BVV(0, 8))
        self.state.memory.store(state + 1, claripy.BVV(0x80, 8))
        for offset in (8, 9, 10):
            self.state.memory.store(state + offset, claripy.BVV(0, 8))


class AssemblyReset(angr.SimProcedure):
    def __init__(self, next_address):
        super().__init__(); self.next_address = next_address

    def run(self):
        record(self.state, 3, claripy.Concat(
            registers_vector(assembly_registers(self.state)),
            self.state.memory.load(MISC, 1)))
        self.state.regs.h = claripy.BVV(0xCD, 8)
        self.state.regs.l = claripy.BVV(0x60, 8)
        self.state.memory.store(MISC, self.state.memory.load(MISC, 1) & 0xBD)
        self.jump(self.next_address)


class NativeReset(angr.SimProcedure):
    def run(self, state):
        record(self.state, 3, self.state.memory.load(state, 9))
        self.state.memory.store(state + 6, claripy.BVV(0xCD, 8))
        self.state.memory.store(state + 7, claripy.BVV(0x60, 8))
        self.state.memory.store(state + 8,
                                self.state.memory.load(state + 8, 1) & 0xBD)


def pointer_transition(registers, sprite):
    decrement = sprite - 1
    offset = (decrement << 1)[7:0]
    address = claripy.BVV(MOVE_BASE, 16) + claripy.ZeroExt(8, offset)
    result = dict(registers)
    result.update(
        a=offset,
        f=claripy.If(offset == 0, claripy.BVV(0x80, 8), claripy.BVV(0, 8)),
        d=claripy.BVV(0, 8), e=offset,
        h=address[15:8], l=address[7:0],
    )
    return result


class AssemblyPointer(angr.SimProcedure):
    def __init__(self, next_address):
        super().__init__(); self.next_address = next_address

    def run(self):
        sprite = self.state.memory.load(SPRITE, 1)
        before = assembly_registers(self.state)
        record(self.state, 4, claripy.Concat(registers_vector(before), sprite))
        after = pointer_transition(before, sprite)
        set_assembly_registers(self.state, after)
        self.jump(self.next_address)


class NativePointer(angr.SimProcedure):
    def run(self, state):
        sprite = self.state.memory.load(state + 8, 1)
        before = native_registers(self.state, state)
        record(self.state, 4, claripy.Concat(registers_vector(before), sprite))
        after = pointer_transition(before, sprite)
        store_native_registers(self.state, state, after)


def sound_input_assembly(state):
    return claripy.Concat(
        registers_vector(assembly_registers(state)),
        state.memory.load(NEW_SOUND, 1), state.memory.load(AUDIO_BANK, 1),
        state.memory.load(FADE, 1), state.memory.load(FADE_RELOAD, 1),
        state.memory.load(FADE_COUNTER, 1), state.memory.load(LAST_MUSIC, 1),
        state.memory.load(CHANNELS, 4), state.memory.load(SAVED_BANK, 1),
        state.memory.load(BANK, 1), state.memory.load(ROMB, 1),
        claripy.BVV(0, 8), state.memory.load(LOW_HEALTH, 1),
        state.memory.load(AUDIO_SAVED, 1),
    )


def apply_sound_post_assembly(state):
    post = state.globals["sound_post"]
    set_assembly_registers_from_vector(state, post[191:128])
    addresses = (
        NEW_SOUND, AUDIO_BANK, FADE, FADE_RELOAD, FADE_COUNTER, LAST_MUSIC,
        CHANNELS, CHANNELS + 1, CHANNELS + 2, CHANNELS + 3,
        SAVED_BANK, BANK, ROMB, None, LOW_HEALTH, AUDIO_SAVED,
    )
    for index, address in enumerate(addresses, 8):
        if address is not None:
            state.memory.store(address, byte_at(post, index, 24))


class AssemblySound(angr.SimProcedure):
    def run(self):
        record(self.state, 5, sound_input_assembly(self.state))
        apply_sound_post_assembly(self.state)
        target = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp += 2
        self.inhibit_autoret = True
        self.jump(target)


class NativeSound(angr.SimProcedure):
    def run(self, state):
        record(self.state, 5, self.state.memory.load(state, 24))
        self.state.memory.store(state, self.state.globals["sound_post"])


class StoreImmediateAtHL(angr.SimProcedure):
    def __init__(self, value, next_address):
        super().__init__(); self.value, self.next_address = value, next_address

    def run(self):
        self.state.memory.store(self.state.regs.hl, claripy.BVV(self.value, 8))
        self.jump(self.next_address)


class LoadAConstant(angr.SimProcedure):
    def __init__(self, value, next_address):
        super().__init__(); self.value, self.next_address = value, next_address

    def run(self):
        self.state.regs.a = claripy.BVV(self.value, 8)
        self.jump(self.next_address)


def setup_globals(state, values):
    state.globals["tags"] = ()
    state.globals["trace"] = ()
    state.globals["animate_post_registers"] = values["animate_post_registers"]
    state.globals["animate_post_bytes"] = values["animate_post_bytes"]
    state.globals["animate_post_oam"] = values["animate_post_oam"]
    state.globals["sound_post"] = values["sound_post"]


def setup_memory(state, base, values, scripted):
    for address in FINAL_BYTES:
        value = (values["status5"] if address == STATUS5
                 else values[f"m{address:x}"])
        state.memory.store(base + address, value)
    state.memory.store(base + OAM_BASE, values["oam"])
    state.memory.store(base + MOVE_BASE, values["movement"])
    condition = values["status5"] & 1
    state.solver.add(condition == (1 if scripted else 0))
    state.solver.add(byte_at(values["animate_post_registers"], 1, 8) & 0x0F == 0)
    state.solver.add(byte_at(values["sound_post"], 1, 24) & 0x0F == 0)


def endpoint(state, base):
    trace = (claripy.Concat(*state.globals["trace"])
             if state.globals["trace"] else claripy.BVV(0, 8))
    registers = (assembly_registers(state) if base == 0
                 else native_registers(state, NS))
    return Endpoint(registers_vector(registers), final_memory(state, base), trace,
                    tuple(state.solver.constraints))


def assembly(values, scripted):
    location = symbol_location(SYMBOLS, "DoBoulderDustAnimation")
    assert linked_bytes(ROM, location, len(BODY)) == BODY
    project = angr.Project(rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100, main_opts={"backend": "blob",
        "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0,
        "entry_point": location.address})
    q = location.address
    project.hook(q, Sm83LoadAImmediate(STATUS5, q + 3), length=3)
    project.hook(q + 3, Sm83BitRegister(0, "a", q + 5), length=2)
    project.hook(q + 11, AssemblyAnimate(q + 14), length=3)
    project.hook(q + 14, AssemblyDiscard(q + 17), length=3)
    project.hook(q + 17, Sm83StoreAImmediate(JOY_IGNORE, q + 20), length=3)
    project.hook(q + 20, AssemblyReset(q + 23), length=3)
    project.hook(q + 23, Sm83SetAtHl(7, q + 25), length=2)
    project.hook(q + 25, Sm83LoadAImmediate(BOULDER, q + 28), length=3)
    project.hook(q + 28, Sm83StoreAHighImmediate(0x8C, q + 30), length=2)
    project.hook(q + 30, AssemblyPointer(q + 33), length=3)
    project.hook(q + 33, StoreImmediateAtHL(0x10, q + 35), length=2)
    project.hook(q + 35, LoadAConstant(0xAC, q + 37), length=2)
    project.hook(q + 37, AssemblySound(), length=3)
    state = project.factory.blank_state(addr=q)
    set_assembly_registers(state, values)
    state.regs.sp = claripy.BVV(STACK, 16)
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    setup_globals(state, values); setup_memory(state, 0, values, scripted)
    ends = collect_returns(project, state, RETURN)
    assert len(ends) == 1
    assert ends[0].globals["tags"] == ((1, 2, 3, 4, 5) if not scripted else ())
    return [endpoint(ends[0], 0)]


def native(values, scripted):
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_do_boulder_dust_animation")
    assert function is not None
    hooks = {
        "port_animate_boulder_dust": NativeAnimate(),
        "port_discard_button_presses": NativeDiscard(),
        "port_reset_boulder_push_flags": NativeReset(),
        "port_get_sprite_movement_byte2_pointer": NativePointer(),
        "port_play_sound": NativeSound(),
    }
    for name, procedure in hooks.items():
        symbol = project.loader.find_symbol(name); assert symbol is not None
        project.hook(symbol.rebased_addr, procedure)
    state = project.factory.call_state(function.rebased_addr, NS, NM)
    store_native_registers(state, NS, values)
    setup_globals(state, values); setup_memory(state, NM, values, scripted)
    manager = project.factory.simulation_manager(state); manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    expected = () if scripted else (1, 2, 3, 4, 5)
    assert manager.deadended[0].globals["tags"] == expected
    return [endpoint(manager.deadended[0], NM)]


@pytest.mark.skipif(not ELF.exists(), reason="run native")
@pytest.mark.parametrize("scripted", (True, False))
def test_do_boulder_dust_animation_pathwise_equivalence(scripted):
    values = symbolic_registers(f"do_boulder_{scripted}")
    for address in FINAL_BYTES:
        if address == STATUS5:
            continue
        values[f"m{address:x}"] = claripy.BVS(
            f"do_boulder_{scripted}_m{address:x}", 8)
    values["status5"] = claripy.BVS(f"do_boulder_{scripted}_status5", 8)
    values["oam"] = claripy.BVS(f"do_boulder_{scripted}_oam", OAM_SIZE * 8)
    values["movement"] = claripy.BVS(
        f"do_boulder_{scripted}_movement", MOVE_SIZE * 8)
    values["animate_post_registers"] = claripy.BVS(
        f"do_boulder_{scripted}_animate_post_registers", 64)
    values["animate_post_bytes"] = claripy.BVS(
        f"do_boulder_{scripted}_animate_post_bytes", len(ANIMATE_BYTES) * 8)
    values["animate_post_oam"] = claripy.BVS(
        f"do_boulder_{scripted}_animate_post_oam", OAM_SIZE * 8)
    values["sound_post"] = claripy.BVS(f"do_boulder_{scripted}_sound_post", 192)
    assembly_ends = assembly(values, scripted)
    native_ends = native(values, scripted)
    assert assembly_ends[0].trace.size() == native_ends[0].trace.size()
    for byte in range(assembly_ends[0].trace.size() // 8):
        solver = claripy.Solver()
        solver.add(assembly_ends[0].constraints, native_ends[0].constraints)
        high = assembly_ends[0].trace.size() - byte * 8 - 1
        assembly_byte = assembly_ends[0].trace[high:high - 7]
        native_byte = native_ends[0].trace[high:high - 7]
        solver.add(assembly_byte != native_byte)
        assert not solver.satisfiable(), (
            f"trace byte {byte} differs: "
            f"{solver.eval(assembly_byte, 1)[0]:02x} != "
            f"{solver.eval(native_byte, 1)[0]:02x}"
        )
    assert_pathwise_equivalent(assembly_ends, native_ends,
                               ("registers", "memory", "trace"))
