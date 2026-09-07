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
    Sm83AddHlRegisterPair, Sm83BitAtHl, Sm83BitRegister, Sm83CpImmediate,
    Sm83LoadAHighImmediate, Sm83LoadAImmediate, Sm83ResAtHl, Sm83SetAtHl,
    Sm83StoreAHighImmediate, Sm83StoreAImmediate, Sm83XorA,
)

ROOT = Path(__file__).resolve().parents[2]
ROM, SYMBOLS = ROOT / "pokered.gbc", ROOT / "pokered.sym"
ELF = ROOT / "verification/build/ports.elf"
NS, NM, STACK, RETURN = 0x100000, 0x200000, 0xD000, 0xEFFF
CHANNELS, NEW_SOUND, AUDIO_BANK, AUDIO_SAVED = 0xC026, 0xC0EE, 0xC0EF, 0xC0F0
MOVEMENT_STATUS_BASE, MOVEMENT_STATUS_SIZE, FACING = 0xC101, 0xF1, 0xC109
MISC, PLAYER_DIRECTION = 0xCD60, 0xD52A
FADE, FADE_RELOAD, FADE_COUNTER, LAST_MUSIC = 0xCFC7, 0xCFC8, 0xCFC9, 0xCFCA
LOW_HEALTH, BOULDER, TILE_RESULT, STATUS1 = 0xD083, 0xD718, 0xD71C, 0xD728
NUM_SPRITES, MOVEMENT_BYTE_BASE, MOVEMENT_BYTE_SIZE = 0xD4E1, 0xD4E4, 0x1D
SPRITE, JOY_HELD, BANK, SAVED_BANK, ROMB = 0xFF8C, 0xFFB4, 0xFFB8, 0xFFB9, 0x2000
TABLE_UP, TABLE_DOWN, TABLE_LEFT, TABLE_RIGHT = 0x72AD, 0x72AF, 0x72B1, 0x72B3
BODY = bytes.fromhex(
    "fa28d7cb47c8fa60cdcb4fc0afe08ccd6b0bf08cea18d7a7cadd722101c11600"
    "f08ccb375f19cbbecd58357efe10c2dd722160cdcb76cbf6c8f0b4e6f0c83e5a"
    "cd6d3efa1cd7a7c2dd72f0b447fa09c1fe042810fe082814fe0c2818cb78c811"
    "af721816cb70c811ad72180ecb68c811b1721806cb60c811b372cd3a363ea8cd"
    "b1232160cdcbcec940ff00ff80ffc0ff"
)
SCALARS = (
    CHANNELS, CHANNELS + 1, CHANNELS + 2, CHANNELS + 3,
    NEW_SOUND, AUDIO_BANK, AUDIO_SAVED, FACING, MISC,
    PLAYER_DIRECTION, FADE, FADE_RELOAD, FADE_COUNTER, LAST_MUSIC,
    LOW_HEALTH, BOULDER, TILE_RESULT, STATUS1, NUM_SPRITES,
    SPRITE, JOY_HELD, BANK, SAVED_BANK, ROMB,
)


@dataclass(frozen=True)
class Endpoint:
    registers: claripy.ast.BV
    memory: claripy.ast.BV
    trace: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def rv(registers):
    return claripy.Concat(*(registers[name] for name in REGISTERS))


def byte_at(value, index, size):
    high = size * 8 - index * 8 - 1
    return value[high:high - 7]


def record(state, tag, payload):
    state.globals["tags"] += (tag,)
    state.globals["trace"] += (claripy.Concat(claripy.BVV(tag, 8), payload),)


def return_from_stack(procedure):
    target = procedure.state.memory.load(
        procedure.state.regs.sp, 2, endness="Iend_LE")
    procedure.state.regs.sp += 2
    procedure.inhibit_autoret = True
    procedure.jump(target)


def set_asm_regs(state, value):
    for index, name in enumerate(REGISTERS):
        byte = byte_at(value, index, 8)
        setattr(state.regs, name,
                sm83_flags_to_z80(byte) if name == "f" else byte)


def set_native_regs(state, pointer, value):
    for index in range(8):
        state.memory.store(pointer + index, byte_at(value, index, 8))


class AssemblyFrontEntry(angr.SimProcedure):
    def __init__(self, next_address):
        super().__init__(); self.next_address = next_address

    def run(self):
        record(self.state, 1, rv(assembly_registers(self.state)))
        self.state.regs.d = claripy.BVV(0x10, 8)
        self.jump(self.next_address)


class NativeFrontEntry(angr.SimProcedure):
    def run(self, registers):
        record(self.state, 1, rv(native_registers(self.state, registers)))
        self.state.memory.store(registers + 4, claripy.BVV(0x10, 8))


def front_result(facing):
    if facing == 0:
        return 0x4C, 0x40, 4
    if facing == 4:
        return 0x2C, 0x40, 8
    if facing == 12:
        return 0x3C, 0x50, 1
    return 0x3C, 0x30, 2


class AssemblyFront(angr.SimProcedure):
    def __init__(self, facing, sprite):
        super().__init__(); self.facing, self.sprite = facing, sprite

    def run(self):
        record(self.state, 2, claripy.Concat(
            rv(assembly_registers(self.state)), claripy.BVV(self.facing, 8),
            claripy.BVV(0, 8), claripy.BVV(self.sprite, 8), claripy.BVV(0, 48)))
        y, x, direction = front_result(self.facing)
        self.state.regs.a = claripy.BVV(self.sprite, 8)
        self.state.regs.f = claripy.BVV(0, 8)
        self.state.regs.b = claripy.BVV(y, 8)
        self.state.regs.c = claripy.BVV(x, 8)
        self.state.regs.d = claripy.BVV(1, 8)
        self.state.regs.e = claripy.BVV(self.sprite, 8)
        self.state.regs.h = claripy.BVV(0xC1, 8)
        status = MOVEMENT_STATUS_BASE + self.sprite * 0x10
        self.state.regs.l = claripy.BVV(status & 0xFF, 8)
        self.state.memory.store(status,
                                self.state.memory.load(status, 1) | 0x80)
        self.state.memory.store(PLAYER_DIRECTION, claripy.BVV(direction, 8))
        self.state.memory.store(SPRITE, claripy.BVV(self.sprite, 8))
        return_from_stack(self)


class NativeFront(angr.SimProcedure):
    def __init__(self, facing, sprite):
        super().__init__(); self.facing, self.sprite = facing, sprite

    def run(self, state, memory):
        record(self.state, 2, self.state.memory.load(state, 17))
        y, x, direction = front_result(self.facing)
        status = MOVEMENT_STATUS_BASE + self.sprite * 0x10
        values = (self.sprite, 0, y, x, 1, self.sprite, 0xC1, status & 0xFF)
        for offset, value in enumerate(values):
            self.state.memory.store(state + offset, claripy.BVV(value, 8))
        self.state.memory.store(state + 9, claripy.BVV(direction, 8))
        self.state.memory.store(state + 16, claripy.BVV(self.sprite, 8))
        self.state.memory.store(memory + status,
                                self.state.memory.load(memory + status, 1) | 0x80)


def pointer_result(registers, sprite):
    offset = 2 * (sprite - 1)
    address = MOVEMENT_BYTE_BASE + offset
    result = dict(registers)
    result.update(a=claripy.BVV(offset, 8),
                  f=claripy.BVV(0x80 if offset == 0 else 0, 8),
                  d=claripy.BVV(0, 8), e=claripy.BVV(offset, 8),
                  h=claripy.BVV(address >> 8, 8), l=claripy.BVV(address & 0xFF, 8))
    return result


class AssemblyPointer(angr.SimProcedure):
    def __init__(self, sprite):
        super().__init__(); self.sprite = sprite

    def run(self):
        before = assembly_registers(self.state)
        record(self.state, 3, claripy.Concat(rv(before), self.state.memory.load(SPRITE, 1)))
        set_assembly_registers(self.state, pointer_result(before, self.sprite))
        return_from_stack(self)


class NativePointer(angr.SimProcedure):
    def __init__(self, sprite):
        super().__init__(); self.sprite = sprite

    def run(self, state):
        before = native_registers(self.state, state)
        record(self.state, 3, claripy.Concat(rv(before), self.state.memory.load(state + 8, 1)))
        store_native_registers(self.state, state, pointer_result(before, self.sprite))


class AssemblyCollision(angr.SimProcedure):
    def __init__(self, next_address, result):
        super().__init__(); self.next_address, self.result = next_address, result

    def run(self):
        record(self.state, 4, rv(assembly_registers(self.state)))
        set_asm_regs(self.state, self.state.globals["collision_post"])
        self.state.memory.store(TILE_RESULT, claripy.BVV(self.result, 8))
        self.inhibit_autoret = True
        self.jump(self.next_address)


class NativeCollision(angr.SimProcedure):
    def __init__(self, result):
        super().__init__(); self.result = result

    def run(self, registers, memory):
        record(self.state, 4, rv(native_registers(self.state, registers)))
        set_native_regs(self.state, registers, self.state.globals["collision_post"])
        self.state.memory.store(memory + TILE_RESULT, claripy.BVV(self.result, 8))


class AssemblyMove(angr.SimProcedure):
    def run(self):
        record(self.state, 5, claripy.Concat(
            rv(assembly_registers(self.state)),
            self.state.memory.load(self.state.regs.de, 2)))
        set_asm_regs(self.state, self.state.globals["move_post"])
        return_from_stack(self)


class NativeMove(angr.SimProcedure):
    def run(self, registers, memory):
        current = native_registers(self.state, registers)
        de = claripy.Concat(current["d"], current["e"])
        record(self.state, 5, claripy.Concat(
            rv(current), self.state.memory.load(memory + de, 2)))
        set_native_regs(self.state, registers, self.state.globals["move_post"])


def sound_input_asm(state):
    return claripy.Concat(
        rv(assembly_registers(state)), state.memory.load(NEW_SOUND, 1),
        state.memory.load(AUDIO_BANK, 1), state.memory.load(FADE, 1),
        state.memory.load(FADE_RELOAD, 1), state.memory.load(FADE_COUNTER, 1),
        state.memory.load(LAST_MUSIC, 1), state.memory.load(CHANNELS, 4),
        state.memory.load(SAVED_BANK, 1), state.memory.load(BANK, 1),
        state.memory.load(ROMB, 1), claripy.BVV(0, 8),
        state.memory.load(LOW_HEALTH, 1), state.memory.load(AUDIO_SAVED, 1))


class AssemblySound(angr.SimProcedure):
    def run(self):
        record(self.state, 6, sound_input_asm(self.state))
        post = self.state.globals["sound_post"]
        set_asm_regs(self.state, post[191:128])
        addresses = (NEW_SOUND, AUDIO_BANK, FADE, FADE_RELOAD, FADE_COUNTER,
                     LAST_MUSIC, CHANNELS, CHANNELS + 1, CHANNELS + 2,
                     CHANNELS + 3, SAVED_BANK, BANK, ROMB, None,
                     LOW_HEALTH, AUDIO_SAVED)
        for index, address in enumerate(addresses, 8):
            if address is not None:
                self.state.memory.store(address, byte_at(post, index, 24))
        return_from_stack(self)


class NativeSound(angr.SimProcedure):
    def run(self, state):
        record(self.state, 6, self.state.memory.load(state, 24))
        self.state.memory.store(state, self.state.globals["sound_post"])


class AssemblyReset(angr.SimProcedure):
    def run(self):
        record(self.state, 7, claripy.Concat(
            rv(assembly_registers(self.state)), self.state.memory.load(MISC, 1)))
        self.state.regs.h = claripy.BVV(0xCD, 8)
        self.state.regs.l = claripy.BVV(0x60, 8)
        self.state.memory.store(MISC, self.state.memory.load(MISC, 1) & 0xBD)
        return_from_stack(self)


class NativeReset(angr.SimProcedure):
    def run(self, state):
        record(self.state, 7, self.state.memory.load(state, 9))
        self.state.memory.store(state + 6, claripy.BVV(0xCD, 8))
        self.state.memory.store(state + 7, claripy.BVV(0x60, 8))
        self.state.memory.store(state + 8, self.state.memory.load(state + 8, 1) & 0xBD)


class SwapA(angr.SimProcedure):
    def __init__(self, next_address):
        super().__init__(); self.next_address = next_address

    def run(self):
        a = self.state.regs.a
        self.state.regs.a = claripy.Concat(a[3:0], a[7:4])
        self.state.regs.f = claripy.If(self.state.regs.a == 0,
                                      claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        self.jump(self.next_address)


class AndA(angr.SimProcedure):
    def __init__(self, mask, next_address):
        super().__init__(); self.mask, self.next_address = mask, next_address

    def run(self):
        self.state.regs.a &= self.mask
        self.state.regs.f = claripy.If(self.state.regs.a == 0,
                                      claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        self.jump(self.next_address)


class LoadAConstant(angr.SimProcedure):
    def __init__(self, value, next_address):
        super().__init__(); self.value, self.next_address = value, next_address

    def run(self):
        self.state.regs.a = claripy.BVV(self.value, 8)
        self.jump(self.next_address)


def setup(state, base, values, scenario, facing, held, movement, collision, sprite):
    misc = 0 if scenario in ("reject", "first") else 0x40
    initial = {
        STATUS1: 1, MISC: misc, SPRITE: 0, JOY_HELD: held,
        BOULDER: 0, TILE_RESULT: 0, FACING: facing, NUM_SPRITES: sprite,
        PLAYER_DIRECTION: 0,
        NEW_SOUND: values["new_sound"], AUDIO_BANK: values["audio_bank"],
        AUDIO_SAVED: values["audio_saved"], FADE: values["fade"],
        FADE_RELOAD: values["fade_reload"], FADE_COUNTER: values["fade_counter"],
        LAST_MUSIC: values["last_music"], LOW_HEALTH: values["low_health"],
        BANK: values["bank"], SAVED_BANK: values["saved_bank"], ROMB: values["romb"],
    }
    state.memory.store(base + MOVEMENT_STATUS_BASE,
                       claripy.BVV(0, MOVEMENT_STATUS_SIZE * 8))
    state.memory.store(base + MOVEMENT_BYTE_BASE,
                       claripy.BVV(0, MOVEMENT_BYTE_SIZE * 8))
    for address, value in initial.items():
        state.memory.store(base + address,
                           value if isinstance(value, claripy.ast.BV) else claripy.BVV(value, 8))
    for index in range(4):
        state.memory.store(base + CHANNELS + index, values[f"channel{index}"])
    state.memory.store(base + MOVEMENT_STATUS_BASE + sprite * 0x10,
                       claripy.BVV(0x23, 8))
    state.memory.store(base + MOVEMENT_BYTE_BASE + 2 * (sprite - 1),
                       claripy.BVV(movement, 8))
    for address, pair in ((TABLE_UP, (0x40, 0xFF)), (TABLE_DOWN, (0x00, 0xFF)),
                          (TABLE_LEFT, (0x80, 0xFF)), (TABLE_RIGHT, (0xC0, 0xFF))):
        state.memory.store(base + address, bytes(pair))
    state.globals["tags"] = (); state.globals["trace"] = ()
    state.globals["collision_post"] = values["collision_post"]
    state.globals["move_post"] = values["move_post"]
    state.globals["sound_post"] = values["sound_post"]
    state.globals["collision"] = collision
    state.solver.add(byte_at(values["collision_post"], 1, 8) & 0x0F == 0)
    state.solver.add(byte_at(values["move_post"], 1, 8) & 0x0F == 0)
    state.solver.add(byte_at(values["sound_post"], 1, 24) & 0x0F == 0)


def memory_vector(state, base):
    return claripy.Concat(
        *(state.memory.load(base + address, 1) for address in SCALARS),
        state.memory.load(base + MOVEMENT_STATUS_BASE, MOVEMENT_STATUS_SIZE),
        state.memory.load(base + MOVEMENT_BYTE_BASE, MOVEMENT_BYTE_SIZE),
        state.memory.load(base + TABLE_UP, 8))


def endpoint(state, base, native):
    trace = claripy.Concat(*state.globals["trace"])
    registers = native_registers(state, NS) if native else assembly_registers(state)
    return Endpoint(rv(registers), memory_vector(state, base), trace,
                    tuple(state.solver.constraints))


def assembly(values, scenario, facing, held, movement, collision, sprite=1):
    location = symbol_location(SYMBOLS, "TryPushingBoulder")
    assert linked_bytes(ROM, location, len(BODY)) == BODY
    project = angr.Project(rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100, main_opts={"backend": "blob",
        "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0,
        "entry_point": location.address})
    q = location.address
    project.hook(q, Sm83LoadAImmediate(STATUS1, q + 3), length=3)
    project.hook(q + 3, Sm83BitRegister(0, "a", q + 5), length=2)
    project.hook(q + 6, Sm83LoadAImmediate(MISC, q + 9), length=3)
    project.hook(q + 9, Sm83BitRegister(1, "a", q + 11), length=2)
    project.hook(q + 12, Sm83XorA(q + 13), length=1)
    project.hook(q + 13, Sm83StoreAHighImmediate(0x8C, q + 15), length=2)
    front = symbol_location(SYMBOLS, "IsSpriteInFrontOfPlayer").address
    project.hook(front, AssemblyFrontEntry(front + 2), length=2)
    project.hook(front + 2, AssemblyFront(facing, sprite))
    project.hook(q + 18, Sm83LoadAHighImmediate(0x8C, q + 20), length=2)
    project.hook(q + 20, Sm83StoreAImmediate(BOULDER, q + 23), length=3)
    project.hook(q + 23, AndA(0xFF, q + 24), length=1)
    reset = symbol_location(SYMBOLS, "ResetBoulderPushFlags").address
    project.hook(reset, AssemblyReset())
    project.hook(q + 32, Sm83LoadAHighImmediate(0x8C, q + 34), length=2)
    project.hook(q + 34, SwapA(q + 36), length=2)
    project.hook(q + 37, Sm83AddHlRegisterPair("de", q + 38), length=1)
    project.hook(q + 38, Sm83ResAtHl(7, q + 40), length=2)
    pointer = symbol_location(SYMBOLS, "GetSpriteMovementByte2Pointer").address
    project.hook(pointer, AssemblyPointer(sprite))
    project.hook(q + 44, Sm83CpImmediate(0x10, q + 46), length=2)
    project.hook(q + 52, Sm83BitAtHl(6, q + 54), length=2)
    project.hook(q + 54, Sm83SetAtHl(6, q + 56), length=2)
    project.hook(q + 57, Sm83LoadAHighImmediate(0xB4, q + 59), length=2)
    project.hook(q + 59, AndA(0xF0, q + 61), length=2)
    project.hook(q + 62, AssemblyCollision(q + 67, collision), length=5)
    project.hook(q + 67, Sm83LoadAImmediate(TILE_RESULT, q + 70), length=3)
    project.hook(q + 70, AndA(0xFF, q + 71), length=1)
    project.hook(q + 74, Sm83LoadAHighImmediate(0xB4, q + 76), length=2)
    project.hook(q + 77, Sm83LoadAImmediate(FACING, q + 80), length=3)
    for offset, value in ((80, 4), (84, 8), (88, 12)):
        project.hook(q + offset, Sm83CpImmediate(value, q + offset + 2), length=2)
    for offset, bit in ((92, 3), (100, 2), (108, 1), (116, 0)):
        project.hook(q + offset, Sm83BitRegister(bit, "b", q + offset + 2), length=2)
    move = symbol_location(SYMBOLS, "MoveSprite").address
    project.hook(move, AssemblyMove())
    project.hook(q + 125, LoadAConstant(0xA8, q + 127), length=2)
    sound = symbol_location(SYMBOLS, "PlaySound").address
    project.hook(sound, AssemblySound())
    project.hook(q + 133, Sm83SetAtHl(1, q + 135), length=2)
    state = project.factory.blank_state(addr=q)
    set_assembly_registers(state, values)
    state.regs.sp = claripy.BVV(STACK, 16)
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    setup(state, 0, values, scenario, facing, held, movement, collision, sprite)
    ends = collect_returns(project, state, RETURN)
    assert len(ends) == 1
    return [endpoint(ends[0], 0, False)]


def native(values, scenario, facing, held, movement, collision, sprite=1):
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_try_pushing_boulder"); assert function
    hooks = {
        "port_is_sprite_in_front_of_player": NativeFrontEntry(),
        "port_is_sprite_in_front_of_player2": NativeFront(facing, sprite),
        "port_get_sprite_movement_byte2_pointer": NativePointer(sprite),
        "port_check_for_collision_when_pushing_boulder": NativeCollision(collision),
        "port_move_sprite": NativeMove(), "port_play_sound": NativeSound(),
        "port_reset_boulder_push_flags": NativeReset(),
    }
    for name, procedure in hooks.items():
        symbol = project.loader.find_symbol(name); assert symbol
        project.hook(symbol.rebased_addr, procedure)
    state = project.factory.call_state(function.rebased_addr, NS, NM)
    store_native_registers(state, NS, values)
    setup(state, NM, values, scenario, facing, held, movement, collision, sprite)
    manager = project.factory.simulation_manager(state); manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [endpoint(manager.deadended[0], NM, True)]


CASES = (
    ("reject", 0, 0, 0x11, 0), ("first", 0, 0, 0x10, 0),
    ("noheld", 0, 0, 0x10, 0), ("collision", 0, 0x08, 0x10, 0xFF),
    ("mismatch_down", 0, 0x04, 0x10, 0),
    ("mismatch_up", 4, 0x08, 0x10, 0),
    ("mismatch_left", 8, 0x08, 0x10, 0),
    ("mismatch_right", 12, 0x08, 0x10, 0),
    ("push_down", 0, 0x08, 0x10, 0),
    ("push_up", 4, 0x04, 0x10, 0),
    ("push_left", 8, 0x02, 0x10, 0),
    ("push_right", 12, 0x01, 0x10, 0),
)


def inputs(prefix):
    values = symbolic_registers(prefix)
    for name in ("new_sound", "audio_bank", "audio_saved", "fade",
                 "fade_reload", "fade_counter", "last_music", "low_health",
                 "bank", "saved_bank", "romb"):
        values[name] = claripy.BVS(f"{prefix}_{name}", 8)
    for index in range(4):
        values[f"channel{index}"] = claripy.BVS(f"{prefix}_channel{index}", 8)
    values["collision_post"] = claripy.BVS(f"{prefix}_collision_post", 64)
    values["move_post"] = claripy.BVS(f"{prefix}_move_post", 64)
    values["sound_post"] = claripy.BVS(f"{prefix}_sound_post", 192)
    return values


@pytest.mark.skipif(not ELF.exists(), reason="run native")
@pytest.mark.parametrize("scenario,facing,held,movement,collision", CASES)
def test_try_pushing_boulder_complete_paths(
    scenario, facing, held, movement, collision,
):
    values = inputs(f"try_push_{scenario}")
    assembly_ends = assembly(values, scenario, facing, held, movement, collision)
    native_ends = native(values, scenario, facing, held, movement, collision)
    assert assembly_ends[0].trace.size() == native_ends[0].trace.size(), (
        assembly_ends[0].trace.size(), native_ends[0].trace.size()
    )
    for index in range(assembly_ends[0].trace.size() // 8):
        solver = claripy.Solver()
        solver.add(assembly_ends[0].constraints, native_ends[0].constraints)
        high = assembly_ends[0].trace.size() - index * 8 - 1
        left = assembly_ends[0].trace[high:high - 7]
        right = native_ends[0].trace[high:high - 7]
        solver.add(left != right)
        assert not solver.satisfiable(), (
            f"trace byte {index}: {solver.eval(left, 1)[0]:02x} != "
            f"{solver.eval(right, 1)[0]:02x}")
    assert_pathwise_equivalent(
        assembly_ends, native_ends,
        ("registers", "memory", "trace"),
    )


@pytest.mark.skipif(not ELF.exists(), reason="run native")
@pytest.mark.parametrize("sprite", range(1, 16))
def test_try_pushing_boulder_all_valid_sprite_indices(sprite):
    values = inputs(f"try_push_sprite_{sprite}")
    assembly_ends = assembly(values, "reject", 0, 0, 0x11, 0, sprite)
    native_ends = native(values, "reject", 0, 0, 0x11, 0, sprite)
    assert_pathwise_equivalent(
        assembly_ends, native_ends,
        ("registers", "memory", "trace"),
    )
