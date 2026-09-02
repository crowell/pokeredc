from __future__ import annotations

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
from verification.harness.rom import linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import (
    Sm83AddImmediate, Sm83AddRegister, Sm83BitRegister,
    Sm83CpImmediate, Sm83CpRegister, Sm83DecRegister, Sm83IncRegister,
    Sm83LoadAHighImmediate, Sm83LoadAImmediate,
    Sm83StoreAHighImmediate, Sm83StoreAImmediate, Sm83XorA,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xd000
RETURN = 0xffff

SPRITE1 = 0xc100
SPRITE2 = 0xc200
TILE = 0xc45c
H_CURRENT_SPRITE_OFFSET = 0xffda
H_TILE_PLAYER_STANDING_ON = 0xff93


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
    constraints: tuple[claripy.ast.Bool, ...]


class Branch(angr.SimProcedure):
    """Fork a conditional JR using Z80-layout Z or C flags."""

    def __init__(self, taken: int, fallthrough: int, flag: int,
                 taken_when_set: bool) -> None:
        super().__init__()
        self.taken = taken
        self.fallthrough = fallthrough
        self.flag = flag
        self.taken_when_set = taken_when_set

    def run(self) -> None:  # type: ignore[override]
        condition = ((self.state.regs.f >> self.flag) & 1) != 0
        if not self.taken_when_set:
            condition = ~condition
        taken = self.state.copy()
        fallthrough = self.state.copy()
        taken.solver.add(condition)
        fallthrough.solver.add(~condition)
        taken.regs.ip = claripy.BVV(self.taken, 16)
        fallthrough.regs.ip = claripy.BVV(self.fallthrough, 16)
        self.inhibit_autoret = True
        self.successors.add_successor(taken, self.taken, condition, "Ijk_Boring")
        self.successors.add_successor(
            fallthrough, self.fallthrough, ~condition, "Ijk_Boring"
        )


class Jump(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.jump(self.next_address)


class LoadAConstant(angr.SimProcedure):
    """LD A,n preserves all flags on the SM83."""

    def __init__(self, value: int, next_address: int) -> None:
        super().__init__()
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(self.value, 8)
        self.jump(self.next_address)


class AndA(angr.SimProcedure):
    """SM83 AND keeps A and sets H plus Z from its result."""

    def __init__(self, value: int, next_address: int) -> None:
        super().__init__()
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.regs.a & self.value
        self.state.regs.f = claripy.BVV(0x10, 8) | claripy.If(
            self.state.regs.a == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)
        )
        self.jump(self.next_address)


class LoadAAtHL(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self.state.regs.hl, 1)
        self.jump(self.next_address)


class LoadHConstant(angr.SimProcedure):
    def __init__(self, value: int, next_address: int) -> None:
        super().__init__()
        self.value = value
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = claripy.BVV(self.value, 8)
        self.jump(self.next_address)


class LoadRegister(angr.SimProcedure):
    def __init__(self, destination: str, source: str, next_address: int) -> None:
        super().__init__()
        self.destination = destination
        self.source = source
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.destination, getattr(self.state.regs, self.source))
        self.jump(self.next_address)


class StoreAAtHL(angr.SimProcedure):
    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(self.state.regs.hl, self.state.regs.a)
        self.jump(self.next_address)


class IncHLAndLoadA(angr.SimProcedure):
    """The adjacent ``INC HL`` / ``LD A,[HL]`` pair at the frame rollover."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        new_l = self.state.regs.l + 1
        self.state.regs.l = new_l
        self.state.regs.a = self.state.memory.load(
            claripy.Concat(self.state.regs.h, new_l), 1
        )
        self.jump(self.next_address)


class Call(angr.SimProcedure):
    def __init__(self, target: int, return_address: int) -> None:
        super().__init__()
        self.target = target
        self.return_address = return_address

    def run(self) -> None:  # type: ignore[override]
        sp = self.state.regs.sp - 2
        self.state.memory.store(sp, claripy.BVV(self.return_address, 16),
                                endness="Iend_LE")
        self.state.regs.sp = sp
        self.jump(self.target)


class Return(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        target = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp += 2
        self.jump(target)


class ReturnIfZero(Return):
    def run(self) -> None:  # type: ignore[override]
        assert self.state.solver.is_true((self.state.regs.f & 0x40) != 0)
        super().run()


def _endpoint(state: angr.SimState, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    registers = native_registers(state, NATIVE_STATE) if native else assembly_registers(state)
    watched = (
        *(SPRITE1 + offset for offset in (0, 2, 7, 8, 9)),
        *(SPRITE2 + offset for offset in (0, 7)),
        TILE, H_CURRENT_SPRITE_OFFSET, H_TILE_PLAYER_STANDING_ON,
        0xcfc4, 0xcfc5, 0xd528, 0xd535, 0xd736,
    )
    return Endpoint(
        **registers,
        state=claripy.Concat(*(state.memory.load(base + address, 1)
                               for address in watched)),
        constraints=tuple(state.solver.constraints),
    )


def _setup(state: angr.SimState, base: int, *, counter: claripy.ast.BV,
           tile: int, direction: int = 0, font_loaded: int = 0,
           walk_counter: int = 0, movement_flags: int = 0,
           current_offset: int = 0, intra: int = 0, animation: int = 0,
           facing: int = 0, grass_tile: int = 0,
           counter_nonzero: bool = False) -> None:
    state.memory.store(base + SPRITE2, counter)
    state.memory.store(base + TILE, claripy.BVV(tile, 8))
    state.memory.store(base + H_CURRENT_SPRITE_OFFSET,
                       claripy.BVV(current_offset, 8))
    # The real detector call is deliberately composed through its linked
    # unused-current-sprite early return, not replaced by a synthetic stub.
    state.memory.store(base + SPRITE1 + current_offset, claripy.BVV(0, 8))
    state.memory.store(base + SPRITE1, claripy.BVV(0, 8))
    for offset, value in ((2, 0x55), (7, intra), (8, animation), (9, facing)):
        state.memory.store(base + SPRITE1 + offset, claripy.BVV(value, 8))
    for address, value in ((0xcfc4, font_loaded), (0xcfc5, walk_counter),
                           (0xd528, direction), (0xd535, grass_tile),
                           (0xd736, movement_flags)):
        state.memory.store(base + address, claripy.BVV(value, 8))
    state.memory.store(base + 0xc207, claripy.BVV(0, 8))
    state.memory.store(base + H_TILE_PLAYER_STANDING_ON, claripy.BVV(0, 8))
    if counter_nonzero:
        state.solver.add(counter != 0)


def _hook_assembly(project: angr.Project, q: int, detector: int) -> None:
    # UpdatePlayerSprite.  Each non-generic SM83 opcode and every conditional
    # edge is adapted explicitly; the linked bytes below guard these offsets.
    project.hook(q + 0, Sm83LoadAImmediate(0xc200, q + 3), length=3)
    project.hook(q + 3, AndA(0xff, q + 4), length=1)
    project.hook(q + 4, Branch(q + 16, q + 6, 6, True), length=2)
    project.hook(q + 6, Sm83CpImmediate(0xff, q + 8), length=2)
    project.hook(q + 8, Branch(q + 25, q + 10, 6, True), length=2)
    project.hook(q + 10, Sm83DecRegister("a", q + 11), length=1)
    project.hook(q + 11, Sm83StoreAImmediate(0xc200, q + 14), length=3)
    project.hook(q + 14, Jump(q + 25), length=2)
    project.hook(q + 16, Sm83LoadAImmediate(TILE, q + 19), length=3)
    project.hook(q + 19, Sm83StoreAHighImmediate(0x93, q + 21), length=2)
    project.hook(q + 21, Sm83CpImmediate(0x60, q + 23), length=2)
    project.hook(q + 23, Branch(q + 31, q + 25, 0, True), length=2)
    project.hook(q + 25, LoadAConstant(0xff, q + 27), length=2)
    project.hook(q + 27, Sm83StoreAImmediate(0xc102, q + 30), length=3)
    project.hook(q + 30, Return(), length=1)
    project.hook(q + 31, Call(detector, q + 34), length=3)

    # The exact, real detector prefix and its RET Z terminal for the unused
    # current sprite path.  This keeps the C composition at an actual callee.
    d = detector
    project.hook(d, Jump(d + 1), length=1)
    project.hook(d + 1, LoadHConstant(0xc1, d + 3), length=2)
    project.hook(d + 3, Sm83LoadAHighImmediate(0xda, d + 5), length=2)
    project.hook(d + 5, Sm83AddImmediate(0, d + 7), length=2)
    project.hook(d + 7, LoadRegister("l", "a", d + 8), length=1)
    project.hook(d + 8, LoadAAtHL(d + 9), length=1)
    project.hook(d + 9, AndA(0xff, d + 10), length=1)
    project.hook(d + 10, ReturnIfZero(), length=1)

    project.hook(q + 34, LoadHConstant(0xc1, q + 36), length=2)
    project.hook(q + 36, Sm83LoadAImmediate(0xcfc5, q + 39), length=3)
    project.hook(q + 39, AndA(0xff, q + 40), length=1)
    project.hook(q + 40, Branch(q + 95, q + 42, 6, False), length=2)
    project.hook(q + 42, Sm83LoadAImmediate(0xd528, q + 45), length=3)
    for offset, bit, next_offset, fallthrough in (
        (45, 2, 49, 52), (52, 3, 56, 60), (60, 1, 64, 68), (68, 0, 72, 76)
    ):
        project.hook(q + offset, Sm83BitRegister(bit, "a", q + offset + 2), length=2)
        project.hook(q + offset + 2, Branch(q + fallthrough, q + next_offset,
                                            6, True), length=2)
    project.hook(q + 49, Sm83XorA(q + 50), length=1)
    project.hook(q + 50, Jump(q + 85), length=2)
    for offset, value in ((56, 4), (64, 8), (72, 12)):
        project.hook(q + offset, LoadAConstant(value, q + offset + 2), length=2)
        project.hook(q + offset + 2, Jump(q + 85), length=2)
    project.hook(q + 76, Sm83XorA(q + 77), length=1)
    project.hook(q + 77, Sm83StoreAImmediate(0xc107, q + 80), length=3)
    project.hook(q + 80, Sm83StoreAImmediate(0xc108, q + 83), length=3)
    project.hook(q + 83, Jump(q + 122), length=2)
    project.hook(q + 85, Sm83StoreAImmediate(0xc109, q + 88), length=3)
    project.hook(q + 88, Sm83LoadAImmediate(0xcfc4, q + 91), length=3)
    project.hook(q + 91, Sm83BitRegister(0, "a", q + 93), length=2)
    project.hook(q + 93, Branch(q + 76, q + 95, 6, False), length=2)
    project.hook(q + 95, Sm83LoadAImmediate(0xd736, q + 98), length=3)
    project.hook(q + 98, Sm83BitRegister(7, "a", q + 100), length=2)
    project.hook(q + 100, Branch(q + 133, q + 102, 6, False), length=2)
    project.hook(q + 102, Sm83LoadAHighImmediate(0xda, q + 104), length=2)
    project.hook(q + 104, Sm83AddImmediate(7, q + 106), length=2)
    project.hook(q + 106, LoadRegister("l", "a", q + 107), length=1)
    project.hook(q + 107, LoadAAtHL(q + 108), length=1)
    project.hook(q + 108, Sm83IncRegister("a", q + 109), length=1)
    project.hook(q + 109, StoreAAtHL(q + 110), length=1)
    project.hook(q + 110, Sm83CpImmediate(4, q + 112), length=2)
    project.hook(q + 112, Branch(q + 122, q + 114, 6, False), length=2)
    project.hook(q + 114, Sm83XorA(q + 115), length=1)
    project.hook(q + 115, StoreAAtHL(q + 116), length=1)
    project.hook(q + 116, IncHLAndLoadA(q + 118), length=2)
    project.hook(q + 118, Sm83IncRegister("a", q + 119), length=1)
    project.hook(q + 119, AndA(3, q + 121), length=2)
    project.hook(q + 121, StoreAAtHL(q + 122), length=1)
    project.hook(q + 122, Sm83LoadAImmediate(0xc108, q + 125), length=3)
    project.hook(q + 125, LoadRegister("b", "a", q + 126), length=1)
    project.hook(q + 126, Sm83LoadAImmediate(0xc109, q + 129), length=3)
    project.hook(q + 129, Sm83AddRegister("b", q + 130), length=1)
    project.hook(q + 130, Sm83StoreAImmediate(0xc102, q + 133), length=3)
    project.hook(q + 133, Sm83LoadAHighImmediate(0x93, q + 135), length=2)
    project.hook(q + 135, LoadRegister("c", "a", q + 136), length=1)
    project.hook(q + 136, Sm83LoadAImmediate(0xd535, q + 139), length=3)
    project.hook(q + 139, Sm83CpRegister("c", q + 140), length=1)
    project.hook(q + 140, LoadAConstant(0, q + 142), length=2)
    project.hook(q + 142, Branch(q + 146, q + 144, 6, False), length=2)
    project.hook(q + 144, LoadAConstant(0x80, q + 146), length=2)
    project.hook(q + 146, Sm83StoreAImmediate(0xc207, q + 149), length=3)
    project.hook(q + 149, Return(), length=1)


def _assembly(values: dict[str, claripy.ast.BV], **setup: object) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "UpdatePlayerSprite")
    detector = symbol_location(SYMBOLS, "DetectCollisionBetweenSprites")
    assert linked_bytes(ROM, location, 150).hex() == (
        "fa00c2a7280afeff280f3dea00c21809fa5cc4e093fe6038063effea02c1c9cd"
        "704c26c1fac5cfa72035fa28d5cb572803af1821cb5f28043e041819cb4f2804"
        "3e081811cb4728043e0c1809afea07c1ea08c11825ea09c1fac4cfcb4720edfa"
        "36d7cb7f201ff0dac6076f7e3c77fe042008af77237e3ce60377fa08c147fa09"
        "c180ea02c1f0934ffa35d5b93e0020023e80ea07c2c9"
    )
    assert linked_bytes(ROM, detector, 11).hex() == "0026c1f0dac6006f7ea7c8"
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    _hook_assembly(project, location.address, detector.address)
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    _setup(state, 0, **setup)  # type: ignore[arg-type]
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN)
    assert not manager.errored and manager.found
    return [_endpoint(result, False) for result in manager.found]


def _native(values: dict[str, claripy.ast.BV], **setup: object) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_update_player_sprite")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    _setup(state, NATIVE_MEMORY, **setup)  # type: ignore[arg-type]
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and manager.deadended
    return [_endpoint(result, True) for result in manager.deadended]


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),
                    reason="build artifacts missing")
@pytest.mark.parametrize("counter_value", (1, 0xff))
def test_update_player_sprite_pending_animation_pathwise_equivalence(
    counter_value: int,
) -> None:
    """Decrement and $ff animation-counter disable paths preserve all state."""
    values = symbolic_registers("update_player_pending")
    counter = claripy.BVV(counter_value, 8)
    assert_pathwise_equivalent(
        _assembly(values, counter=counter, tile=0),
        _native(values, counter=counter, tile=0),
        (*REGISTERS, "state"),
    )


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),
                    reason="build artifacts missing")
def test_update_player_sprite_text_box_pathwise_equivalence() -> None:
    values = symbolic_registers("update_player_text_box")
    assert_pathwise_equivalent(
        _assembly(values, counter=claripy.BVV(0, 8), tile=0x60),
        _native(values, counter=claripy.BVV(0, 8), tile=0x60),
        (*REGISTERS, "state"),
    )


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),
                    reason="build artifacts missing")
@pytest.mark.parametrize(("direction", "font_loaded", "walk_counter", "movement_flags",
                          "intra", "animation", "grass_tile"), [
    (0, 0, 0, 0, 2, 3, 0),       # stationary resets both animation counters
    (0x04, 0, 0, 0, 3, 1, 0x22), # down advances frame and is grass-obscured
    (0x08, 1, 0, 0, 0, 2, 0x11), # font-loaded facing takes notMoving
    (0, 0, 1, 0x80, 1, 2, 0x60), # moving/spinning skips animation update
])
def test_update_player_sprite_normal_frame_pathwise_equivalence(
    direction: int, font_loaded: int, walk_counter: int, movement_flags: int,
    intra: int, animation: int, grass_tile: int,
) -> None:
    """Normal frames compose through the linked detector's real RET Z path."""
    values = symbolic_registers("update_player_normal")
    kwargs = dict(counter=claripy.BVV(0, 8), tile=0x22, direction=direction,
                  font_loaded=font_loaded, walk_counter=walk_counter,
                  movement_flags=movement_flags, intra=intra,
                  animation=animation, grass_tile=grass_tile)
    assert_pathwise_equivalent(
        _assembly(values, **kwargs), _native(values, **kwargs), (*REGISTERS, "state")
    )
