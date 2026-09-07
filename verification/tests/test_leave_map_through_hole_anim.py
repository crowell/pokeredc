"""Compose complete linked hole-warp, fade, restore and delay-loop bodies."""

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
    REGISTERS, assembly_registers, native_registers, set_assembly_registers,
    store_native_registers, symbolic_registers,
)
from verification.harness.rom import collect_returns, linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import (
    Sm83DecRegister, Sm83LoadAAtHlIncrement, Sm83LoadAImmediate,
    Sm83StoreAHighImmediate, Sm83StoreAImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
ROM, SYMBOLS = ROOT / "pokered.gbc", ROOT / "pokered.sym"
ELF = ROOT / "verification/build/ports.elf"
NS, NM, STACK, RET = 0x100000, 0x200000, 0xD000, 0xFFFF
ENABLED, PLAYER_Y, PLAYER_IMAGE = 0xCFCB, 0xC104, 0xC102
SAVED_Y, SAVED_FACING = 0xCD4F, 0xCD50
PALETTE_ADDRESS = 0x211C
PALETTE = bytes.fromhex("908090404040000000")
WATCHED = (
    *range(0xC2FF, 0xC3A1),  # Entire shadow OAM and both guards.
    *range(0xC100, 0xC108), *range(0xCD4E, 0xCD52),
    *range(0xCFCA, 0xCFCD), *range(0xFF46, 0xFF4B),
)
TRACE_ADDRESSES = (
    *range(0xC300, 0xC310), ENABLED, PLAYER_Y, PLAYER_IMAGE, 0xFF47, 0xFF48, 0xFF49,
)
BODIES = {
    "LeaveMapThroughHoleAnim": (
        "3effeacbcffa02c3ea0ac3fa06c3ea0ec33ea0ea00c3ea04c30e02cd3937"
        "3ea0ea08c3ea0cc3cdd8203e01eacbcfc37247"
    ),
    "GBFadeOutToWhite": "211c2106032ae0472ae0482ae0490e08cd39370520efc9",
    "RestoreFacingDirectionAndYScreenPos": "fa4fcdea04c1fa50cdea02c1c9",
    "DelayFrames": "cdaf200d20fac9",
}


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
    frames: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def record_frame(state, registers, base):
    state.globals["frames"] += (claripy.Concat(
        *(registers[name] for name in REGISTERS),
        *(state.memory.load(base + address, 1) for address in TRACE_ADDRESSES),
    ),)


class AcknowledgedDelayFrame(angr.SimProcedure):
    """Only the independently proven interrupt-wait transition is composed."""

    def run(self):
        record_frame(self.state, assembly_registers(self.state), 0)
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x50, 8)
        target = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp += 2
        self.jump(target)


def observe_native_frame(state):
    record_frame(state, native_registers(state, state.regs.rdi), NM)


def setup(state, base, values):
    for address in WATCHED:
        state.memory.store(base + address, values[f"m{address:x}"])
    state.memory.store(base + PALETTE_ADDRESS, PALETTE)
    state.globals["frames"] = ()


def endpoint(state, native):
    # Two frames while half-hidden, then three eight-frame palette stages.
    assert len(state.globals["frames"]) == 26
    base = NM if native else 0
    registers = native_registers(state, NS) if native else assembly_registers(state)
    return Endpoint(
        **registers,
        memory=claripy.Concat(*(state.memory.load(base + address, 1) for address in WATCHED)),
        frames=claripy.Concat(*state.globals["frames"]),
        constraints=tuple(state.solver.constraints),
    )


def assembly(values):
    locations = {name: symbol_location(SYMBOLS, name) for name in BODIES}
    for name, body in BODIES.items():
        expected = bytes.fromhex(body)
        assert linked_bytes(ROM, locations[name], len(expected)) == expected
    palette = symbol_location(SYMBOLS, "FadePal6")
    assert palette.address == PALETTE_ADDRESS
    assert linked_bytes(ROM, palette, len(PALETTE)) == PALETTE
    location = locations["LeaveMapThroughHoleAnim"]
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    q = location.address
    for offset, address in ((5, 0xC302), (11, 0xC306)):
        project.hook(q + offset, Sm83LoadAImmediate(address, q + offset + 3), length=3)
    for offset, address in (
        (2, ENABLED), (8, 0xC30A), (14, 0xC30E), (19, 0xC300),
        (22, 0xC304), (32, 0xC308), (35, 0xC30C), (43, ENABLED),
    ):
        project.hook(q + offset, Sm83StoreAImmediate(address, q + offset + 3), length=3)
    q = locations["GBFadeOutToWhite"].address
    for offset in (5, 8, 11):
        project.hook(q + offset, Sm83LoadAAtHlIncrement(q + offset + 1), length=1)
    for offset, address in ((6, 0x47), (9, 0x48), (12, 0x49)):
        project.hook(q + offset, Sm83StoreAHighImmediate(address, q + offset + 2), length=2)
    project.hook(q + 19, Sm83DecRegister("b", q + 20), length=1)
    q = locations["RestoreFacingDirectionAndYScreenPos"].address
    project.hook(q, Sm83LoadAImmediate(SAVED_Y, q + 3), length=3)
    project.hook(q + 3, Sm83StoreAImmediate(PLAYER_Y, q + 6), length=3)
    project.hook(q + 6, Sm83LoadAImmediate(SAVED_FACING, q + 9), length=3)
    project.hook(q + 9, Sm83StoreAImmediate(PLAYER_IMAGE, q + 12), length=3)
    q = locations["DelayFrames"].address
    project.hook(q + 3, Sm83DecRegister("c", q + 4), length=1)
    project.hook(symbol_location(SYMBOLS, "DelayFrame").address, AcknowledgedDelayFrame())
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    setup(state, 0, values)
    state.regs.sp = claripy.BVV(STACK, 16)
    state.memory.store(STACK, claripy.BVV(RET, 16), endness="Iend_LE")
    ends = collect_returns(project, state, RET)
    assert len(ends) == 1
    return [endpoint(ends[0], False)]


def native(values):
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_leave_map_through_hole_anim")
    delay = project.loader.find_symbol("port_delay_frame")
    assert function is not None and delay is not None
    project.hook(delay.rebased_addr, observe_native_frame, length=0)
    state = project.factory.call_state(function.rebased_addr, NS, NM)
    store_native_registers(state, NS, values)
    setup(state, NM, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and not manager.unconstrained
    assert len(manager.deadended) == 1
    return [endpoint(manager.deadended[0], True)]


def test_leave_map_through_hole_anim_pathwise_equivalence():
    assert ELF.exists() and ROM.exists() and SYMBOLS.exists(), "build native and red artifacts"
    values = symbolic_registers("hole_anim")
    for address in WATCHED:
        values[f"m{address:x}"] = claripy.BVS(f"hole_anim_m{address:x}", 8)
    assert_pathwise_equivalent(
        assembly(values), native(values), (*REGISTERS, "memory", "frames"),
    )
