"""Full motion/copy/delay loops for both directions and every terminating Y.

Both stock callers leave HL pointing at the delay field, and choose +/-16
motion with two or three frames of delay. Sixteen Y inputs per direction
exhaust the terminating domain; other Y residues cannot reach the target.
"""

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
    Sm83AddRegister, Sm83CpRegister, Sm83DecRegister, Sm83LoadAAtHlIncrement,
    Sm83LoadAImmediate, Sm83OrRegister, Sm83StoreAImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
ROM, SYMBOLS = ROOT / "pokered.gbc", ROOT / "pokered.sym"
ELF = ROOT / "verification/build/ports.elf"
NS, NM, STACK, RET = 0x100000, 0x200000, 0xD000, 0xFFFF
DELTA, MAX_Y, DELAY, Y, IMAGE, LIST = 0xCD3D, 0xCD3E, 0xCD3F, 0xC104, 0xC102, 0xCD48
WATCHED = (*range(0xCD3C, 0xCD4D), *range(0xC101, 0xC108))
BODIES = {
    "PlayerSpinWhileMovingUpOrDown": "cd1747fa3dcd4ffa04c181ea04c14ffa3ecdb9c8fa3fcd4fcd393718e3",
    "SpinPlayerSprite": "7eea02c1e52148cd1147cd010400cdb500fa47cdea4bcde1c9",
    "CopyData": "2a12130b79b020f8c9",
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


class ReturnZ(angr.SimProcedure):
    def run(self):
        condition = (self.state.regs.f & 0x40) != 0
        target = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        yes, no = self.state.copy(), self.state.copy()
        yes.regs.sp += 2
        self.inhibit_autoret = True
        self.successors.add_successor(yes, target, condition, "Ijk_Ret")
        self.successors.add_successor(no, self.addr + 1, ~condition, "Ijk_Boring")


def record_frame(state, registers, base):
    state.globals["frames"] += (claripy.Concat(
        *(registers[name] for name in REGISTERS),
        *(state.memory.load(base + address, 1) for address in
          (Y, IMAGE, DELAY, *range(LIST - 1, LIST + 4))),
    ),)


class AcknowledgedDelayFrame(angr.SimProcedure):
    def run(self):
        record_frame(self.state, assembly_registers(self.state), 0)
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x50, 8)
        target = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp += 2
        self.jump(target)


def observe_native_frame(state):
    record_frame(state, native_registers(state, state.regs.rdi), NM)


def setup(state, base, values, delta, target, steps, delay):
    for address in WATCHED:
        state.memory.store(base + address, values[f"m{address:x}"])
    for address, value in (
        (DELTA, delta), (MAX_Y, target), (DELAY, delay),
        (Y, (target - steps * delta) & 255),
    ):
        state.memory.store(base + address, claripy.BVV(value, 8))
    state.globals["frames"] = ()


def endpoint(state, native, steps, delay):
    frames = state.globals["frames"]
    assert len(frames) == (steps - 1) * delay
    base = NM if native else 0
    registers = native_registers(state, NS) if native else assembly_registers(state)
    return Endpoint(
        **registers,
        memory=claripy.Concat(*(state.memory.load(base + address, 1) for address in WATCHED)),
        frames=claripy.Concat(*frames) if frames else claripy.BVV(0, 8),
        constraints=tuple(state.solver.constraints),
    )


def assembly(values, delta, target, steps, delay):
    locations = {name: symbol_location(SYMBOLS, name) for name in BODIES}
    for name, body in BODIES.items():
        expected = bytes.fromhex(body)
        assert linked_bytes(ROM, locations[name], len(expected)) == expected
    location = locations["PlayerSpinWhileMovingUpOrDown"]
    project = angr.Project(
        rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": location.address},
    )
    q = location.address
    for offset, address in ((3, DELTA), (7, Y), (15, MAX_Y), (20, DELAY)):
        project.hook(q + offset, Sm83LoadAImmediate(address, q + offset + 3), length=3)
    project.hook(q + 10, Sm83AddRegister("c", q + 11), length=1)
    project.hook(q + 11, Sm83StoreAImmediate(Y, q + 14), length=3)
    project.hook(q + 18, Sm83CpRegister("c", q + 19), length=1)
    project.hook(q + 19, ReturnZ(), length=1)
    q = locations["SpinPlayerSprite"].address
    project.hook(q + 1, Sm83StoreAImmediate(IMAGE, q + 4), length=3)
    project.hook(q + 17, Sm83LoadAImmediate(LIST - 1, q + 20), length=3)
    project.hook(q + 20, Sm83StoreAImmediate(LIST + 3, q + 23), length=3)
    q = locations["CopyData"].address
    project.hook(q, Sm83LoadAAtHlIncrement(q + 1), length=1)
    project.hook(q + 5, Sm83OrRegister("b", q + 6), length=1)
    q = locations["DelayFrames"].address
    project.hook(q + 3, Sm83DecRegister("c", q + 4), length=1)
    project.hook(symbol_location(SYMBOLS, "DelayFrame").address, AcknowledgedDelayFrame())
    state = project.factory.blank_state(addr=location.address)
    set_assembly_registers(state, values)
    setup(state, 0, values, delta, target, steps, delay)
    state.regs.sp = claripy.BVV(STACK, 16)
    state.memory.store(STACK, claripy.BVV(RET, 16), endness="Iend_LE")
    ends = collect_returns(project, state, RET)
    assert len(ends) == 1
    return [endpoint(ends[0], False, steps, delay)]


def native(values, delta, target, steps, delay):
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_player_spin_while_moving_up_or_down")
    frame = project.loader.find_symbol("port_delay_frame")
    assert function is not None and frame is not None
    project.hook(frame.rebased_addr, observe_native_frame, length=0)
    state = project.factory.call_state(function.rebased_addr, NS, NM)
    store_native_registers(state, NS, values)
    setup(state, NM, values, delta, target, steps, delay)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and not manager.unconstrained
    assert len(manager.deadended) == 1
    return [endpoint(manager.deadended[0], True, steps, delay)]


@pytest.mark.parametrize("delta,target", ((0x10, 0x3C), (0xF0, 0xEC)))
@pytest.mark.parametrize("delay", (2, 3))
@pytest.mark.parametrize("steps", range(1, 17))
def test_player_spin_motion_gameplay_pathwise_equivalence(delta, target, delay, steps):
    assert ELF.exists() and ROM.exists() and SYMBOLS.exists(), "build native and red artifacts"
    values = symbolic_registers(f"spin_motion_{delta}_{delay}_{steps}")
    values["h"], values["l"] = claripy.BVV(DELAY >> 8, 8), claripy.BVV(DELAY & 255, 8)
    for address in WATCHED:
        values[f"m{address:x}"] = claripy.BVS(f"spin_motion_{delta}_{delay}_{steps}_m{address:x}", 8)
    assert_pathwise_equivalent(
        assembly(values, delta, target, steps, delay),
        native(values, delta, target, steps, delay),
        (*REGISTERS, "memory", "frames"),
    )
