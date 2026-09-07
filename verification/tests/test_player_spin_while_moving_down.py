"""Run the complete wrapper, motion, spin, CopyData and DelayFrames bodies.

Only DelayFrame uses its acknowledged-interrupt composition boundary. Native
DelayFrame still executes; a zero-length observation hook records its inputs.
The 16 Y cases exhaust termination under +16 modulo 256 (low nibble must be C).
wOnSGB is a boolean hardware flag, tested at both gameplay values.
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
    Sm83AddRegister, Sm83CpRegister, Sm83DecRegister, Sm83IncRegister,
    Sm83LoadAAtHlIncrement, Sm83LoadAImmediate, Sm83OrRegister,
    Sm83StoreAAtHlIncrement, Sm83StoreAImmediate, Sm83XorImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NS, NM, STACK, RETURN = 0x100000, 0x200000, 0xD000, 0xFFFF
DELTA, MAX_Y, DELAY, Y, IMAGE, LIST, SGB = (
    0xCD3D, 0xCD3E, 0xCD3F, 0xC104, 0xC102, 0xCD48, 0xCF1B,
)
WATCHED = (*range(0xCD3C, 0xCD4D), *range(0xC101, 0xC108), SGB)
BODIES = {
    "PlayerSpinWhileMovingDown": "213dcd3e10223e3c22cd7f4777c35547",
    "GetPlayerTeleportAnimFrameDelay": "fa1bcfee013c3cc9",
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
    delays: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class ReturnZ(angr.SimProcedure):
    """SM83 conditional return with the concrete caller stack retained."""

    def run(self):
        condition = (self.state.regs.f & 0x40) != 0
        target = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        yes, no = self.state.copy(), self.state.copy()
        yes.regs.sp += 2
        self.inhibit_autoret = True
        self.successors.add_successor(yes, target, condition, "Ijk_Ret")
        self.successors.add_successor(no, self.addr + 1, ~condition, "Ijk_Boring")


def record_delay(state, registers, base):
    event = claripy.Concat(
        *(registers[name] for name in REGISTERS),
        *(state.memory.load(base + address, 1) for address in (Y, IMAGE, DELAY)),
    )
    state.globals["delay_trace"] += (event,)


class AcknowledgedDelayFrame(angr.SimProcedure):
    def run(self):
        record_delay(self.state, assembly_registers(self.state), 0)
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x50, 8)
        target = self.state.memory.load(self.state.regs.sp, 2, endness="Iend_LE")
        self.state.regs.sp += 2
        self.jump(target)


def observe_native_delay(state):
    record_delay(state, native_registers(state, state.regs.rdi), NM)


def setup(state, base, values, steps, on_sgb):
    for address in WATCHED:
        state.memory.store(base + address, values[f"m{address:x}"])
    state.memory.store(base + Y, claripy.BVV((0x3C - 16 * steps) & 255, 8))
    state.memory.store(base + SGB, claripy.BVV(on_sgb, 8))
    state.globals["delay_trace"] = ()


def endpoint(state, native, steps, on_sgb):
    trace = state.globals["delay_trace"]
    assert len(trace) == (steps - 1) * (3 - on_sgb)
    base = NM if native else 0
    registers = native_registers(state, NS) if native else assembly_registers(state)
    return Endpoint(
        **registers,
        memory=claripy.Concat(*(state.memory.load(base + address, 1) for address in WATCHED)),
        delays=claripy.Concat(*trace) if trace else claripy.BVV(0, 8),
        constraints=tuple(state.solver.constraints),
    )


def assembly(values, steps, on_sgb):
    locations = {name: symbol_location(SYMBOLS, name) for name in BODIES}
    for name, body in BODIES.items():
        expected = bytes.fromhex(body)
        assert linked_bytes(ROM, locations[name], len(expected)) == expected
    start = locations["PlayerSpinWhileMovingDown"]
    project = angr.Project(
        rom_window(ROM, start.bank), auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"),
                   "base_addr": 0, "entry_point": start.address},
    )
    q = start.address
    project.hook(q + 5, Sm83StoreAAtHlIncrement(q + 6), length=1)
    project.hook(q + 8, Sm83StoreAAtHlIncrement(q + 9), length=1)
    q = locations["GetPlayerTeleportAnimFrameDelay"].address
    project.hook(q, Sm83LoadAImmediate(SGB, q + 3), length=3)
    project.hook(q + 3, Sm83XorImmediate(1, q + 5), length=2)
    project.hook(q + 5, Sm83IncRegister("a", q + 6), length=1)
    project.hook(q + 6, Sm83IncRegister("a", q + 7), length=1)
    q = locations["PlayerSpinWhileMovingUpOrDown"].address
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
    state = project.factory.blank_state(addr=start.address)
    set_assembly_registers(state, values)
    setup(state, 0, values, steps, on_sgb)
    state.regs.sp = claripy.BVV(STACK, 16)
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    ends = collect_returns(project, state, RETURN)
    assert len(ends) == 1
    return [endpoint(ends[0], False, steps, on_sgb)]


def native(values, steps, on_sgb):
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_player_spin_while_moving_down")
    delay = project.loader.find_symbol("port_delay_frame")
    assert function is not None and delay is not None
    project.hook(delay.rebased_addr, observe_native_delay, length=0)
    state = project.factory.call_state(function.rebased_addr, NS, NM)
    store_native_registers(state, NS, values)
    setup(state, NM, values, steps, on_sgb)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and not manager.unconstrained
    assert len(manager.deadended) == 1
    return [endpoint(manager.deadended[0], True, steps, on_sgb)]


@pytest.mark.parametrize("steps", range(1, 17))
@pytest.mark.parametrize("on_sgb", (0, 1))
def test_player_spin_while_moving_down_pathwise_equivalence(steps, on_sgb):
    assert ELF.exists() and ROM.exists() and SYMBOLS.exists(), "build native and red artifacts"
    values = symbolic_registers(f"spin_down_{steps}_{on_sgb}")
    for address in WATCHED:
        values[f"m{address:x}"] = claripy.BVS(f"spin_down_{steps}_{on_sgb}_m{address:x}", 8)
    assert_pathwise_equivalent(
        assembly(values, steps, on_sgb), native(values, steps, on_sgb),
        (*REGISTERS, "memory", "delays"),
    )
