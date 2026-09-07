"""Complete leaf proof: execute linked instructions, not a function model."""
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
from verification.harness.sm83_shims import Sm83StoreAHighImmediate, Sm83StoreAImmediate

ROOT = Path(__file__).resolve().parents[2]
ROM = ROOT / "pokered.gbc"
SYMS = ROOT / "pokered.sym"
ELF = ROOT / "verification/build/ports.elf"
NS, NM, STACK, RETURN = 0x100000, 0x200000, 0xD000, 0xEFFF
ADDRESSES = (0xFFB4, 0xD528, 0xD60C)


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
    constraints: tuple


def endpoint(state, native):
    base = NM if native else 0
    return Endpoint(
        **(native_registers(state, NS) if native else assembly_registers(state)),
        memory=claripy.Concat(*(state.memory.load(base + a, 1) for a in ADDRESSES)),
        constraints=tuple(state.solver.constraints),
    )


def test_reds_house2_f_default_script_instruction_equivalence():
    values = symbolic_registers("reds2_default")
    memory = [claripy.BVS(f"reds2_memory_{a:x}", 8) for a in ADDRESSES]
    location = symbol_location(SYMS, "RedsHouse2FDefaultScript")
    # XOR A; LDH [hJoyHeld],A; LD A,UP; LD [wPlayerMovingDirection],A;
    # LD A,NOOP; LD [wRedsHouse2FCurScript],A; RET. LD preserves flags.
    expected = bytes.fromhex("af e0 b4 3e 08 ea 28 d5 3e 01 ea 0c d6 c9")
    assert linked_bytes(ROM, location, len(expected)) == expected
    p = angr.Project(rom_window(ROM, location.bank), auto_load_libs=False,
        rebase_granularity=0x100, main_opts={"backend": "blob",
        "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0, "entry_point": location.address})
    q = location.address
    p.hook(q + 1, Sm83StoreAHighImmediate(0xB4, q + 3), length=2)
    p.hook(q + 5, Sm83StoreAImmediate(0xD528, q + 8), length=3)
    p.hook(q + 10, Sm83StoreAImmediate(0xD60C, q + 13), length=3)
    s = p.factory.blank_state(addr=q)
    set_assembly_registers(s, values)
    for address, value in zip(ADDRESSES, memory): s.memory.store(address, value)
    s.regs.sp = STACK
    s.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    asm = [endpoint(e, False) for e in collect_returns(p, s, RETURN)]

    p = angr.Project(ELF, auto_load_libs=False)
    f = p.loader.find_symbol("port_reds_house2_f_default_script")
    assert f
    s = p.factory.call_state(f.rebased_addr, NS, NM)
    store_native_registers(s, NS, values)
    for address, value in zip(ADDRESSES, memory): s.memory.store(NM + address, value)
    sim = p.factory.simulation_manager(s)
    sim.run()
    assert not sim.errored and len(sim.deadended) == 1
    assert_pathwise_equivalent(asm, [endpoint(e, True) for e in sim.deadended], (*REGISTERS, "memory"))
