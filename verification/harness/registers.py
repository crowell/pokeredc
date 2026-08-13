from __future__ import annotations

import angr
import claripy

from verification.harness.rom import sm83_flags_to_z80, z80_flags_to_sm83


REGISTERS = ("a", "f", "b", "c", "d", "e", "h", "l")


def symbolic_registers(prefix: str) -> dict[str, claripy.ast.BV]:
    return {
        register: (
            claripy.Concat(claripy.BVS(f"{prefix}_flags", 4), claripy.BVV(0, 4))
            if register == "f"
            else claripy.BVS(f"{prefix}_{register}", 8)
        )
        for register in REGISTERS
    }


def set_assembly_registers(
    state: angr.SimState, values: dict[str, claripy.ast.BV]
) -> None:
    for register in REGISTERS:
        value = values[register]
        if register == "f":
            value = sm83_flags_to_z80(value)
        setattr(state.regs, register, value)


def assembly_registers(state: angr.SimState) -> dict[str, claripy.ast.BV]:
    values = {register: getattr(state.regs, register) for register in REGISTERS}
    values["f"] = z80_flags_to_sm83(state.regs.f)
    return values


def store_native_registers(
    state: angr.SimState, address: int, values: dict[str, claripy.ast.BV]
) -> None:
    for offset, register in enumerate(REGISTERS):
        state.memory.store(address + offset, values[register])


def native_registers(state: angr.SimState, address: int) -> dict[str, claripy.ast.BV]:
    return {
        register: state.memory.load(address + offset, 1)
        for offset, register in enumerate(REGISTERS)
    }
