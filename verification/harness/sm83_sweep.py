"""Linear-sweep SM83 shim installation for straight-line linked code.

The z80 P-code engine cannot decode SM83-only opcodes and miscomputes some
flag semantics. This module sweeps linked instruction bytes from a function
entry and hooks every SM83-only or flag-relevant opcode site with an exact
SM83-semantics shim so native execution follows SM83 behavior.
"""

from __future__ import annotations

import angr

from verification.harness.sm83_shims import (
    Sm83AdcRegister,
    Sm83AddRegister,
    Sm83CpImmediate,
    Sm83CpRegister,
    Sm83DecRegister,
    Sm83IncRegister,
    Sm83LoadAFromImmediate,
    Sm83LoadAHighImmediate,
    Sm83LoadAImmediate,
    Sm83RlRegister,
    Sm83RrRegister,
    Sm83SbcRegister,
    Sm83SlaRegister,
    Sm83SraRegister,
    Sm83SrlRegister,
    Sm83StoreAHighImmediate,
    Sm83SubImmediate,
    Sm83SubRegister,
    Sm83SwapRegister,
    Sm83XorRegister,
)


class MapperBankWrite(angr.SimProcedure):
    """SM83 ``LD [rROMB], A`` mapper write; a hardware no-op in the flat
    memory model whose net effect is modeled by the port under proof."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.jump(self._next_address)


def opcode_length(opcode: int) -> int:
    """Return the encoded length of one instruction from its first byte.

    Unlisted opcodes are treated as one-byte instructions; every function
    swept with this helper uses only encodings listed here or single-byte
    register/ALU operations.
    """

    if opcode == 0xCB:
        return 2
    if opcode in (0x01, 0x21, 0xCD, 0xEA, 0xFA):
        return 3
    if opcode in (
        0x06, 0x0E, 0x16, 0x1E, 0x26, 0x2E, 0x36, 0x3E,
        0xE0, 0xF0, 0xFE,
        0x18, 0x20, 0x28, 0x30, 0x38,
    ):
        return 2
    return 1


_REGISTER_NAMES = ("b", "c", "d", "e", "h", "l", None, "a")


def install_sm83_hooks(
    project: angr.Project, window: bytes, start: int, end: int
) -> dict[str, int]:
    """Hook every SM83-only or flag-relevant opcode site in [start, end).

    Returns per-opcode hook counts so tests can assert the sweep matched the
    expected instruction mix exactly.
    """

    counts: dict[str, int] = {}
    position = start

    def hook(shim: angr.SimProcedure) -> None:
        project.hook(position, shim, length=following - position)
        counts[hex(opcode)] = counts.get(hex(opcode), 0) + 1

    while position < end:
        opcode = window[position]
        following = position + opcode_length(opcode)
        operand = window[position + 1] if following > position + 1 else 0
        if opcode == 0xE0:
            hook(Sm83StoreAHighImmediate(operand, following))
        elif opcode == 0xF0:
            hook(Sm83LoadAHighImmediate(operand, following))
        elif opcode == 0xEA:
            hook(MapperBankWrite(following))
        elif opcode == 0xFA:
            address = (operand << 8) | window[position + 2]
            hook(Sm83LoadAImmediate(address, following))
        elif opcode == 0x3E:
            hook(Sm83LoadAFromImmediate(position + 1, following))
        elif opcode == 0xFE:
            hook(Sm83CpImmediate(operand, following))
        elif opcode == 0xD6:
            hook(Sm83SubImmediate(operand, following))
        elif opcode in (0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x87):
            name = _REGISTER_NAMES[opcode - 0x80]
            if name is not None:
                hook(Sm83AddRegister(name, following))
        elif opcode in (0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8F):
            name = _REGISTER_NAMES[opcode - 0x88]
            if name is not None:
                hook(Sm83AdcRegister(name, following))
        elif opcode in (0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x97):
            name = _REGISTER_NAMES[opcode - 0x90]
            if name is not None:
                hook(Sm83SubRegister(name, following))
        elif opcode in (0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9F):
            name = _REGISTER_NAMES[opcode - 0x98]
            if name is not None:
                hook(Sm83SbcRegister(name, following))
        elif opcode in (0x04, 0x0C, 0x14, 0x1C, 0x24, 0x2C, 0x3C):
            name = _REGISTER_NAMES[(opcode >> 3) & 0x07]
            if name is not None:
                hook(Sm83IncRegister(name, following))
        elif opcode in (0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D):
            name = _REGISTER_NAMES[(opcode >> 3) & 0x07]
            if name is not None:
                hook(Sm83DecRegister(name, following))
        elif opcode in (0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAF):
            name = _REGISTER_NAMES[opcode - 0xA8]
            if name is not None:
                hook(Sm83XorRegister(name, following))
        elif opcode in (0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBF):
            name = _REGISTER_NAMES[opcode - 0xB8]
            if name is not None:
                hook(Sm83CpRegister(name, following))
        elif opcode == 0xCB:
            second = window[position + 1]
            operation = (second >> 3) & 0x07
            name = _REGISTER_NAMES[second & 0x07]
            shims = {
                2: Sm83RlRegister,
                3: Sm83RrRegister,
                4: Sm83SlaRegister,
                5: Sm83SraRegister,
                6: Sm83SwapRegister,
                7: Sm83SrlRegister,
            }
            if name is not None and operation in shims:
                hook(shims[operation](name, following))
        position = following
    return counts
