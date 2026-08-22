from __future__ import annotations

import angr
import claripy


class Sm83AndImmediate(angr.SimProcedure):
    """Correct SM83 ``AND n`` result and flags."""

    def __init__(self, immediate: int, next_address: int) -> None:
        super().__init__()
        self._immediate = immediate
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.regs.a & self._immediate
        # SM83 AND n: Z from result; C, N, H always cleared.
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x40, 8),
            claripy.BVV(0, 8),
        )
        self.jump(self._next_address)


class Sm83XorImmediate(angr.SimProcedure):
    """Correct SM83 ``XOR n`` result and flags."""

    def __init__(self, immediate: int, next_address: int) -> None:
        super().__init__()
        self._immediate = immediate
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.regs.a ^ self._immediate
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x40, 8),
            claripy.BVV(0, 8),
        )
        self.jump(self._next_address)


class Sm83OrRegister(angr.SimProcedure):
    """Correct SM83 ``OR r`` result and flags."""

    def __init__(self, register: str, next_address: int) -> None:
        super().__init__()
        self._register = register
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.regs.a | getattr(
            self.state.regs, self._register
        )
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x40, 8),
            claripy.BVV(0, 8),
        )
        self.jump(self._next_address)


class Sm83XorRegister(angr.SimProcedure):
    """Correct SM83 ``XOR r`` result and flags. Covers ``XOR A`` (opcode AF),
    which clears the accumulator by xoring it with itself."""

    def __init__(self, register: str, next_address: int) -> None:
        super().__init__()
        self._register = register
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.regs.a ^ getattr(
            self.state.regs, self._register
        )
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x40, 8),
            claripy.BVV(0, 8),
        )
        self.jump(self._next_address)

class Sm83AndRegister(angr.SimProcedure):
    """Correct SM83 ``AND r`` result and flags."""

    def __init__(self, register: str, next_address: int) -> None:
        super().__init__()
        self._register = register
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.regs.a & getattr(
            self.state.regs, self._register
        )
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x40, 8),
            claripy.BVV(0, 8),
        )
        self.jump(self._next_address)


class Sm83Scf(angr.SimProcedure):
    """Correct SM83 ``SCF`` flags: preserve Z, set C, clear N and H."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.f = (self.state.regs.f & 0x40) | 1
        self.jump(self._next_address)


class Sm83ResRegister(angr.SimProcedure):
    """Correct SM83 ``RES n, r`` without affecting flags."""

    def __init__(self, bit: int, register: str, next_address: int) -> None:
        super().__init__()
        self._bit = bit
        self._register = register
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        value = getattr(self.state.regs, self._register)
        setattr(self.state.regs, self._register, value & ~(1 << self._bit))
        self.jump(self._next_address)


class Sm83CpAtHl(angr.SimProcedure):
    """Correct SM83/Z80-compatible ``CP (HL)`` semantics.

    The SLEIGH definition bundled with pypcode 3.2.1 calculates the Z80
    half-carry mask using an arithmetic right shift of -1. That leaves the
    mask equal to -1 and makes H clear for every CP. This shim writes the Z80
    flag layout expected by subsequent generic-Z80 control-flow instructions;
    the proof adapter later maps Z, N, H, and C into canonical SM83 positions.
    """

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        left = self.state.regs.a
        right = self.state.memory.load(self.state.regs.hl, 1)

        flags = claripy.BVV(0x02, 8)  # Z80 N
        flags |= claripy.If(left == right, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        flags |= claripy.If(
            (left & 0x0F).ULT(right & 0x0F),
            claripy.BVV(0x10, 8),
            claripy.BVV(0, 8),
        )
        flags |= claripy.If(left.ULT(right), claripy.BVV(0x01, 8), claripy.BVV(0, 8))

        self.state.regs.f = flags
        self.jump(self._next_address)


class Sm83SubRegister(angr.SimProcedure):
    """Correct SM83 subtraction and flags for an 8-bit register operand."""

    def __init__(self, register: str, next_address: int) -> None:
        super().__init__()
        self._register = register
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        left = self.state.regs.a
        right = getattr(self.state.regs, self._register)
        result = left - right

        flags = claripy.BVV(0x02, 8)  # Z80 N
        flags |= claripy.If(result == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        flags |= claripy.If(
            (left & 0x0F).ULT(right & 0x0F),
            claripy.BVV(0x10, 8),
            claripy.BVV(0, 8),
        )
        flags |= claripy.If(left.ULT(right), claripy.BVV(0x01, 8), claripy.BVV(0, 8))

        self.state.regs.a = result
        self.state.regs.f = flags
        self.jump(self._next_address)


class Sm83SubImmediate(angr.SimProcedure):
    """Correct SM83 ``SUB n`` semantics and flags."""

    def __init__(self, immediate: int, next_address: int) -> None:
        super().__init__()
        self._immediate = immediate
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        left = self.state.regs.a
        right = claripy.BVV(self._immediate, 8)
        result = left - right
        flags = claripy.BVV(0x02, 8)
        flags |= claripy.If(result == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        flags |= claripy.If(
            (left & 0x0F).ULT(right & 0x0F),
            claripy.BVV(0x10, 8),
            claripy.BVV(0, 8),
        )
        flags |= claripy.If(left.ULT(right), claripy.BVV(1, 8), claripy.BVV(0, 8))
        self.state.regs.a = result
        self.state.regs.f = flags
        self.jump(self._next_address)


class Sm83SubAtHl(angr.SimProcedure):
    """Correct SM83 ``SUB [HL]`` semantics and flags."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        left = self.state.regs.a
        right = self.state.memory.load(self.state.regs.hl, 1)
        result = left - right
        flags = claripy.BVV(0x02, 8)
        flags |= claripy.If(result == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        flags |= claripy.If(
            (left & 0x0F).ULT(right & 0x0F),
            claripy.BVV(0x10, 8),
            claripy.BVV(0, 8),
        )
        flags |= claripy.If(left.ULT(right), claripy.BVV(1, 8), claripy.BVV(0, 8))
        self.state.regs.a = result
        self.state.regs.f = flags
        self.jump(self._next_address)


class Sm83AddRegister(angr.SimProcedure):
    """Correct SM83 ``ADD A, r`` flags."""

    def __init__(self, register: str, next_address: int) -> None:
        super().__init__()
        self._register = register
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        left = self.state.regs.a
        right = getattr(self.state.regs, self._register)
        wide = claripy.ZeroExt(1, left) + claripy.ZeroExt(1, right)
        result = wide[7:0]
        flags = claripy.If(result == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        flags |= claripy.If(
            (left & 0x0F) + (right & 0x0F) > 0x0F,
            claripy.BVV(0x10, 8),
            claripy.BVV(0, 8),
        )
        flags |= claripy.ZeroExt(7, wide[8])
        self.state.regs.a = result
        self.state.regs.f = flags
        self.jump(self._next_address)


class Sm83AddAtHl(angr.SimProcedure):
    """Correct SM83 ``ADD A, [HL]`` semantics and flags."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        left = self.state.regs.a
        right = self.state.memory.load(self.state.regs.hl, 1)
        wide = claripy.ZeroExt(1, left) + claripy.ZeroExt(1, right)
        result = wide[7:0]
        flags = claripy.If(result == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        flags |= claripy.If(
            (left & 0x0F) + (right & 0x0F) > 0x0F,
            claripy.BVV(0x10, 8),
            claripy.BVV(0, 8),
        )
        flags |= claripy.ZeroExt(7, wide[8])
        self.state.regs.a = result
        self.state.regs.f = flags
        self.jump(self._next_address)


class Sm83AddImmediate(angr.SimProcedure):
    """Correct SM83 ``ADD A, n`` flags for an 8-bit immediate operand."""

    def __init__(self, immediate: int, next_address: int) -> None:
        super().__init__()
        self._immediate = immediate
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        left = self.state.regs.a
        right = claripy.BVV(self._immediate, 8)
        wide = claripy.ZeroExt(1, left) + claripy.ZeroExt(1, right)
        result = wide[7:0]
        flags = claripy.If(result == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        flags |= claripy.If(
            (left & 0x0F) + (right & 0x0F) > 0x0F,
            claripy.BVV(0x10, 8),
            claripy.BVV(0, 8),
        )
        flags |= claripy.ZeroExt(7, wide[8])
        self.state.regs.a = result
        self.state.regs.f = flags
        self.jump(self._next_address)


class Sm83AddHlRegisterPair(angr.SimProcedure):
    """Correct SM83 ``ADD HL, rr`` semantics and flags."""

    def __init__(self, register_pair: str, next_address: int) -> None:
        super().__init__()
        self._register_pair = register_pair
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        left = self.state.regs.hl
        right = getattr(self.state.regs, self._register_pair)
        wide = claripy.ZeroExt(1, left) + claripy.ZeroExt(1, right)
        low_wide = claripy.ZeroExt(1, left & 0x0FFF) + claripy.ZeroExt(
            1, right & 0x0FFF
        )
        flags = self.state.regs.f & 0x40  # preserve Z in the Z80 layout
        flags |= claripy.If(
            low_wide > 0x0FFF, claripy.BVV(0x10, 8), claripy.BVV(0, 8)
        )
        flags |= claripy.ZeroExt(7, wide[16])
        self.state.regs.hl = wide[15:0]
        self.state.regs.f = flags
        self.jump(self._next_address)


class Sm83SbcRegister(angr.SimProcedure):
    """Correct SM83 subtraction-with-carry for an 8-bit register operand."""

    def __init__(self, register: str, next_address: int) -> None:
        super().__init__()
        self._register = register
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        left = self.state.regs.a
        right = getattr(self.state.regs, self._register)
        carry = self.state.regs.f & 1
        result = left - right - carry
        extended_left = claripy.ZeroExt(1, left)
        extended_right = claripy.ZeroExt(1, right) + claripy.ZeroExt(1, carry)
        low_left = claripy.ZeroExt(1, left & 0x0F)
        low_right = claripy.ZeroExt(1, right & 0x0F) + claripy.ZeroExt(1, carry)

        flags = claripy.BVV(0x02, 8)  # Z80 N
        flags |= claripy.If(result == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        flags |= claripy.If(
            low_left.ULT(low_right),
            claripy.BVV(0x10, 8),
            claripy.BVV(0, 8),
        )
        flags |= claripy.If(
            extended_left.ULT(extended_right),
            claripy.BVV(0x01, 8),
            claripy.BVV(0, 8),
        )

        self.state.regs.a = result
        self.state.regs.f = flags
        self.jump(self._next_address)


class Sm83SbcImmediate(angr.SimProcedure):
    """Correct SM83 ``SBC A, n`` semantics and flags."""

    def __init__(self, immediate: int, next_address: int) -> None:
        super().__init__()
        self._immediate = immediate
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        left = self.state.regs.a
        right = claripy.BVV(self._immediate, 8)
        carry = self.state.regs.f & 1
        result = left - right - carry
        extended_left = claripy.ZeroExt(1, left)
        extended_right = claripy.ZeroExt(1, right) + claripy.ZeroExt(1, carry)
        low_left = claripy.ZeroExt(1, left & 0x0F)
        low_right = claripy.ZeroExt(1, right & 0x0F) + claripy.ZeroExt(1, carry)
        flags = claripy.BVV(0x02, 8)
        flags |= claripy.If(result == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        flags |= claripy.If(
            low_left.ULT(low_right),
            claripy.BVV(0x10, 8),
            claripy.BVV(0, 8),
        )
        flags |= claripy.If(
            extended_left.ULT(extended_right),
            claripy.BVV(1, 8),
            claripy.BVV(0, 8),
        )
        self.state.regs.a = result
        self.state.regs.f = flags
        self.jump(self._next_address)


class Sm83AdcRegister(angr.SimProcedure):
    """Correct SM83 ``ADC A, r`` semantics and flags."""

    def __init__(self, register: str, next_address: int) -> None:
        super().__init__()
        self._register = register
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        left = self.state.regs.a
        right = getattr(self.state.regs, self._register)
        carry = self.state.regs.f & 1
        wide = (
            claripy.ZeroExt(1, left)
            + claripy.ZeroExt(1, right)
            + claripy.ZeroExt(1, carry)
        )
        low_wide = (
            claripy.ZeroExt(1, left & 0x0F)
            + claripy.ZeroExt(1, right & 0x0F)
            + claripy.ZeroExt(1, carry)
        )
        result = wide[7:0]
        flags = claripy.If(result == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        flags |= claripy.If(
            low_wide > 0x0F, claripy.BVV(0x10, 8), claripy.BVV(0, 8)
        )
        flags |= claripy.ZeroExt(7, wide[8])
        self.state.regs.a = result
        self.state.regs.f = flags
        self.jump(self._next_address)


class Sm83CpImmediate(angr.SimProcedure):
    """Correct SM83 comparison flags for an 8-bit immediate operand."""

    def __init__(self, immediate: int, next_address: int) -> None:
        super().__init__()
        self._immediate = immediate
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        left = self.state.regs.a
        right = claripy.BVV(self._immediate, 8)
        result = left - right

        flags = claripy.BVV(0x02, 8)  # Z80 N
        flags |= claripy.If(result == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        flags |= claripy.If(
            (left & 0x0F).ULT(right & 0x0F),
            claripy.BVV(0x10, 8),
            claripy.BVV(0, 8),
        )
        flags |= claripy.If(left.ULT(right), claripy.BVV(0x01, 8), claripy.BVV(0, 8))

        self.state.regs.f = flags
        self.jump(self._next_address)


class Sm83CpRegister(angr.SimProcedure):
    """Correct SM83 comparison flags for an 8-bit register operand."""

    def __init__(self, register: str, next_address: int) -> None:
        super().__init__()
        self._register = register
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        left = self.state.regs.a
        right = getattr(self.state.regs, self._register)
        result = left - right

        flags = claripy.BVV(0x02, 8)  # Z80 N
        flags |= claripy.If(result == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        flags |= claripy.If(
            (left & 0x0F).ULT(right & 0x0F),
            claripy.BVV(0x10, 8),
            claripy.BVV(0, 8),
        )
        flags |= claripy.If(left.ULT(right), claripy.BVV(0x01, 8), claripy.BVV(0, 8))

        self.state.regs.f = flags
        self.jump(self._next_address)


class Sm83BitRegister(angr.SimProcedure):
    """Correct SM83 ``BIT n, r`` flags while preserving carry."""

    def __init__(self, bit: int, register: str, next_address: int) -> None:
        super().__init__()
        self._bit = bit
        self._register = register
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        value = getattr(self.state.regs, self._register)
        flags = (self.state.regs.f & 1) | claripy.BVV(0x10, 8)  # Z80 C and H
        flags |= claripy.If(
            value & (1 << self._bit) == 0,
            claripy.BVV(0x40, 8),
            claripy.BVV(0, 8),
        )
        self.state.regs.f = flags
        self.jump(self._next_address)


class Sm83BitAtHl(angr.SimProcedure):
    """Correct SM83 ``BIT n, [HL]`` flags while preserving carry."""

    def __init__(self, bit: int, next_address: int) -> None:
        super().__init__()
        self._bit = bit
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        value = self.state.memory.load(self.state.regs.hl, 1)
        flags = (self.state.regs.f & 1) | claripy.BVV(0x10, 8)
        flags |= claripy.If(
            value & (1 << self._bit) == 0,
            claripy.BVV(0x40, 8),
            claripy.BVV(0, 8),
        )
        self.state.regs.f = flags
        self.jump(self._next_address)


class Sm83ResAtHl(angr.SimProcedure):
    """Correct SM83 ``RES n, [HL]`` without affecting flags."""

    def __init__(self, bit: int, next_address: int) -> None:
        super().__init__()
        self._bit = bit
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        value = self.state.memory.load(self.state.regs.hl, 1)
        self.state.memory.store(self.state.regs.hl, value & ~(1 << self._bit))
        self.jump(self._next_address)


class Sm83SetAtHl(angr.SimProcedure):
    """Correct SM83 ``SET n, [HL]`` without affecting flags."""

    def __init__(self, bit: int, next_address: int) -> None:
        super().__init__()
        self._bit = bit
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        value = self.state.memory.load(self.state.regs.hl, 1)
        self.state.memory.store(self.state.regs.hl, value | (1 << self._bit))
        self.jump(self._next_address)


class Sm83StoreAImmediate(angr.SimProcedure):
    """Implement SM83 ``LD [a16], A`` (opcode EA), absent from the Z80."""

    def __init__(self, address: int, next_address: int) -> None:
        super().__init__()
        self._address = address
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(self._address, self.state.regs.a)
        self.jump(self._next_address)


class Sm83LoadAImmediate(angr.SimProcedure):
    """Implement SM83 ``LD A,[a16]`` (opcode FA), absent from the Z80."""

    def __init__(self, address: int, next_address: int) -> None:
        super().__init__()
        self._address = address
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self._address, 1)
        self.jump(self._next_address)


class Sm83LoadAFromImmediate(angr.SimProcedure):
    """Implement SM83 ``LD A, n`` (opcode 3E): load the immediate into A and
    clear Z/N/H/C. The Z80 pcode backend sets H here, which SM83 does not."""

    def __init__(self, immediate_address: int, next_address: int) -> None:
        super().__init__()
        self._immediate_address = immediate_address
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self._immediate_address, 1)
        self.state.regs.f = claripy.BVV(0, 8)
        self.jump(self._next_address)


class Sm83LoadAFromRegister(angr.SimProcedure):
    """Implement SM83 ``LD A, r`` (opcodes 78-7F) for a register operand:
    load the source register into A and clear Z/N/H/C. The Z80 pcode backend
    leaves/modifies flags incorrectly (e.g. sets C) for register loads, which
    SM83 does not do."""

    def __init__(self, source_register: str, next_address: int) -> None:
        super().__init__()
        self._source_register = source_register
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = getattr(self.state.regs, self._source_register)
        self.state.regs.f = claripy.BVV(0, 8)
        self.jump(self._next_address)


class Sm83StoreAHighImmediate(Sm83StoreAImmediate):
    """Implement SM83 ``LDH [a8], A`` (opcode E0), absent from the Z80."""

    def __init__(self, offset: int, next_address: int) -> None:
        super().__init__(address=0xFF00 | offset, next_address=next_address)


class Sm83LoadAHighImmediate(Sm83LoadAImmediate):
    """Implement SM83 ``LDH A,[a8]`` (opcode F0), absent from the Z80."""

    def __init__(self, offset: int, next_address: int) -> None:
        super().__init__(address=0xFF00 | offset, next_address=next_address)


class Sm83LoadAAtHlIncrement(angr.SimProcedure):
    """Implement SM83 ``LD A,[HL+]`` (opcode 2A), absent from the Z80."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self.state.regs.hl, 1)
        self.state.regs.hl = self.state.regs.hl + 1
        self.jump(self._next_address)


class Sm83LoadAAtHlDecrement(angr.SimProcedure):
    """Implement SM83 ``LD A,[HL-]`` (opcode 3A), absent from the Z80."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self.state.regs.hl, 1)
        self.state.regs.hl = self.state.regs.hl - 1
        self.jump(self._next_address)


class Sm83StoreAAtHlIncrement(angr.SimProcedure):
    """Implement SM83 ``LD [HL+],A`` (opcode 22), absent from the Z80."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(self.state.regs.hl, self.state.regs.a)
        self.state.regs.hl = self.state.regs.hl + 1
        self.jump(self._next_address)


class Sm83StoreAAtHlDecrement(angr.SimProcedure):
    """Implement SM83 ``LD [HL-],A`` (opcode 32), absent from the Z80."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(self.state.regs.hl, self.state.regs.a)
        self.state.regs.hl = self.state.regs.hl - 1
        self.jump(self._next_address)


class Sm83DecRegister(angr.SimProcedure):
    """Correct SM83 ``DEC r`` flags while preserving carry."""

    def __init__(self, register: str, next_address: int) -> None:
        super().__init__()
        self._register = register
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        value = getattr(self.state.regs, self._register)
        result = value - 1
        flags = self.state.regs.f & 0x01  # preserve Z80-layout carry
        flags |= claripy.BVV(0x02, 8)  # N
        flags |= claripy.If(result == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        flags |= claripy.If(
            (value & 0x0F) == 0,
            claripy.BVV(0x10, 8),
            claripy.BVV(0, 8),
        )
        setattr(self.state.regs, self._register, result)
        self.state.regs.f = flags
        self.jump(self._next_address)


class Sm83DecAtHl(angr.SimProcedure):
    """Correct SM83 ``DEC [HL]`` flags while preserving carry."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        value = self.state.memory.load(self.state.regs.hl, 1)
        result = value - 1
        flags = self.state.regs.f & 0x01  # preserve Z80-layout carry
        flags |= claripy.BVV(0x02, 8)  # N
        flags |= claripy.If(result == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        flags |= claripy.If(
            (value & 0x0F) == 0,
            claripy.BVV(0x10, 8),
            claripy.BVV(0, 8),
        )
        self.state.memory.store(self.state.regs.hl, result)
        self.state.regs.f = flags
        self.jump(self._next_address)


class Sm83IncRegister(angr.SimProcedure):
    """Correct SM83 ``INC r`` flags while preserving carry."""

    def __init__(self, register: str, next_address: int) -> None:
        super().__init__()
        self._register = register
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        value = getattr(self.state.regs, self._register)
        result = value + 1
        flags = self.state.regs.f & 0x01  # preserve Z80-layout carry
        flags |= claripy.If(result == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        flags |= claripy.If(
            (value & 0x0F) == 0x0F,
            claripy.BVV(0x10, 8),
            claripy.BVV(0, 8),
        )
        setattr(self.state.regs, self._register, result)
        self.state.regs.f = flags
        self.jump(self._next_address)


class Sm83SrlRegister(angr.SimProcedure):
    """Correct SM83 ``SRL r`` result and flags."""

    def __init__(self, register: str, next_address: int) -> None:
        super().__init__()
        self._register = register
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        value = getattr(self.state.regs, self._register)
        result = claripy.LShR(value, 1)
        flags = claripy.If(result == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        flags |= claripy.ZeroExt(7, value[0])
        setattr(self.state.regs, self._register, result)
        self.state.regs.f = flags
        self.jump(self._next_address)


class Sm83SwapRegister(angr.SimProcedure):
    """Correct SM83 ``SWAP r`` semantics for Z80 p-code opcode collisions."""

    def __init__(self, register: str, next_address: int) -> None:
        super().__init__()
        self._register = register
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        value = getattr(self.state.regs, self._register)
        result = (value << 4) | (value >> 4)
        setattr(self.state.regs, self._register, result)
        self.state.regs.f = claripy.If(
            result == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)
        )
        self.jump(self._next_address)


class Sm83SlaRegister(angr.SimProcedure):
    """Correct SM83 ``SLA r`` result and flags."""

    def __init__(self, register: str, next_address: int) -> None:
        super().__init__()
        self._register = register
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        value = getattr(self.state.regs, self._register)
        result = value << 1
        flags = claripy.If(result == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        flags |= claripy.ZeroExt(7, value[7])
        setattr(self.state.regs, self._register, result)
        self.state.regs.f = flags
        self.jump(self._next_address)


class Sm83SwapAtHl(angr.SimProcedure):
    """Implement SM83 ``SWAP [HL]``, whose CB opcode differs from the Z80."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        value = self.state.memory.load(self.state.regs.hl, 1)
        result = (value << 4) | claripy.LShR(value, 4)
        self.state.memory.store(self.state.regs.hl, result)
        self.state.regs.f = claripy.If(
            result == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)
        )
        self.jump(self._next_address)


class Sm83SraRegister(angr.SimProcedure):
    """Correct SM83 ``SRA r`` result and flags."""

    def __init__(self, register: str, next_address: int) -> None:
        super().__init__()
        self._register = register
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        value = getattr(self.state.regs, self._register)
        result = claripy.Concat(value[7], value[7:1])
        flags = claripy.If(result == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        flags |= claripy.ZeroExt(7, value[0])
        setattr(self.state.regs, self._register, result)
        self.state.regs.f = flags
        self.jump(self._next_address)


class Sm83RlRegister(angr.SimProcedure):
    """Correct SM83 ``RL r`` result and flags."""

    def __init__(self, register: str, next_address: int) -> None:
        super().__init__()
        self._register = register
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        value = getattr(self.state.regs, self._register)
        carry_in = self.state.regs.f[0]
        result = claripy.Concat(value[6:0], carry_in)
        flags = claripy.If(result == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        flags |= claripy.ZeroExt(7, value[7])
        setattr(self.state.regs, self._register, result)
        self.state.regs.f = flags
        self.jump(self._next_address)


class Sm83RrRegister(angr.SimProcedure):
    """Correct SM83 ``RR r`` result and flags."""

    def __init__(self, register: str, next_address: int) -> None:
        super().__init__()
        self._register = register
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        value = getattr(self.state.regs, self._register)
        carry_in = self.state.regs.f[0]
        result = claripy.Concat(carry_in, value[7:1])
        flags = claripy.If(result == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        flags |= claripy.ZeroExt(7, value[0])
        setattr(self.state.regs, self._register, result)
        self.state.regs.f = flags
        self.jump(self._next_address)


class Sm83Rrca(angr.SimProcedure):
    """Correct SM83 ``RRCA`` semantics (Z is always cleared)."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        value = self.state.regs.a
        self.state.regs.a = claripy.RotateRight(value, 1)
        self.state.regs.f = claripy.ZeroExt(7, value[0])
        self.jump(self._next_address)


class Sm83Rlca(angr.SimProcedure):
    """Correct SM83 ``RLCA`` semantics (Z is always cleared)."""

    def __init__(self, next_address: int) -> None:
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        value = self.state.regs.a
        self.state.regs.a = claripy.RotateLeft(value, 1)
        self.state.regs.f = claripy.ZeroExt(7, value[7])
        self.jump(self._next_address)


class Sm83SwapRegister(angr.SimProcedure):
    """Implement SM83 ``SWAP r``, whose CB opcode differs from the Z80."""

    def __init__(self, register: str, next_address: int) -> None:
        super().__init__()
        self._register = register
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        value = getattr(self.state.regs, self._register)
        result = (value << 4) | claripy.LShR(value, 4)
        flags = claripy.If(result == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
        setattr(self.state.regs, self._register, result)
        self.state.regs.f = flags
        self.jump(self._next_address)
