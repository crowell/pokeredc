from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
    REGISTERS,
    assembly_registers,
    native_registers,
    set_assembly_registers,
    store_native_registers,
    symbolic_registers,
)
from verification.harness.rom import linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import (
    Sm83LoadAAtHlIncrement,
    Sm83LoadAHighImmediate,
    Sm83RrRegister,
    Sm83SrlRegister,
    Sm83StoreAImmediate,
    Sm83StoreAHighImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF
HP = 0xCFE6
TEXT_BOX_ID = 0xD125
MAX_HP = 0xCFF4
LAST_SWITCH = 0xCCE3
H_PRODUCT = 0xFF95
H_DIVISOR = 0xFF99
EXPECTED = bytes.fromhex(
    "21e6cf2ab621ae4e2848afe09621e6cf2aeae3cce0977eeae4cce0983e19e099"
    "cdac3821f4cf2a46cb3fcb18cb3fcb18780604e099cdb938f09821ae4efe4630"
    "1121b54efe28300a21bc4efe0a300321c34ec3493c17bc5c2208181317c35c22"
    "08180c17cd5c2208180517d65c22"
)


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
    text_box_id: claripy.ast.BV
    last_switch: claripy.ast.BV
    product: claripy.ast.BV
    divisor: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class SetupHP(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = claripy.BVV(0xCF, 8)
        self.state.regs.l = claripy.BVV(0xE6, 8)
        self.jump(self.state.addr + 3)


class OrAtHL(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.regs.a | self.state.memory.load(self.state.regs.hl, 1)
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0, claripy.BVV(0x40, 8), claripy.BVV(0, 8)
        )
        self.jump(self.state.addr + 1)


class SetupGoHL(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = claripy.BVV(0x4E, 8)
        self.state.regs.l = claripy.BVV(0xAE, 8)
        self.jump(self.state.addr + 3)


class SetupMaxHL(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.h = claripy.BVV(0xCF, 8)
        self.state.regs.l = claripy.BVV(0xF4, 8)
        self.jump(self.state.addr + 3)


class XorA(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(0, 8)
        self.state.regs.f = claripy.BVV(0x40, 8)
        self.jump(self.state.addr + 1)


class LoadAAtHL(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.memory.load(self.state.regs.hl, 1)
        self.jump(self.state.addr + 1)


class LoadAImmediate(angr.SimProcedure):
    def __init__(self, value: int) -> None:
        super().__init__()
        self.value = value

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = claripy.BVV(self.value, 8)
        self.jump(self.state.addr + 2)


class PrintBranch(angr.SimProcedure):
    def __init__(self, nonzero: int) -> None:
        super().__init__()
        self.nonzero = nonzero

    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        zero = self.state.regs.a == 0
        for is_zero in (True, False):
            successor = self.state.copy()
            successor.add_constraints(zero if is_zero else ~zero)
            if is_zero:
                successor.memory.store(TEXT_BOX_ID, claripy.BVV(1, 8))
                successor.regs.b = claripy.BVV(0xC4, 8)
                successor.regs.c = claripy.BVV(0xB9, 8)
                target = DONE
            else:
                target = self.nonzero
            self.successors.add_successor(
                successor, target, claripy.BoolV(True), "Ijk_Boring"
            )


class LoadBAtHL(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.b = self.state.memory.load(self.state.regs.hl, 1)
        self.jump(self.state.addr + 1)


class LoadAFromB(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.regs.b
        self.jump(self.state.addr + 1)


class LoadBImmediate(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.b = claripy.BVV(4, 8)
        self.jump(self.state.addr + 2)


class MultiplyBoundary(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        multiplicand = self.state.memory.load(0xFF96, 3)
        multiplier = self.state.memory.load(0xFF99, 1)
        product = claripy.ZeroExt(8, multiplicand) * claripy.ZeroExt(24, multiplier)
        self.state.memory.store(H_PRODUCT, product)
        self.state.memory.store(0xFF99, claripy.BVV(0, 8))
        self.jump(self.continuation)


class DivideBoundary(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        dividend = self.state.memory.load(H_PRODUCT, 4)
        divisor = self.state.memory.load(H_DIVISOR, 1)
        quotient = claripy.If(divisor == 0, claripy.BVV(0, 32), dividend // claripy.ZeroExt(24, divisor))
        remainder = claripy.If(
            divisor == 0,
            claripy.BVV(0, 8),
            claripy.Extract(7, 0, dividend % claripy.ZeroExt(24, divisor)),
        )
        self.state.memory.store(H_PRODUCT, quotient)
        self.state.memory.store(H_DIVISOR, remainder)
        self.jump(self.continuation)


class SelectPercentage(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self.continuation = continuation

    @staticmethod
    def cp_flags(left: claripy.ast.BV, right: int) -> claripy.ast.BV:
        return (
            claripy.BVV(0x02, 8)
            | claripy.If(left == right, claripy.BVV(0x40, 8), claripy.BVV(0, 8))
            | claripy.If((left & 0x0F) < (right & 0x0F), claripy.BVV(0x10, 8), claripy.BVV(0, 8))
            | claripy.If(left < right, claripy.BVV(0x01, 8), claripy.BVV(0, 8))
        )

    def run(self) -> None:  # type: ignore[override]
        percentage = self.state.regs.a
        cases = (
            (percentage >= 70, 0x4EAE, 70),
            ((percentage < 70) & (percentage >= 40), 0x4EB5, 40),
            ((percentage < 40) & (percentage >= 10), 0x4EBC, 10),
            (percentage < 10, 0x4EC3, 10),
        )
        for condition, pointer, threshold in cases:
            successor = self.state.copy()
            successor.add_constraints(condition)
            successor.regs.h = claripy.BVV(pointer >> 8, 8)
            successor.regs.l = claripy.BVV(pointer & 0xFF, 8)
            successor.regs.f = self.cp_flags(percentage, threshold)
            self.successors.add_successor(
                successor, self.continuation, claripy.BoolV(True), "Ijk_Boring"
            )
        self.inhibit_autoret = True


class PrintTextBoundary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(TEXT_BOX_ID, claripy.BVV(1, 8))
        self.state.regs.b = claripy.BVV(0xC4, 8)
        self.state.regs.c = claripy.BVV(0xB9, 8)
        self.inhibit_autoret = True
        self.jump(DONE)


def _assembly(values: dict[str, claripy.ast.BV], *, max_hp: int) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "PrintSendOutMonMessage")
    base = location.address
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    project = angr.Project(
        rom_window(ROM, location.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": base,
        },
    )
    project.hook(base, SetupHP(), length=3)
    project.hook(base + 3, Sm83LoadAAtHlIncrement(base + 4), length=1)
    project.hook(base + 4, OrAtHL(), length=1)
    project.hook(base + 5, SetupGoHL(), length=3)
    project.hook(base + 8, PrintBranch(base + 10), length=2)
    project.hook(base + 10, XorA(), length=1)
    project.hook(base + 11, Sm83StoreAHighImmediate(0x96, base + 13), length=2)
    project.hook(base + 13, SetupHP(), length=3)
    project.hook(base + 16, Sm83LoadAAtHlIncrement(base + 17), length=1)
    project.hook(base + 17, Sm83StoreAImmediate(LAST_SWITCH, base + 20), length=3)
    project.hook(base + 20, Sm83StoreAHighImmediate(0x97, base + 22), length=2)
    project.hook(base + 22, LoadAAtHL(), length=1)
    project.hook(base + 23, Sm83StoreAImmediate(LAST_SWITCH + 1, base + 26), length=3)
    project.hook(base + 26, Sm83StoreAHighImmediate(0x98, base + 28), length=2)
    project.hook(base + 28, LoadAImmediate(25), length=2)
    project.hook(base + 30, Sm83StoreAHighImmediate(0x99, base + 32), length=2)
    project.hook(base + 32, MultiplyBoundary(base + 35), length=3)
    project.hook(base + 35, SetupMaxHL(), length=3)
    project.hook(base + 38, Sm83LoadAAtHlIncrement(base + 39), length=1)
    project.hook(base + 39, LoadBAtHL(), length=1)
    project.hook(base + 40, Sm83SrlRegister("a", base + 42), length=2)
    project.hook(base + 42, Sm83RrRegister("b", base + 44), length=2)
    project.hook(base + 44, Sm83SrlRegister("a", base + 46), length=2)
    project.hook(base + 46, Sm83RrRegister("b", base + 48), length=2)
    project.hook(base + 48, LoadAFromB(), length=1)
    project.hook(base + 49, LoadBImmediate(), length=2)
    project.hook(base + 51, Sm83StoreAHighImmediate(0x99, base + 53), length=2)
    project.hook(base + 53, DivideBoundary(base + 56), length=3)
    project.hook(base + 56, Sm83LoadAHighImmediate(0x98, base + 58), length=2)
    project.hook(base + 58, SetupGoHL(), length=3)
    project.hook(base + 61, SelectPercentage(base + 82), length=2)
    project.hook(base + 82, PrintTextBoundary(), length=3)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.memory.store(HP, values["hp_low"])
    state.memory.store(HP + 1, values["hp_high"])
    state.memory.store(MAX_HP, claripy.BVV(max_hp >> 8, 8))
    state.memory.store(MAX_HP + 1, claripy.BVV(max_hp & 0xFF, 8))
    state.memory.store(LAST_SWITCH, claripy.BVV(0, 16), endness="Iend_LE")
    state.memory.store(TEXT_BOX_ID, claripy.BVV(0, 8))
    for address in range(0xFF95, 0xFFA0):
        state.memory.store(address, claripy.BVV(0, 8))
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE, num_find=1)
    assert not manager.errored
    return [
        Endpoint(
            **assembly_registers(end),
            text_box_id=end.memory.load(TEXT_BOX_ID, 1),
            last_switch=end.memory.load(LAST_SWITCH, 2),
            product=end.memory.load(H_PRODUCT, 4),
            divisor=end.memory.load(H_DIVISOR, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.found
    ]


def _native(values: dict[str, claripy.ast.BV], *, max_hp: int) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_print_send_out_mon_message")
    assert function is not None
    state = project.factory.call_state(function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, values["hp_low"])
    state.memory.store(NATIVE_STATE + 9, values["hp_high"])
    state.memory.store(NATIVE_MEMORY + MAX_HP, claripy.BVV(max_hp >> 8, 8))
    state.memory.store(NATIVE_MEMORY + MAX_HP + 1, claripy.BVV(max_hp & 0xFF, 8))
    state.memory.store(NATIVE_MEMORY + LAST_SWITCH, claripy.BVV(0, 16), endness="Iend_LE")
    state.memory.store(NATIVE_MEMORY + TEXT_BOX_ID, claripy.BVV(0, 8))
    for address in range(0xFF95, 0xFFA0):
        state.memory.store(NATIVE_MEMORY + address, claripy.BVV(0, 8))
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            text_box_id=end.memory.load(NATIVE_MEMORY + TEXT_BOX_ID, 1),
            last_switch=end.memory.load(NATIVE_MEMORY + LAST_SWITCH, 2),
            product=end.memory.load(NATIVE_MEMORY + H_PRODUCT, 4),
            divisor=end.memory.load(NATIVE_MEMORY + H_DIVISOR, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run make -C verification native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run make red")
@pytest.mark.parametrize(
    ("hp_low", "hp_high"),
    ((0x00, 0x00), (0x02, 0xBC), (0x01, 0xF4), (0x00, 0xC8), (0x00, 0x32)),
)
def test_print_send_out_mon_message_entry_pathwise_equivalence(
    hp_low: int, hp_high: int,
) -> None:
    values = symbolic_registers("print_send_out_mon_message")
    values["hp_low"] = claripy.BVV(hp_low, 8)
    values["hp_high"] = claripy.BVV(hp_high, 8)
    assert_pathwise_equivalent(
        _assembly(values, max_hp=1000), _native(values, max_hp=1000),
        (*REGISTERS, "text_box_id", "last_switch", "product", "divisor"),
    )
