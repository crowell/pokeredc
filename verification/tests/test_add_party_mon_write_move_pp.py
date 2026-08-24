from __future__ import annotations

from dataclasses import dataclass
from functools import cache
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
from verification.harness.rom import (
    linked_bytes,
    rom_window,
    sm83_flags_to_z80,
    symbol_location,
)
from verification.harness.sm83_shims import (
    Sm83DecRegister,
    Sm83LoadAAtHlIncrement,
    Sm83LoadAImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xFF80
RETURN = 0xFFFF
W_MOVE_DATA = 0xCD6D
W_MOVE_DATA_PP = W_MOVE_DATA + 5
MOVE_LENGTH = 0x06
EXECUTING_BANK = 0x03
EXPECTED = bytes.fromhex(
    "06042aa7281b3de5d5c5210040010600cd873a116dcd3e0ecd9d00c1d1e1"
    "fa72cd13120520dcc9"
)
SNAPSHOT_BITS = 8 * len(REGISTERS)

# The three distinct real-caller memory topologies. Other party slots are a
# constant PARTYMON_STRUCT_LENGTH translation and execute the same addressing
# recurrence with the same non-aliasing relationship.
CALLER_LAYOUTS = (
    pytest.param(0xD173, 0xD187, id="add-party-mon"),
    pytest.param(0xD173, 0xCD77, id="restore-bonus-pp"),
    pytest.param(0xCFED, 0xCFFD, id="battle-load-move-pps"),
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
    moves: claripy.ast.BV
    pp: claripy.ast.BV
    move_data: claripy.ast.BV
    banks: claripy.ast.BV
    add_calls: claripy.ast.BV
    far_calls: claripy.ast.BV
    call_counts: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class Sm83AndA(angr.SimProcedure):
    """Exact SM83 AND A flags in the Z80 p-code flag layout."""

    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x50, 8),
            claripy.BVV(0x10, 8),
        )
        self.jump(self._continuation)


class Sm83JrNz(angr.SimProcedure):
    """Exact concrete JR NZ used after the loop's concrete DEC B."""

    def __init__(self, target: int, continuation: int) -> None:
        super().__init__()
        self._target = target
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        zero = (self.state.regs.f & 0x40)[6:6]
        assert not zero.symbolic
        self.jump(
            self._continuation
            if self.state.solver.eval(zero) != 0
            else self._target
        )


class Sm83JrZ(angr.SimProcedure):
    """Exact JR Z; each proof case constrains the move's empty/nonempty class."""

    def __init__(self, target: int, continuation: int) -> None:
        super().__init__()
        self._target = target
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        zero = (self.state.regs.f & 0x40)[6:6]
        can_jump = self.state.solver.satisfiable(extra_constraints=(zero == 1,))
        can_continue = self.state.solver.satisfiable(
            extra_constraints=(zero == 0,)
        )
        assert can_jump != can_continue
        self.jump(self._target if can_jump else self._continuation)


def _add_n_times_result(
    a: claripy.ast.BV, bc: claripy.ast.BV, hl: claripy.ast.BV
) -> tuple[claripy.ast.BV, claripy.ast.BV]:
    a_wide = claripy.ZeroExt(16, a)
    bc_wide = claripy.ZeroExt(8, bc)
    hl_wide = claripy.ZeroExt(8, hl)
    total = hl_wide + a_wide * bc_wide
    previous = (
        claripy.ZeroExt(8, hl)
        + claripy.ZeroExt(16, a - 1) * bc_wide
    )[15:0]
    last_add = claripy.ZeroExt(16, previous) + claripy.ZeroExt(16, bc)
    carry = claripy.If(
        last_add > 0xFFFF, claripy.BVV(0x10, 8), claripy.BVV(0, 8)
    )
    flags = claripy.If(
        a == 0,
        claripy.BVV(0xA0, 8),
        claripy.BVV(0xC0, 8) | carry,
    )
    return total[15:0], flags


def _capture_registers(state: angr.SimState) -> claripy.ast.BV:
    registers = assembly_registers(state)
    return claripy.Concat(*(registers[name] for name in REGISTERS))


class AssemblyAddNTimes(angr.SimProcedure):
    """Complete transition of the independently proven AddNTimes callee."""

    def run(self) -> None:  # type: ignore[override]
        site = self.state.globals["add_count"]
        self.state.globals["add_count"] += 1
        self.state.globals[f"add_call_{site}"] = _capture_registers(self.state)
        registers = assembly_registers(self.state)
        hl, flags = _add_n_times_result(
            registers["a"],
            claripy.Concat(registers["b"], registers["c"]),
            claripy.Concat(registers["h"], registers["l"]),
        )
        self.state.regs.a = 0
        self.state.regs.f = sm83_flags_to_z80(flags)
        self.state.regs.hl = hl
        return_address = self.state.memory.load(
            self.state.regs.sp, 2, endness="Iend_LE"
        )
        self.state.regs.sp += 2
        self.jump(return_address)


class NativeAddNTimes(angr.SimProcedure):
    def run(self, state_address: claripy.ast.BV) -> None:  # type: ignore[override]
        site = self.state.globals["add_count"]
        self.state.globals["add_count"] += 1
        self.state.globals[f"add_call_{site}"] = self.state.memory.load(
            state_address, 8
        )
        a = self.state.memory.load(state_address, 1)
        bc = claripy.Concat(
            self.state.memory.load(state_address + 2, 1),
            self.state.memory.load(state_address + 3, 1),
        )
        hl_before = claripy.Concat(
            self.state.memory.load(state_address + 6, 1),
            self.state.memory.load(state_address + 7, 1),
        )
        hl_after, flags = _add_n_times_result(a, bc, hl_before)
        self.state.memory.store(state_address, claripy.BVV(0, 8))
        self.state.memory.store(state_address + 1, flags)
        self.state.memory.store(state_address + 6, hl_after[15:8])
        self.state.memory.store(state_address + 7, hl_after[7:0])


class AssemblyFarCopyData(angr.SimProcedure):
    """Complete transition of the independently proven FarCopyData callee."""

    def run(self) -> None:  # type: ignore[override]
        site = self.state.globals["far_count"]
        self.state.globals["far_count"] += 1
        self.state.globals[f"far_call_{site}"] = _capture_registers(self.state)
        original_f = self.state.regs.f
        original_bank = self.state.globals["loaded_bank"]
        self.state.globals["requested_bank"] = self.state.regs.a
        self.state.regs.a = original_bank
        self.state.regs.f = original_f
        for register in ("b", "c", "d", "e", "h", "l"):
            setattr(
                self.state.regs,
                register,
                self.state.globals[f"copy_{site}_{register}"],
            )
        for offset in range(MOVE_LENGTH):
            self.state.memory.store(
                W_MOVE_DATA + offset,
                self.state.globals[f"copy_{site}_{offset}"],
            )
        return_address = self.state.memory.load(
            self.state.regs.sp, 2, endness="Iend_LE"
        )
        self.state.regs.sp += 2
        self.jump(return_address)


class NativeFarCopyData(angr.SimProcedure):
    def run(
        self, state_address: claripy.ast.BV, memory: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        site = self.state.globals["far_count"]
        self.state.globals["far_count"] += 1
        self.state.globals[f"far_call_{site}"] = self.state.memory.load(
            state_address, 8
        )
        requested_bank = self.state.memory.load(state_address, 1)
        original_bank = self.state.memory.load(state_address + 9, 1)
        self.state.memory.store(state_address, original_bank)
        self.state.memory.store(state_address + 8, requested_bank)
        for offset, register in enumerate(("b", "c", "d", "e", "h", "l"), 2):
            self.state.memory.store(
                state_address + offset,
                self.state.globals[f"copy_{site}_{register}"],
            )
        for offset in range(MOVE_LENGTH):
            self.state.memory.store(
                memory + W_MOVE_DATA + offset,
                self.state.globals[f"copy_{site}_{offset}"],
            )


def _inputs(prefix: str, moves: int, destination: int) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["h"] = claripy.BVV(moves >> 8, 8)
    values["l"] = claripy.BVV(moves & 0xFF, 8)
    values["d"] = claripy.BVV(destination >> 8, 8)
    values["e"] = claripy.BVV(destination & 0xFF, 8)
    values["requested_bank"] = claripy.BVS(f"{prefix}_requested_bank", 8)
    values["loaded_bank"] = claripy.BVV(EXECUTING_BANK, 8)
    values["rom_bank"] = claripy.BVV(EXECUTING_BANK, 8)
    for index in range(4):
        values[f"move_{index}"] = claripy.BVS(f"{prefix}_move_{index}", 8)
        values[f"pp_{index}"] = claripy.BVS(f"{prefix}_pp_{index}", 8)
    for offset in range(MOVE_LENGTH):
        values[f"move_data_{offset}"] = claripy.BVS(
            f"{prefix}_move_data_{offset}", 8
        )
    for site in range(4):
        for register in ("b", "c", "d", "e", "h", "l"):
            values[f"copy_{site}_{register}"] = claripy.BVS(
                f"{prefix}_copy_{site}_{register}", 8
            )
        for offset in range(MOVE_LENGTH):
            values[f"copy_{site}_{offset}"] = claripy.BVS(
                f"{prefix}_copy_{site}_{offset}", 8
            )
    return values


def _setup(
    state: angr.SimState,
    values: dict[str, claripy.ast.BV],
    moves: int,
    destination: int,
    empty_mask: int,
    native: bool,
) -> None:
    memory_base = NATIVE_MEMORY if native else 0
    for index in range(4):
        move = values[f"move_{index}"]
        state.memory.store(memory_base + moves + index, move)
        state.memory.store(
            memory_base + destination + 1 + index, values[f"pp_{index}"]
        )
        state.add_constraints(
            move == 0 if empty_mask & (1 << index) else move != 0
        )
    for offset in range(MOVE_LENGTH):
        state.memory.store(
            memory_base + W_MOVE_DATA + offset,
            values[f"move_data_{offset}"],
        )
    for field in ("requested_bank", "loaded_bank", "rom_bank"):
        state.globals[field] = values[field]
    state.globals["add_count"] = 0
    state.globals["far_count"] = 0
    for site in range(4):
        state.globals[f"add_call_{site}"] = None
        state.globals[f"far_call_{site}"] = None
        for register in ("b", "c", "d", "e", "h", "l"):
            state.globals[f"copy_{site}_{register}"] = values[
                f"copy_{site}_{register}"
            ]
        for offset in range(MOVE_LENGTH):
            state.globals[f"copy_{site}_{offset}"] = values[
                f"copy_{site}_{offset}"
            ]


def _trace(state: angr.SimState, name: str) -> claripy.ast.BV:
    return claripy.Concat(
        *(
            state.globals[f"{name}_call_{site}"]
            if state.globals[f"{name}_call_{site}"] is not None
            else claripy.BVV(0, SNAPSHOT_BITS)
            for site in range(4)
        )
    )


def _endpoint(
    state: angr.SimState, moves: int, destination: int, native: bool
) -> Endpoint:
    memory_base = NATIVE_MEMORY if native else 0
    registers = (
        native_registers(state, NATIVE_STATE)
        if native
        else assembly_registers(state)
    )
    banks = (
        state.memory.load(NATIVE_STATE + 8, 3)
        if native
        else claripy.Concat(
            state.globals["requested_bank"],
            state.globals["loaded_bank"],
            state.globals["rom_bank"],
        )
    )
    return Endpoint(
        **registers,
        moves=state.memory.load(memory_base + moves, 4),
        pp=state.memory.load(memory_base + destination + 1, 4),
        move_data=state.memory.load(memory_base + W_MOVE_DATA, MOVE_LENGTH),
        banks=banks,
        add_calls=_trace(state, "add"),
        far_calls=_trace(state, "far"),
        call_counts=claripy.Concat(
            claripy.BVV(state.globals["add_count"], 8),
            claripy.BVV(state.globals["far_count"], 8),
        ),
        constraints=tuple(state.solver.constraints),
    )


@cache
def _assembly_project() -> tuple[angr.Project, int]:
    location = symbol_location(SYMS, "AddPartyMon_WriteMovePP")
    assert linked_bytes(ROM, location, len(EXPECTED)) == EXPECTED
    project = angr.Project(
        rom_window(ROM, location.bank),
        auto_load_libs=False,
        rebase_granularity=0x100,
        main_opts={
            "backend": "blob",
            "arch": ArchPcode("z80:LE:16:default"),
            "base_addr": 0,
            "entry_point": location.address,
        },
    )
    base = location.address
    project.hook(base + 2, Sm83LoadAAtHlIncrement(base + 3), length=1)
    project.hook(base + 3, Sm83AndA(base + 4), length=1)
    project.hook(base + 4, Sm83JrZ(base + 33, base + 6), length=2)
    project.hook(base + 6, Sm83DecRegister("a", base + 7), length=1)
    project.hook(
        base + 30, Sm83LoadAImmediate(W_MOVE_DATA_PP, base + 33), length=3
    )
    project.hook(base + 35, Sm83DecRegister("b", base + 36), length=1)
    project.hook(base + 36, Sm83JrNz(base + 2, base + 38), length=2)
    add_n_times = symbol_location(SYMS, "AddNTimes")
    far_copy_data = symbol_location(SYMS, "FarCopyData")
    project.hook(add_n_times.address, AssemblyAddNTimes())
    project.hook(far_copy_data.address, AssemblyFarCopyData())
    return project, base


@cache
def _native_project() -> tuple[angr.Project, int]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_add_party_mon_write_move_pp")
    add_n_times = project.loader.find_symbol("port_add_n_times")
    far_copy_data = project.loader.find_symbol("port_far_copy_data")
    assert function is not None and add_n_times is not None and far_copy_data is not None
    project.hook(add_n_times.rebased_addr, NativeAddNTimes())
    project.hook(far_copy_data.rebased_addr, NativeFarCopyData())
    return project, function.rebased_addr


def _assembly(
    values: dict[str, claripy.ast.BV],
    moves: int,
    destination: int,
    empty_mask: int,
) -> list[Endpoint]:
    project, base = _assembly_project()
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _setup(state, values, moves, destination, empty_mask, False)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    manager = project.factory.simulation_manager(state)
    manager.explore(find=lambda end: end.addr == RETURN, num_find=2)
    assert not manager.errored and len(manager.found) == 1
    return [_endpoint(end, moves, destination, False) for end in manager.found]


def _native(
    values: dict[str, claripy.ast.BV],
    moves: int,
    destination: int,
    empty_mask: int,
) -> list[Endpoint]:
    project, function = _native_project()
    state = project.factory.call_state(function, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    for offset, field in enumerate(
        ("requested_bank", "loaded_bank", "rom_bank"), 8
    ):
        state.memory.store(NATIVE_STATE + offset, values[field])
    _setup(state, values, moves, destination, empty_mask, True)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [_endpoint(end, moves, destination, True) for end in manager.deadended]


@pytest.mark.skipif(
    not ELF.exists() or not ROM.exists() or not SYMS.exists(), reason="build"
)
@pytest.mark.parametrize("moves,destination", CALLER_LAYOUTS)
@pytest.mark.parametrize("empty_mask", range(16), ids=lambda mask: f"empty-{mask:x}")
def test_add_party_mon_write_move_pp_pathwise_equivalence(
    moves: int, destination: int, empty_mask: int
) -> None:
    prefix = f"add_party_mon_write_move_pp_{moves:04x}_{empty_mask:x}"
    values = _inputs(prefix, moves, destination)
    assert_pathwise_equivalent(
        _assembly(values, moves, destination, empty_mask),
        _native(values, moves, destination, empty_mask),
        (
            *REGISTERS,
            "moves",
            "pp",
            "move_data",
            "banks",
            "add_calls",
            "far_calls",
            "call_counts",
        ),
    )
