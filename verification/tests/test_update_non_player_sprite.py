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
from verification.harness.rom import (
    linked_bytes,
    rom_window,
    sm83_flags_to_z80,
    symbol_location,
)
from verification.harness.sm83_shims import (
    Sm83CpRegister,
    Sm83DecRegister,
    Sm83LoadAHighImmediate,
    Sm83LoadAImmediate,
    Sm83StoreAHighImmediate,
    Sm83SwapRegister,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xFFFF

SCRIPT_OFFSET = 0xCF17
CURRENT_OFFSET = 0xFFDA
PLAYER_TILE = 0xFF93
TRACE = 0xEF00
BODY = bytes.fromhex("3dcb37e093fa17cf47f0dab82003c33652c3d14e")


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


class CopyRegister(angr.SimProcedure):
    def __init__(self, destination: str, source: str, next_address: int) -> None:
        super().__init__()
        self.destination = destination
        self.source = source
        self.next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.destination, getattr(self.state.regs, self.source))
        self.jump(self.next_address)


class BranchNotZero(angr.SimProcedure):
    def __init__(self, taken: int, fallthrough: int) -> None:
        super().__init__()
        self.taken = taken
        self.fallthrough = fallthrough

    def run(self) -> None:  # type: ignore[override]
        condition = (self.state.regs.f & 0x40) == 0
        taken = self.state.copy()
        fallthrough = self.state.copy()
        taken.solver.add(condition)
        fallthrough.solver.add(~condition)
        taken.regs.ip = claripy.BVV(self.taken, 16)
        fallthrough.regs.ip = claripy.BVV(self.fallthrough, 16)
        self.inhibit_autoret = True
        self.successors.add_successor(
            taken, self.taken, condition, "Ijk_Boring"
        )
        self.successors.add_successor(
            fallthrough, self.fallthrough, ~condition, "Ijk_Boring"
        )


class AssemblyCalleeTransition(angr.SimProcedure):
    def __init__(
        self, outputs: dict[str, claripy.ast.BV], kind: int
    ) -> None:
        super().__init__()
        self.outputs = outputs
        self.kind = kind

    def run(self) -> None:  # type: ignore[override]
        for register in REGISTERS:
            value = self.outputs[register]
            if register == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, register, value)
        self.state.memory.store(TRACE + self.kind, self.outputs["effect"])
        self.jump(RETURN)


class NativeCalleeTransition(angr.SimProcedure):
    def __init__(
        self, outputs: dict[str, claripy.ast.BV], kind: int
    ) -> None:
        super().__init__()
        self.outputs = outputs
        self.kind = kind

    def run(
        self, registers: claripy.ast.BV, memory: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        for index, register in enumerate(REGISTERS):
            self.state.memory.store(registers + index, self.outputs[register])
        self.state.memory.store(memory + TRACE + self.kind, self.outputs["effect"])


def inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["script_offset"] = claripy.BVS(f"{prefix}_script_offset", 8)
    values["current_offset"] = claripy.BVS(f"{prefix}_current_offset", 8)
    values["player_tile"] = claripy.BVS(f"{prefix}_player_tile", 8)
    return values


def outputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["effect"] = claripy.BVS(f"{prefix}_effect", 8)
    return values


def setup(
    state: angr.SimState, values: dict[str, claripy.ast.BV], base: int
) -> None:
    state.memory.store(base + SCRIPT_OFFSET, values["script_offset"])
    state.memory.store(base + CURRENT_OFFSET, values["current_offset"])
    state.memory.store(base + PLAYER_TILE, values["player_tile"])
    state.memory.store(base + TRACE + 1, claripy.BVV(0, 8))
    state.memory.store(base + TRACE + 2, claripy.BVV(0, 8))


def endpoint(state: angr.SimState, native: bool) -> Endpoint:
    base = NATIVE_MEMORY if native else 0
    registers = (
        native_registers(state, NATIVE_STATE)
        if native
        else assembly_registers(state)
    )
    watched = (
        SCRIPT_OFFSET,
        CURRENT_OFFSET,
        PLAYER_TILE,
        TRACE + 1,
        TRACE + 2,
    )
    return Endpoint(
        **registers,
        state=claripy.Concat(
            *(state.memory.load(base + address, 1) for address in watched)
        ),
        constraints=tuple(state.solver.constraints),
    )


def assembly(
    values: dict[str, claripy.ast.BV],
    scripted: dict[str, claripy.ast.BV],
    ordinary: dict[str, claripy.ast.BV],
) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "UpdateNonPlayerSprite")
    assert location.bank == 1 and location.address == 0x4C5C
    assert linked_bytes(ROM, location, len(BODY)) == BODY
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
    start = location.address
    project.hook(start, Sm83DecRegister("a", start + 1), length=1)
    project.hook(start + 1, Sm83SwapRegister("a", start + 3), length=2)
    project.hook(start + 3, Sm83StoreAHighImmediate(0x93, start + 5), length=2)
    project.hook(start + 5, Sm83LoadAImmediate(SCRIPT_OFFSET, start + 8), length=3)
    project.hook(start + 8, CopyRegister("b", "a", start + 9), length=1)
    project.hook(start + 9, Sm83LoadAHighImmediate(0xDA, start + 11), length=2)
    project.hook(start + 11, Sm83CpRegister("b", start + 12), length=1)
    project.hook(start + 12, BranchNotZero(start + 17, start + 14), length=2)
    project.hook(
        0x5236, AssemblyCalleeTransition(scripted, 1), length=1
    )
    project.hook(
        0x4ED1, AssemblyCalleeTransition(ordinary, 2), length=1
    )

    state = project.factory.blank_state(addr=start)
    set_assembly_registers(state, values)
    setup(state, values, 0)
    state.regs.sp = claripy.BVV(STACK, 16)
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    manager = project.factory.simulation_manager(state)
    manager.explore(find=RETURN, num_find=2)
    assert not manager.errored and len(manager.found) == 2
    return [endpoint(found, False) for found in manager.found]


def native(
    values: dict[str, claripy.ast.BV],
    scripted: dict[str, claripy.ast.BV],
    ordinary: dict[str, claripy.ast.BV],
) -> list[Endpoint]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_update_non_player_sprite")
    scripted_function = project.loader.find_symbol("port_do_scripted_npc_movement")
    ordinary_function = project.loader.find_symbol("port_update_npc_sprite")
    assert function is not None
    assert scripted_function is not None and ordinary_function is not None
    project.hook(
        scripted_function.rebased_addr, NativeCalleeTransition(scripted, 1)
    )
    project.hook(
        ordinary_function.rebased_addr, NativeCalleeTransition(ordinary, 2)
    )
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    setup(state, values, NATIVE_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 2
    return [endpoint(found, True) for found in manager.deadended]


@pytest.mark.skipif(
    not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),
    reason="build artifacts missing",
)
def test_update_non_player_sprite_pathwise_equivalence() -> None:
    values = inputs("update_non_player_sprite")
    scripted = outputs("update_non_player_sprite_scripted")
    ordinary = outputs("update_non_player_sprite_ordinary")
    assert_pathwise_equivalent(
        assembly(values, scripted, ordinary),
        native(values, scripted, ordinary),
        (*REGISTERS, "state"),
    )
