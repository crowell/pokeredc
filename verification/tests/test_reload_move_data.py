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
    collect_returns,
    linked_bytes,
    rom_window,
    sm83_flags_to_z80,
    symbol_location,
)
from verification.harness.sm83_shims import Sm83DecRegister


ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xE000
RETURN = 0xFFFF
W_NAMED_OBJECT_INDEX = 0xD11E
W_NAME_BUFFER = 0xCD6D
W_STRING_BUFFER = 0xCF4B
H_WHOSE_TURN = 0xFFF3
W_PLAYER_MOVE_LIST_INDEX = 0xCC2E
W_PLAYER_MON_NUMBER = 0xCC2F
W_ENEMY_MOVE_LIST_INDEX = 0xCCE2
W_ENEMY_MON_PARTY_POS = 0xCFE8
W_BATTLE_MON_PP = 0xD02D
W_PARTY_MON1_PP = 0xD188
W_ENEMY_MON_PP = 0xCFFE
W_ENEMY_MON1_PP = 0xD8C1
PARTYMON_LENGTH = 44
MOVES = 0x4000
MOVE_LENGTH = 6
MOVES_BANK = 0x0E
EXPECTED = bytes.fromhex(
    "ea1ed13d210040010600cd873a3e0ecd9d00cd7363cd5830cd26383e01a7c9"
)
TOP_FIELDS = (
    "requested_bank",
    "loaded_bank",
    "rom_bank",
    "name_list_index",
    "name_list_type",
    "predef_bank",
    "named_object_index",
    "swap_temp",
    "swap_temp_plus1",
    "unused_pointer_low",
    "unused_pointer_high",
)
GET_FIELDS = (
    "name_list_index",
    "name_list_type",
    "predef_bank",
    "named_object_index",
    "loaded_bank",
    "rom_bank",
    "swap_temp",
    "swap_temp_plus1",
    "unused_pointer_low",
    "unused_pointer_high",
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
    state: claripy.ast.BV
    memory: claripy.ast.BV
    add_call: claripy.ast.BV
    far_call: claripy.ast.BV
    increment_call: claripy.ast.BV
    get_name_call: claripy.ast.BV
    copy_call: claripy.ast.BV
    trace: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _capture_assembly_registers(state: angr.SimState) -> claripy.ast.BV:
    registers = assembly_registers(state)
    return claripy.Concat(*(registers[name] for name in REGISTERS))


def _record(state: angr.SimState, name: str, snapshot: claripy.ast.BV, tag: int) -> None:
    state.globals[f"{name}_call"] = snapshot
    state.globals["trace"] = state.globals["trace"] * 16 + tag


def _set_assembly_output(state: angr.SimState, prefix: str) -> None:
    for name in REGISTERS:
        value = state.globals[f"{prefix}_{name}"]
        if name == "f":
            value = sm83_flags_to_z80(value)
        setattr(state.regs, name, value)


def _set_native_output(
    state: angr.SimState, address: claripy.ast.BV, prefix: str
) -> None:
    for offset, name in enumerate(REGISTERS):
        state.memory.store(address + offset, state.globals[f"{prefix}_{name}"])


def _add_n_times_result(
    a: claripy.ast.BV, bc: claripy.ast.BV, hl: claripy.ast.BV
) -> tuple[claripy.ast.BV, claripy.ast.BV]:
    total = claripy.ZeroExt(8, hl) + claripy.ZeroExt(16, a) * claripy.ZeroExt(8, bc)
    previous = claripy.ZeroExt(8, hl) + claripy.ZeroExt(16, a - 1) * claripy.ZeroExt(8, bc)
    last = claripy.ZeroExt(16, previous[15:0]) + claripy.ZeroExt(16, bc)
    flags = claripy.If(
        a == 0,
        claripy.BVV(0xA0, 8),
        claripy.BVV(0xC0, 8)
        | claripy.If(last > 0xFFFF, claripy.BVV(0x10, 8), claripy.BVV(0, 8)),
    )
    return total[15:0], flags


class StoreNamedObject(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        self.state.memory.store(W_NAMED_OBJECT_INDEX, self.state.regs.a)
        self.state.globals["named_object_index"] = self.state.regs.a
        self.jump(self._continuation)


class AndA(angr.SimProcedure):
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


class AssemblyAddNTimes(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        _record(self.state, "add", _capture_assembly_registers(self.state), 1)
        registers = assembly_registers(self.state)
        hl, flags = _add_n_times_result(
            registers["a"],
            claripy.Concat(registers["b"], registers["c"]),
            claripy.Concat(registers["h"], registers["l"]),
        )
        self.state.regs.a = 0
        self.state.regs.f = sm83_flags_to_z80(flags)
        self.state.regs.hl = hl
        self.jump(self._continuation)


class NativeAddNTimes(angr.SimProcedure):
    def run(self, address: claripy.ast.BV) -> None:  # type: ignore[override]
        _record(self.state, "add", self.state.memory.load(address, 8), 1)
        a = self.state.memory.load(address, 1)
        bc = self.state.memory.load(address + 2, 2)
        hl, flags = _add_n_times_result(a, bc, self.state.memory.load(address + 6, 2))
        self.state.memory.store(address, claripy.BVV(0, 8))
        self.state.memory.store(address + 1, flags)
        self.state.memory.store(address + 6, hl)


class AssemblyFarCopyData(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        snapshot = claripy.Concat(
            _capture_assembly_registers(self.state),
            self.state.globals["requested_bank"],
            self.state.globals["loaded_bank"],
            self.state.globals["rom_bank"],
        )
        _record(self.state, "far", snapshot, 2)
        registers = assembly_registers(self.state)
        destination = claripy.Concat(registers["d"], registers["e"])
        source = claripy.Concat(registers["h"], registers["l"])
        for offset in range(MOVE_LENGTH):
            self.state.memory.store(
                destination + offset, self.state.globals[f"far_byte_{offset}"]
            )
        self.state.globals["requested_bank"] = registers["a"]
        self.state.regs.a = self.state.globals["loaded_bank"]
        self.state.regs.bc = 0
        self.state.regs.de = destination + MOVE_LENGTH
        self.state.regs.hl = source + MOVE_LENGTH
        self.jump(self._continuation)


class NativeFarCopyData(angr.SimProcedure):
    def run(
        self, address: claripy.ast.BV, memory: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        _record(self.state, "far", self.state.memory.load(address, 11), 2)
        destination = self.state.memory.load(address + 4, 2)
        source = self.state.memory.load(address + 6, 2)
        requested = self.state.memory.load(address, 1)
        loaded = self.state.memory.load(address + 9, 1)
        for offset in range(MOVE_LENGTH):
            self.state.memory.store(
                memory + claripy.ZeroExt(48, destination) + offset,
                self.state.globals[f"far_byte_{offset}"],
            )
        self.state.memory.store(address, loaded)
        self.state.memory.store(address + 2, claripy.BVV(0, 16))
        self.state.memory.store(address + 4, destination + MOVE_LENGTH)
        self.state.memory.store(address + 6, source + MOVE_LENGTH)
        self.state.memory.store(address + 8, requested)


class AssemblyIncrementMovePP(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        _record(
            self.state, "increment", _capture_assembly_registers(self.state), 3
        )
        _set_assembly_output(self.state, "increment_out")
        self.state.memory.store(
            self.state.globals["battle_pp_address"],
            self.state.globals["increment_battle_pp"],
        )
        self.state.memory.store(
            self.state.globals["party_pp_address"],
            self.state.globals["increment_party_pp"],
        )
        self.jump(self._continuation)


class NativeIncrementMovePP(angr.SimProcedure):
    def run(
        self, address: claripy.ast.BV, memory: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        _record(self.state, "increment", self.state.memory.load(address, 8), 3)
        assert not memory.symbolic and self.state.solver.eval(memory) == NATIVE_MEMORY
        _set_native_output(self.state, address, "increment_out")
        self.state.memory.store(
            memory + claripy.ZeroExt(48, self.state.globals["battle_pp_address"]),
            self.state.globals["increment_battle_pp"],
        )
        self.state.memory.store(
            memory + claripy.ZeroExt(48, self.state.globals["party_pp_address"]),
            self.state.globals["increment_party_pp"],
        )


def _assembly_get_state(state: angr.SimState) -> claripy.ast.BV:
    return claripy.Concat(
        _capture_assembly_registers(state),
        *(state.globals[field] for field in GET_FIELDS),
        *(state.globals[f"saved_{name}"] for name in REGISTERS),
        state.globals["saved_bank"],
    )


class AssemblyGetMoveName(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        _record(self.state, "get_name", _assembly_get_state(self.state), 4)
        for offset, name in enumerate(REGISTERS):
            value = self.state.globals[f"get_out_{offset}"]
            if name == "f":
                value = sm83_flags_to_z80(value)
            setattr(self.state.regs, name, value)
        for offset, field in enumerate(GET_FIELDS, 8):
            self.state.globals[field] = self.state.globals[f"get_out_{offset}"]
        for offset, name in enumerate(REGISTERS, 18):
            self.state.globals[f"saved_{name}"] = self.state.globals[
                f"get_out_{offset}"
            ]
        self.state.globals["saved_bank"] = self.state.globals["get_out_26"]
        for offset in range(20):
            self.state.memory.store(
                W_NAME_BUFFER + offset, self.state.globals[f"name_byte_{offset}"]
            )
        self.jump(self._continuation)


class NativeGetMoveName(angr.SimProcedure):
    def run(
        self, address: claripy.ast.BV, memory: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        _record(self.state, "get_name", self.state.memory.load(address, 27), 4)
        for offset in range(27):
            self.state.memory.store(address + offset, self.state.globals[f"get_out_{offset}"])
        for offset in range(20):
            self.state.memory.store(
                memory + W_NAME_BUFFER + offset,
                self.state.globals[f"name_byte_{offset}"],
            )


class AssemblyCopyToStringBuffer(angr.SimProcedure):
    def __init__(self, continuation: int) -> None:
        super().__init__()
        self._continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        _record(self.state, "copy", _capture_assembly_registers(self.state), 5)
        _set_assembly_output(self.state, "copy_out")
        for offset in range(20):
            self.state.memory.store(
                W_STRING_BUFFER + offset,
                self.state.globals[f"string_byte_{offset}"],
            )
        self.jump(self._continuation)


class NativeCopyToStringBuffer(angr.SimProcedure):
    def run(
        self, address: claripy.ast.BV, memory: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        _record(self.state, "copy", self.state.memory.load(address, 8), 5)
        _set_native_output(self.state, address, "copy_out")
        for offset in range(20):
            self.state.memory.store(
                memory + W_STRING_BUFFER + offset,
                self.state.globals[f"string_byte_{offset}"],
            )


def _inputs(prefix: str, destination: int, turn: int) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    values["a"] = claripy.BVS(f"{prefix}_move", 8)
    values["d"] = claripy.BVV(destination >> 8, 8)
    values["e"] = claripy.BVV(destination & 0xFF, 8)
    for field in TOP_FIELDS:
        values[field] = claripy.BVS(f"{prefix}_{field}", 8)
    values["saved_bank"] = claripy.BVS(f"{prefix}_saved_bank", 8)
    for name in REGISTERS:
        values[f"saved_{name}"] = symbolic_registers(f"{prefix}_saved")[name]
        values[f"increment_out_{name}"] = symbolic_registers(
            f"{prefix}_increment_out"
        )[name]
        values[f"copy_out_{name}"] = symbolic_registers(f"{prefix}_copy_out")[name]
    for offset in range(27):
        values[f"get_out_{offset}"] = claripy.BVS(f"{prefix}_get_out_{offset}", 8)
    values["get_out_1"] = claripy.Concat(
        claripy.BVS(f"{prefix}_get_out_flags", 4), claripy.BVV(0, 4)
    )
    for stem, count in (("far_byte", 6), ("name_byte", 20), ("string_byte", 20)):
        for offset in range(count):
            values[f"{stem}_{offset}"] = claripy.BVS(
                f"{prefix}_{stem}_{offset}", 8
            )
    values["increment_battle_pp"] = claripy.BVS(
        f"{prefix}_increment_battle_pp", 8
    )
    values["increment_party_pp"] = claripy.BVS(
        f"{prefix}_increment_party_pp", 8
    )
    values["initial_battle_pp"] = claripy.BVS(f"{prefix}_initial_battle_pp", 8)
    values["initial_party_pp"] = claripy.BVS(f"{prefix}_initial_party_pp", 8)
    move_index = 2
    party_index = 3
    values["battle_pp_address"] = claripy.BVV(
        (W_BATTLE_MON_PP if turn == 0 else W_ENEMY_MON_PP) + move_index, 16
    )
    values["party_pp_address"] = claripy.BVV(
        (W_PARTY_MON1_PP if turn == 0 else W_ENEMY_MON1_PP)
        + PARTYMON_LENGTH * party_index
        + move_index,
        16,
    )
    return values


def _setup(
    state: angr.SimState,
    values: dict[str, claripy.ast.BV],
    turn: int,
    native: bool,
) -> None:
    memory_base = NATIVE_MEMORY if native else 0
    state.add_constraints(values["a"] >= 1, values["a"] < 165)
    for field in TOP_FIELDS:
        state.globals[field] = values[field]
    state.globals["saved_bank"] = values["saved_bank"]
    for name in REGISTERS:
        state.globals[f"saved_{name}"] = values[f"saved_{name}"]
        state.globals[f"increment_out_{name}"] = values[f"increment_out_{name}"]
        state.globals[f"copy_out_{name}"] = values[f"copy_out_{name}"]
    for offset in range(27):
        state.globals[f"get_out_{offset}"] = values[f"get_out_{offset}"]
    for stem, count in (("far_byte", 6), ("name_byte", 20), ("string_byte", 20)):
        for offset in range(count):
            state.globals[f"{stem}_{offset}"] = values[f"{stem}_{offset}"]
    for field in (
        "increment_battle_pp",
        "increment_party_pp",
        "battle_pp_address",
        "party_pp_address",
    ):
        state.globals[field] = values[field]
    state.globals["trace"] = claripy.BVV(0, 32)
    state.memory.store(memory_base + H_WHOSE_TURN, claripy.BVV(turn, 8))
    state.memory.store(memory_base + W_PLAYER_MOVE_LIST_INDEX, claripy.BVV(2, 8))
    state.memory.store(memory_base + W_ENEMY_MOVE_LIST_INDEX, claripy.BVV(2, 8))
    state.memory.store(memory_base + W_PLAYER_MON_NUMBER, claripy.BVV(3, 8))
    state.memory.store(memory_base + W_ENEMY_MON_PARTY_POS, claripy.BVV(3, 8))
    state.memory.store(
        memory_base + claripy.ZeroExt(48, values["battle_pp_address"]),
        values["initial_battle_pp"],
    )
    state.memory.store(
        memory_base + claripy.ZeroExt(48, values["party_pp_address"]),
        values["initial_party_pp"],
    )


def _assembly_state(state: angr.SimState) -> claripy.ast.BV:
    return claripy.Concat(
        *(state.globals[field] for field in TOP_FIELDS),
        *(state.globals[f"saved_{name}"] for name in REGISTERS),
        state.globals["saved_bank"],
    )


def _endpoint(
    state: angr.SimState,
    values: dict[str, claripy.ast.BV],
    destination: int,
    native: bool,
) -> Endpoint:
    memory_base = NATIVE_MEMORY if native else 0
    registers = native_registers(state, NATIVE_STATE) if native else assembly_registers(state)
    top_state = state.memory.load(NATIVE_STATE + 8, 20) if native else _assembly_state(state)
    observed_memory = claripy.Concat(
        state.memory.load(memory_base + W_NAMED_OBJECT_INDEX, 1),
        state.memory.load(memory_base + destination, MOVE_LENGTH),
        state.memory.load(
            memory_base + claripy.ZeroExt(48, values["battle_pp_address"]), 1
        ),
        state.memory.load(
            memory_base + claripy.ZeroExt(48, values["party_pp_address"]), 1
        ),
        state.memory.load(memory_base + W_NAME_BUFFER, 20),
        state.memory.load(memory_base + W_STRING_BUFFER, 20),
    )
    return Endpoint(
        **registers,
        state=top_state,
        memory=observed_memory,
        add_call=state.globals["add_call"],
        far_call=state.globals["far_call"],
        increment_call=state.globals["increment_call"],
        get_name_call=state.globals["get_name_call"],
        copy_call=state.globals["copy_call"],
        trace=state.globals["trace"],
        constraints=tuple(state.solver.constraints),
    )


@cache
def _assembly_project() -> tuple[angr.Project, int]:
    location = symbol_location(SYMS, "ReloadMoveData")
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
    project.hook(base, StoreNamedObject(base + 3), length=3)
    project.hook(base + 3, Sm83DecRegister("a", base + 4), length=1)
    project.hook(base + 10, AssemblyAddNTimes(base + 13), length=3)
    project.hook(base + 15, AssemblyFarCopyData(base + 18), length=3)
    project.hook(base + 18, AssemblyIncrementMovePP(base + 21), length=3)
    project.hook(base + 21, AssemblyGetMoveName(base + 24), length=3)
    project.hook(base + 24, AssemblyCopyToStringBuffer(base + 27), length=3)
    project.hook(base + 29, AndA(base + 30), length=1)
    return project, base


@cache
def _native_project() -> tuple[angr.Project, int]:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_reload_move_data")
    add = project.loader.find_symbol("port_add_n_times")
    far = project.loader.find_symbol("port_far_copy_data")
    increment = project.loader.find_symbol("port_increment_move_pp")
    get_name = project.loader.find_symbol("port_get_move_name")
    copy = project.loader.find_symbol("port_copy_to_string_buffer")
    assert all(symbol is not None for symbol in (function, add, far, increment, get_name, copy))
    project.hook(add.rebased_addr, NativeAddNTimes())
    project.hook(far.rebased_addr, NativeFarCopyData())
    project.hook(increment.rebased_addr, NativeIncrementMovePP())
    project.hook(get_name.rebased_addr, NativeGetMoveName())
    project.hook(copy.rebased_addr, NativeCopyToStringBuffer())
    return project, function.rebased_addr


def _assembly(
    values: dict[str, claripy.ast.BV], destination: int, turn: int
) -> list[Endpoint]:
    project, base = _assembly_project()
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    _setup(state, values, turn, False)
    state.regs.sp = STACK
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    return [
        _endpoint(end, values, destination, False)
        for end in collect_returns(project, state, RETURN)
    ]


def _native(
    values: dict[str, claripy.ast.BV], destination: int, turn: int
) -> list[Endpoint]:
    project, function = _native_project()
    state = project.factory.call_state(function, NATIVE_STATE, NATIVE_MEMORY)
    store_native_registers(state, NATIVE_STATE, values)
    for offset, field in enumerate(TOP_FIELDS, 8):
        state.memory.store(NATIVE_STATE + offset, values[field])
    for offset, name in enumerate(REGISTERS, 19):
        state.memory.store(NATIVE_STATE + offset, values[f"saved_{name}"])
    state.memory.store(NATIVE_STATE + 27, values["saved_bank"])
    _setup(state, values, turn, True)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [_endpoint(manager.deadended[0], values, destination, True)]


@pytest.mark.skipif(
    not ELF.exists() or not ROM.exists() or not SYMS.exists(), reason="build"
)
@pytest.mark.parametrize("destination", (0xCFD2, 0xCFCC), ids=("player", "enemy"))
@pytest.mark.parametrize("turn", (0, 1), ids=("player-turn", "enemy-turn"))
def test_reload_move_data_pathwise_equivalence(destination: int, turn: int) -> None:
    values = _inputs(f"reload_{destination:04x}_{turn}", destination, turn)
    assert_pathwise_equivalent(
        _assembly(values, destination, turn),
        _native(values, destination, turn),
        (
            *REGISTERS,
            "state",
            "memory",
            "add_call",
            "far_call",
            "increment_call",
            "get_name_call",
            "copy_call",
            "trace",
        ),
    )
