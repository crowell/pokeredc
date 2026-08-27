from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

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
    Sm83LoadAHighImmediate,
    Sm83StoreAImmediate,
    Sm83XorA,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
DONE = 0xEFFF
STACK = 0xD800

H_RANDOM_ADD = 0xFFD3
H_RANDOM_SUB = 0xFFD4
W_MON_DATA_LOCATION = 0xCC49
W_PARTY_COUNT = 0xD163
W_NUM_BAG_ITEMS = 0xD31D
W_PLAYER_MONEY = 0xD347
W_OBTAINED_BADGES = 0xD356
W_PLAYER_ID = 0xD359
W_NUM_BOX_ITEMS = 0xD53A
W_PLAYER_COINS = 0xD5A4
W_TOGGLEABLE_COUNTER = 0xD048
W_TOGGLEABLE_FLAGS = 0xD5A6
TOGGLEABLE_FLAGS_SIZE = 32
W_GAME_PROGRESS_FLAGS = 0xD5F0
GAME_PROGRESS_SIZE = 0xC8
W_UNUSED_PLAYER_DATA_BYTE = 0xD71B
W_BOX_COUNT = 0xDA80
SCALARS = (
    H_RANDOM_ADD,
    H_RANDOM_SUB,
    W_MON_DATA_LOCATION,
    W_PARTY_COUNT,
    W_PARTY_COUNT + 1,
    W_NUM_BAG_ITEMS,
    W_NUM_BAG_ITEMS + 1,
    W_PLAYER_MONEY,
    W_PLAYER_MONEY + 1,
    W_PLAYER_MONEY + 2,
    W_OBTAINED_BADGES,
    W_OBTAINED_BADGES + 1,
    W_PLAYER_ID,
    W_PLAYER_ID + 1,
    W_NUM_BOX_ITEMS,
    W_NUM_BOX_ITEMS + 1,
    W_PLAYER_COINS,
    W_PLAYER_COINS + 1,
    W_UNUSED_PLAYER_DATA_BYTE,
    W_BOX_COUNT,
    W_BOX_COUNT + 1,
    W_TOGGLEABLE_COUNTER,
)
EXPECTED = bytes.fromhex(
    "cd5c3ef0d4ea59d3cd5c3ef0d3ea5ad33effea1bd72163d1cda0782180da"
    "cda078211dd3cda078213ad5cda0782148d33e3032af222377ea49cc2156d3"
    "227721a4d5227721f0d501c800cde036c37571"
)
SNAPSHOT_SIZE = len(SCALARS) + GAME_PROGRESS_SIZE + TOGGLEABLE_FLAGS_SIZE
RANDOM_INPUT_SIZE = len(REGISTERS) + 6
LIST_INPUT_SIZE = len(REGISTERS) + 2
FILL_INPUT_SIZE = len(REGISTERS) + GAME_PROGRESS_SIZE
TOGGLE_INPUT_SIZE = len(REGISTERS) + SNAPSHOT_SIZE


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
    div_samples: claripy.ast.BV
    loaded_bank: claripy.ast.BV
    rom_bank: claripy.ast.BV
    random0_input: claripy.ast.BV
    random1_input: claripy.ast.BV
    list0_input: claripy.ast.BV
    list1_input: claripy.ast.BV
    list2_input: claripy.ast.BV
    list3_input: claripy.ast.BV
    fill_input: claripy.ast.BV
    toggle_input: claripy.ast.BV
    random_calls: claripy.ast.BV
    list_calls: claripy.ast.BV
    fill_calls: claripy.ast.BV
    toggle_calls: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def inputs(tag: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(tag)
    values["div_samples"] = claripy.BVS(f"{tag}_div_samples", 32)
    values["loaded_bank"] = claripy.BVS(f"{tag}_loaded_bank", 8)
    values["rom_bank"] = claripy.BVS(f"{tag}_rom_bank", 8)
    values["progress"] = claripy.BVS(f"{tag}_progress", GAME_PROGRESS_SIZE * 8)
    values["toggle_flags"] = claripy.BVS(
        f"{tag}_toggle_flags", TOGGLEABLE_FLAGS_SIZE * 8
    )
    values["toggle_post_flags"] = claripy.BVS(
        f"{tag}_toggle_post_flags", TOGGLEABLE_FLAGS_SIZE * 8
    )
    values["toggle_post_counter"] = claripy.BVS(
        f"{tag}_toggle_post_counter", 8
    )
    for index in range(len(SCALARS)):
        values[f"scalar{index}"] = claripy.BVS(f"{tag}_scalar{index}", 8)
    for register in REGISTERS:
        values[f"toggle_{register}"] = (
            claripy.Concat(
                claripy.BVS(f"{tag}_toggle_flags_out", 4), claripy.BVV(0, 4)
            )
            if register == "f"
            else claripy.BVS(f"{tag}_toggle_{register}", 8)
        )
    return values


def snapshot(state, base: int) -> claripy.ast.BV:
    return claripy.Concat(
        *(state.memory.load(base + address, 1) for address in SCALARS),
        state.memory.load(base + W_GAME_PROGRESS_FLAGS, GAME_PROGRESS_SIZE),
        state.memory.load(base + W_TOGGLEABLE_FLAGS, TOGGLEABLE_FLAGS_SIZE),
    )


def setup(state, values, base: int) -> None:
    for index, address in enumerate(SCALARS):
        state.memory.store(base + address, values[f"scalar{index}"])
    state.memory.store(base + W_GAME_PROGRESS_FLAGS, values["progress"])
    state.memory.store(base + W_TOGGLEABLE_FLAGS, values["toggle_flags"])
    state.globals["div_samples"] = values["div_samples"]
    state.globals["loaded_bank"] = values["loaded_bank"]
    state.globals["rom_bank"] = values["rom_bank"]
    state.globals["toggle_post_flags"] = values["toggle_post_flags"]
    state.globals["toggle_post_counter"] = values["toggle_post_counter"]
    for register in REGISTERS:
        state.globals[f"toggle_{register}"] = values[f"toggle_{register}"]
    for name in ("random", "list", "fill", "toggle"):
        state.globals[f"{name}_calls"] = claripy.BVV(0, 8)
    for index in range(2):
        state.globals[f"random{index}_input"] = claripy.BVV(
            0, RANDOM_INPUT_SIZE * 8
        )
    for index in range(4):
        state.globals[f"list{index}_input"] = claripy.BVV(0, LIST_INPUT_SIZE * 8)
    state.globals["fill_input"] = claripy.BVV(0, FILL_INPUT_SIZE * 8)
    state.globals["toggle_input"] = claripy.BVV(0, TOGGLE_INPUT_SIZE * 8)


def random_transition(registers, random_add, random_sub, div_first, div_second):
    carry_in = registers["f"][4:4]
    first_wide = (
        claripy.ZeroExt(1, random_add)
        + claripy.ZeroExt(1, div_first)
        + claripy.ZeroExt(8, carry_in)
    )
    add_out = first_wide[7:0]
    first_carry = first_wide[8:8]
    borrow_amount = claripy.ZeroExt(1, div_second) + claripy.ZeroExt(
        8, first_carry
    )
    sub_out = (claripy.ZeroExt(1, random_sub) - borrow_amount)[7:0]
    half_borrow = claripy.ZeroExt(1, random_sub[3:0]) < (
        claripy.ZeroExt(1, div_second[3:0]) + claripy.ZeroExt(4, first_carry)
    )
    borrow = claripy.ZeroExt(1, random_sub) < borrow_amount
    flags = (
        claripy.BVV(0x40, 8)
        | claripy.If(sub_out == 0, claripy.BVV(0x80, 8), claripy.BVV(0, 8))
        | claripy.If(half_borrow, claripy.BVV(0x20, 8), claripy.BVV(0, 8))
        | claripy.If(borrow, claripy.BVV(0x10, 8), claripy.BVV(0, 8))
    )
    output = dict(registers)
    output["a"] = add_out
    output["f"] = flags
    return output, add_out, sub_out


def apply_random(state, base: int, get_registers, set_registers) -> None:
    index = state.solver.eval(state.globals["random_calls"])
    assert index in (0, 1)
    registers = get_registers()
    random_add = state.memory.load(base + H_RANDOM_ADD, 1)
    random_sub = state.memory.load(base + H_RANDOM_SUB, 1)
    samples = state.globals["div_samples"]
    div_first = samples[31 - index * 16 : 24 - index * 16]
    div_second = samples[23 - index * 16 : 16 - index * 16]
    state.globals[f"random{index}_input"] = claripy.Concat(
        *(registers[name] for name in REGISTERS),
        random_add,
        random_sub,
        div_first,
        div_second,
        state.globals["loaded_bank"],
        state.globals["rom_bank"],
    )
    output, add_out, sub_out = random_transition(
        registers, random_add, random_sub, div_first, div_second
    )
    set_registers(output)
    state.memory.store(base + H_RANDOM_ADD, add_out)
    state.memory.store(base + H_RANDOM_SUB, sub_out)
    state.globals["random_calls"] += 1


def apply_list(state, base: int, get_registers, set_registers) -> None:
    index = state.solver.eval(state.globals["list_calls"])
    assert index in range(4)
    registers = get_registers()
    address = state.solver.eval(claripy.Concat(registers["h"], registers["l"]))
    state.globals[f"list{index}_input"] = claripy.Concat(
        *(registers[name] for name in REGISTERS),
        state.memory.load(base + address, 2),
    )
    registers["a"] = claripy.BVV(0xFF, 8)
    registers["f"] = claripy.BVV(0x60, 8)
    pointer = (address + 1) & 0xFFFF
    registers["h"] = claripy.BVV(pointer >> 8, 8)
    registers["l"] = claripy.BVV(pointer & 0xFF, 8)
    state.memory.store(base + address, claripy.BVV(0, 8))
    state.memory.store(base + ((address + 1) & 0xFFFF), claripy.BVV(0xFF, 8))
    set_registers(registers)
    state.globals["list_calls"] += 1


def apply_fill(state, base: int, get_registers, set_registers) -> None:
    registers = get_registers()
    state.globals["fill_input"] = claripy.Concat(
        *(registers[name] for name in REGISTERS),
        state.memory.load(base + W_GAME_PROGRESS_FLAGS, GAME_PROGRESS_SIZE),
    )
    state.memory.store(
        base + W_GAME_PROGRESS_FLAGS, claripy.BVV(0, GAME_PROGRESS_SIZE * 8)
    )
    registers["a"] = claripy.BVV(0, 8)
    registers["f"] = claripy.BVV(0x80, 8)
    registers["b"] = claripy.BVV(0, 8)
    registers["c"] = claripy.BVV(0, 8)
    registers["h"] = claripy.BVV(0xD6, 8)
    registers["l"] = claripy.BVV(0xB8, 8)
    set_registers(registers)
    state.globals["fill_calls"] += 1


def apply_toggle(state, base: int, get_registers, set_registers) -> None:
    registers = get_registers()
    state.globals["toggle_input"] = claripy.Concat(
        *(registers[name] for name in REGISTERS), snapshot(state, base)
    )
    state.memory.store(
        base + W_TOGGLEABLE_FLAGS, state.globals["toggle_post_flags"]
    )
    state.memory.store(
        base + W_TOGGLEABLE_COUNTER, state.globals["toggle_post_counter"]
    )
    for register in REGISTERS:
        registers[register] = state.globals[f"toggle_{register}"]
    set_registers(registers)
    state.globals["toggle_calls"] += 1


class AssemblyRandom(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__()
        self.next_address = next_address

    def run(self):
        apply_random(
            self.state,
            0,
            lambda: assembly_registers(self.state),
            lambda registers: set_assembly_registers(self.state, registers),
        )
        self.jump(self.next_address)


class AssemblyList(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__()
        self.next_address = next_address

    def run(self):
        apply_list(
            self.state,
            0,
            lambda: assembly_registers(self.state),
            lambda registers: set_assembly_registers(self.state, registers),
        )
        self.jump(self.next_address)


class AssemblyFill(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__()
        self.next_address = next_address

    def run(self):
        apply_fill(
            self.state,
            0,
            lambda: assembly_registers(self.state),
            lambda registers: set_assembly_registers(self.state, registers),
        )
        self.jump(self.next_address)


class AssemblyToggle(angr.SimProcedure):
    def run(self):
        apply_toggle(
            self.state,
            0,
            lambda: assembly_registers(self.state),
            lambda registers: set_assembly_registers(self.state, registers),
        )
        self.jump(DONE)


class StoreAHLStep(angr.SimProcedure):
    def __init__(self, increment: int, next_address: int):
        super().__init__()
        self.increment = increment
        self.next_address = next_address

    def run(self):
        registers = assembly_registers(self.state)
        pointer = claripy.Concat(registers["h"], registers["l"])
        self.state.memory.store(pointer, registers["a"])
        pointer += self.increment
        registers["h"] = pointer[15:8]
        registers["l"] = pointer[7:0]
        set_assembly_registers(self.state, registers)
        self.jump(self.next_address)


class NativeRandom(angr.SimProcedure):
    def run(self, pointer):
        index = self.state.solver.eval(self.state.globals["random_calls"])
        registers = {
            name: self.state.memory.load(pointer + offset, 1)
            for offset, name in enumerate(REGISTERS)
        }
        random_add = self.state.memory.load(pointer + 8, 1)
        random_sub = self.state.memory.load(pointer + 9, 1)
        div_first = self.state.memory.load(pointer + 10, 1)
        div_second = self.state.memory.load(pointer + 11, 1)
        self.state.globals[f"random{index}_input"] = self.state.memory.load(
            pointer, RANDOM_INPUT_SIZE
        )
        output, add_out, sub_out = random_transition(
            registers, random_add, random_sub, div_first, div_second
        )
        self.state.memory.store(
            pointer,
            claripy.Concat(
                *(output[name] for name in REGISTERS),
                add_out,
                sub_out,
                self.state.memory.load(pointer + 10, 4),
            ),
        )
        self.state.globals["random_calls"] += 1


class NativeList(angr.SimProcedure):
    def run(self, pointer):
        def get_registers():
            return {
                name: self.state.memory.load(pointer + offset, 1)
                for offset, name in enumerate(REGISTERS)
            }

        def set_registers(registers):
            self.state.memory.store(
                pointer,
                claripy.Concat(*(registers[name] for name in REGISTERS)),
            )

        index = self.state.solver.eval(self.state.globals["list_calls"])
        self.state.globals[f"list{index}_input"] = self.state.memory.load(
            pointer, LIST_INPUT_SIZE
        )
        registers = get_registers()
        address = self.state.solver.eval(
            claripy.Concat(registers["h"], registers["l"])
        )
        registers["a"] = claripy.BVV(0xFF, 8)
        registers["f"] = claripy.BVV(0x60, 8)
        address = (address + 1) & 0xFFFF
        registers["h"] = claripy.BVV(address >> 8, 8)
        registers["l"] = claripy.BVV(address & 0xFF, 8)
        set_registers(registers)
        self.state.memory.store(pointer + 8, claripy.BVV(0, 8))
        self.state.memory.store(pointer + 9, claripy.BVV(0xFF, 8))
        self.state.globals["list_calls"] += 1


class NativeFill(angr.SimProcedure):
    def run(self, pointer, memory):
        def get_registers():
            return {
                name: self.state.memory.load(pointer + offset, 1)
                for offset, name in enumerate(REGISTERS)
            }

        def set_registers(registers):
            self.state.memory.store(
                pointer,
                claripy.Concat(*(registers[name] for name in REGISTERS)),
            )

        apply_fill(self.state, NATIVE_MEMORY, get_registers, set_registers)


class NativeToggle(angr.SimProcedure):
    def run(self, pointer, memory):
        def get_registers():
            return {
                name: self.state.memory.load(pointer + offset, 1)
                for offset, name in enumerate(REGISTERS)
            }

        def set_registers(registers):
            self.state.memory.store(
                pointer,
                claripy.Concat(*(registers[name] for name in REGISTERS)),
            )

        apply_toggle(self.state, NATIVE_MEMORY, get_registers, set_registers)


def endpoint(state, base: int) -> Endpoint:
    registers = native_registers(state, NATIVE_STATE) if base else assembly_registers(state)
    return Endpoint(
        **registers,
        memory=snapshot(state, base),
        div_samples=(
            state.memory.load(NATIVE_STATE + 8, 4)
            if base
            else state.globals["div_samples"]
        ),
        loaded_bank=(
            state.memory.load(NATIVE_STATE + 12, 1)
            if base
            else state.globals["loaded_bank"]
        ),
        rom_bank=(
            state.memory.load(NATIVE_STATE + 13, 1)
            if base
            else state.globals["rom_bank"]
        ),
        random0_input=state.globals["random0_input"],
        random1_input=state.globals["random1_input"],
        list0_input=state.globals["list0_input"],
        list1_input=state.globals["list1_input"],
        list2_input=state.globals["list2_input"],
        list3_input=state.globals["list3_input"],
        fill_input=state.globals["fill_input"],
        toggle_input=state.globals["toggle_input"],
        random_calls=state.globals["random_calls"],
        list_calls=state.globals["list_calls"],
        fill_calls=state.globals["fill_calls"],
        toggle_calls=state.globals["toggle_calls"],
        constraints=tuple(state.solver.constraints),
    )


def run_assembly(values) -> Endpoint:
    location = symbol_location(SYMS, "InitPlayerData2")
    end = symbol_location(SYMS, "InitializeEmptyList")
    toggle = symbol_location(SYMS, "InitializeToggleableObjectsFlags")
    assert location.bank == 3
    assert end.address - location.address == len(EXPECTED)
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
    project.hook(base, AssemblyRandom(base + 3), length=3)
    project.hook(base + 3, Sm83LoadAHighImmediate(0xD4, base + 5), length=2)
    project.hook(base + 5, Sm83StoreAImmediate(W_PLAYER_ID, base + 8), length=3)
    project.hook(base + 8, AssemblyRandom(base + 11), length=3)
    project.hook(base + 11, Sm83LoadAHighImmediate(0xD3, base + 13), length=2)
    project.hook(base + 13, Sm83StoreAImmediate(W_PLAYER_ID + 1, base + 16), length=3)
    project.hook(
        base + 18, Sm83StoreAImmediate(W_UNUSED_PLAYER_DATA_BYTE, base + 21), length=3
    )
    for offset in (24, 30, 36, 42):
        project.hook(base + offset, AssemblyList(base + offset + 3), length=3)
    project.hook(base + 50, StoreAHLStep(-1, base + 51), length=1)
    project.hook(base + 51, Sm83XorA(base + 52), length=1)
    project.hook(base + 52, StoreAHLStep(1, base + 53), length=1)
    project.hook(
        base + 55, Sm83StoreAImmediate(W_MON_DATA_LOCATION, base + 58), length=3
    )
    project.hook(base + 61, StoreAHLStep(1, base + 62), length=1)
    project.hook(base + 66, StoreAHLStep(1, base + 67), length=1)
    project.hook(base + 74, AssemblyFill(base + 77), length=3)
    project.hook(toggle.address, AssemblyToggle(), length=1)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.regs.sp = STACK
    setup(state, values, 0)
    manager = project.factory.simulation_manager(state)
    manager.explore(find=DONE)
    assert not manager.errored
    assert len(manager.found) == 1
    return endpoint(manager.found[0], 0)


def run_native(values) -> Endpoint:
    project = angr.Project(ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_init_player_data2")
    random = project.loader.find_symbol("port_random_generate")
    empty = project.loader.find_symbol("port_initialize_empty_list")
    fill = project.loader.find_symbol("port_fill_memory")
    toggle = project.loader.find_symbol("port_initialize_toggleable_objects_flags")
    assert function is not None
    assert random is not None
    assert empty is not None
    assert fill is not None
    assert toggle is not None
    project.hook(random.rebased_addr, NativeRandom())
    project.hook(empty.rebased_addr, NativeList())
    project.hook(fill.rebased_addr, NativeFill())
    project.hook(toggle.rebased_addr, NativeToggle())
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    state.memory.store(NATIVE_STATE + 8, values["div_samples"])
    state.memory.store(NATIVE_STATE + 12, values["loaded_bank"])
    state.memory.store(NATIVE_STATE + 13, values["rom_bank"])
    setup(state, values, NATIVE_MEMORY)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    assert len(manager.deadended) == 1
    return endpoint(manager.deadended[0], NATIVE_MEMORY)


def assert_equal(solver, left, right, label: str) -> None:
    difference = left != right
    if not claripy.is_false(difference) and solver.satisfiable(
        extra_constraints=(difference,)
    ):
        raise AssertionError(f"{label} differs")


def assert_chunks(solver, left, right, bits: int, label: str) -> None:
    assert left.size() == bits
    assert right.size() == bits
    for offset in range(0, bits, 64):
        high = bits - 1 - offset
        low = max(0, high - 63)
        assert_equal(solver, left[high:low], right[high:low], f"{label} {low}:{high}")


def assert_equivalent(left: Endpoint, right: Endpoint) -> None:
    solver = claripy.Solver()
    solver.add(left.constraints)
    solver.add(right.constraints)
    assert solver.satisfiable()
    for name in (
        *REGISTERS,
        "div_samples",
        "loaded_bank",
        "rom_bank",
        "random_calls",
        "list_calls",
        "fill_calls",
        "toggle_calls",
    ):
        assert_equal(solver, getattr(left, name), getattr(right, name), name)
    assert_chunks(solver, left.memory, right.memory, SNAPSHOT_SIZE * 8, "memory")
    for index in range(2):
        name = f"random{index}_input"
        assert_chunks(
            solver,
            getattr(left, name),
            getattr(right, name),
            RANDOM_INPUT_SIZE * 8,
            name,
        )
    for index in range(4):
        name = f"list{index}_input"
        assert_chunks(
            solver,
            getattr(left, name),
            getattr(right, name),
            LIST_INPUT_SIZE * 8,
            name,
        )
    assert_chunks(
        solver,
        left.fill_input,
        right.fill_input,
        FILL_INPUT_SIZE * 8,
        "fill_input",
    )
    assert_chunks(
        solver,
        left.toggle_input,
        right.toggle_input,
        TOGGLE_INPUT_SIZE * 8,
        "toggle_input",
    )
    for endpoint_state in (left, right):
        assert solver.is_true(endpoint_state.random_calls == 2)
        assert solver.is_true(endpoint_state.list_calls == 4)
        assert solver.is_true(endpoint_state.fill_calls == 1)
        assert solver.is_true(endpoint_state.toggle_calls == 1)


@pytest.mark.skipif(
    not ELF.exists() or not ROM.exists() or not SYMS.exists(), reason="build"
)
def test_init_player_data2_pathwise_equivalence():
    values = inputs("init_player_data2")
    assert_equivalent(run_assembly(values), run_native(values))
