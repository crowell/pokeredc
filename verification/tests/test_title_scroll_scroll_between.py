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
    collect_returns,
    linked_bytes,
    rom_window,
    symbol_location,
)
from verification.harness.sm83_shims import (
    Sm83CpRegister,
    Sm83StoreAHighImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
BEFORE = 0x110000
AFTER = 0x120000
STACK = 0xD000
RETURN = 0xFFFF
SCX = 0xFF43
EXPECTED_BODY = bytes.fromhex("f044bd20fb7ce043f044bc28fbc9")


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
    ly: claripy.ast.BV
    scx: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class ReadSequenceLy(angr.SimProcedure):
    def __init__(self, sequence: str, continuation: int) -> None:
        super().__init__()
        self.sequence = sequence
        self.continuation = continuation

    def run(self) -> None:  # type: ignore[override]
        index_key = f"{self.sequence}_index"
        index = self.state.globals[index_key]
        values = self.state.globals[self.sequence]
        assert index < len(values)
        value = values[index]
        self.state.globals[index_key] = index + 1
        self.state.globals["ly"] = value
        self.state.regs.a = value
        self.jump(self.continuation)


def _inputs(prefix: str, repeated: bool) -> dict[str, object]:
    values: dict[str, object] = symbolic_registers(prefix)
    values["ly"] = claripy.BVS(f"{prefix}_initial_ly", 8)
    values["scx"] = claripy.BVS(f"{prefix}_initial_scx", 8)
    if repeated:
        values["before"] = (
            claripy.BVS(f"{prefix}_before0", 8),
            claripy.BVS(f"{prefix}_before1", 8),
            values["l"],
        )
        values["after"] = (
            values["h"],
            values["h"],
            claripy.BVS(f"{prefix}_after2", 8),
        )
    else:
        values["before"] = (values["l"],)
        values["after"] = (claripy.BVS(f"{prefix}_after0", 8),)
    return values


def _constraints(
    state: angr.SimState, values: dict[str, object], repeated: bool
) -> None:
    before = values["before"]
    after = values["after"]
    assert isinstance(before, tuple) and isinstance(after, tuple)
    if repeated:
        state.solver.add(before[0] != values["l"])
        state.solver.add(before[1] != values["l"])
    state.solver.add(after[-1] != values["h"])


def _assembly(
    values: dict[str, object], repeated: bool
) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "_TitleScroll.ScrollBetween")
    reference = symbol_location(SYMBOLS, "ScrollTitleScreenGameVersion")
    assert linked_bytes(ROM, location, len(EXPECTED_BODY)) == EXPECTED_BODY
    assert linked_bytes(ROM, reference, len(EXPECTED_BODY)) == EXPECTED_BODY
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
    project.hook(base, ReadSequenceLy("before", base + 2), length=2)
    project.hook(base + 2, Sm83CpRegister("l", base + 3), length=1)
    project.hook(
        base + 6, Sm83StoreAHighImmediate(0x43, base + 8), length=2
    )
    project.hook(base + 8, ReadSequenceLy("after", base + 10), length=2)
    project.hook(base + 10, Sm83CpRegister("h", base + 11), length=1)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)  # type: ignore[arg-type]
    state.memory.store(SCX, values["scx"])
    state.globals["ly"] = values["ly"]
    state.globals["before"] = values["before"]
    state.globals["after"] = values["after"]
    state.globals["before_index"] = 0
    state.globals["after_index"] = 0
    _constraints(state, values, repeated)
    state.regs.sp = claripy.BVV(STACK, 16)
    state.memory.store(
        STACK, claripy.BVV(RETURN, 16), endness="Iend_LE"
    )
    ends = collect_returns(project, state, RETURN)
    assert len(ends) == 1
    return [
        Endpoint(
            **assembly_registers(end),
            ly=end.globals["ly"],
            scx=end.memory.load(SCX, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in ends
    ]


def _native(
    values: dict[str, object], repeated: bool
) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol("port_title_scroll_scroll_between")
    assert function is not None
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, BEFORE, AFTER
    )
    store_native_registers(state, NATIVE_STATE, values)  # type: ignore[arg-type]
    state.memory.store(
        NATIVE_STATE + 8,
        claripy.Concat(values["ly"], values["scx"]),
    )
    before = values["before"]
    after = values["after"]
    assert isinstance(before, tuple) and isinstance(after, tuple)
    state.memory.store(BEFORE, claripy.Concat(*before))
    state.memory.store(AFTER, claripy.Concat(*after))
    _constraints(state, values, repeated)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored and len(manager.deadended) == 1
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            ly=end.memory.load(NATIVE_STATE + 8, 1),
            scx=end.memory.load(NATIVE_STATE + 9, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(
    not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`"
)
@pytest.mark.parametrize("repeated", (False, True))
def test_title_scroll_scroll_between_pathwise_equivalence(
    repeated: bool,
) -> None:
    values = _inputs(f"title_scroll_between_{int(repeated)}", repeated)
    assert_pathwise_equivalent(
        _assembly(values, repeated),
        _native(values, repeated),
        (*REGISTERS, "ly", "scx"),
    )
