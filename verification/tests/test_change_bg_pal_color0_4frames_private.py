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
    sm83_flags_to_z80,
    symbol_location,
)
from verification.harness.sm83_shims import (
    Sm83LoadAHighImmediate,
    Sm83OrRegister,
    Sm83StoreAHighImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
NATIVE_ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NATIVE_STATE = 0x100000
NATIVE_MEMORY = 0x200000
STACK = 0xD000
RETURN = 0xFFFF
R_BGP = 0xFF47
EXPECTED = bytes.fromhex("cd943ef047b0e0470e04cd3937f047e6fce047c9")
PREDEF_FIELDS = tuple(f"predef{index}" for index in range(6))


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
    predef: claripy.ast.BV
    calls: claripy.ast.BV
    palette: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class AssemblyPredefSummary(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        registers = assembly_registers(self.state)
        self.state.globals["call_predef"] = claripy.Concat(
            *(registers[register] for register in REGISTERS),
            *(self.state.globals[field] for field in PREDEF_FIELDS),
        )
        _set_assembly_outputs(self.state, "predef")
        self.jump(self._next_address)


class AssemblyDelaySummary(angr.SimProcedure):
    def __init__(self, next_address: int):
        super().__init__()
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        registers = assembly_registers(self.state)
        self.state.globals["call_delay"] = claripy.Concat(
            *(registers[register] for register in REGISTERS),
            claripy.BVV(0, 24),
            self.state.memory.load(R_BGP, 1),
        )
        _set_assembly_outputs(self.state, "delay")
        self.jump(self._next_address)


class NativePredefSummary(angr.SimProcedure):
    def run(self, callee_state: claripy.ast.BV) -> None:  # type: ignore[override]
        self.state.globals["call_predef"] = self.state.memory.load(
            callee_state, 14
        )
        self.state.memory.store(
            callee_state,
            claripy.Concat(
                *(self.state.globals[f"predef_out_{register}"]
                  for register in REGISTERS)
            ),
        )


class NativeDelaySummary(angr.SimProcedure):
    def run(
        self, callee_state: claripy.ast.BV, observations: claripy.ast.BV
    ) -> None:  # type: ignore[override]
        self.state.globals["call_delay"] = claripy.Concat(
            self.state.memory.load(callee_state, 10),
            self.state.memory.load(observations, 1),
            self.state.memory.load(NATIVE_MEMORY + R_BGP, 1),
        )
        self.state.memory.store(
            callee_state,
            claripy.Concat(
                *(self.state.globals[f"delay_out_{register}"]
                  for register in REGISTERS)
            ),
        )


class Sm83AndImmediateExact(angr.SimProcedure):
    """SM83 AND sets H, unlike the generic Z80 p-code model."""

    def __init__(self, immediate: int, next_address: int):
        super().__init__()
        self._immediate = immediate
        self._next_address = next_address

    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a &= self._immediate
        self.state.regs.f = claripy.If(
            self.state.regs.a == 0,
            claripy.BVV(0x50, 8),
            claripy.BVV(0x10, 8),
        )
        self.jump(self._next_address)


def _set_assembly_outputs(state: angr.SimState, kind: str) -> None:
    for register in REGISTERS:
        value = state.globals[f"{kind}_out_{register}"]
        if register == "f":
            value = sm83_flags_to_z80(value)
        setattr(state.regs, register, value)


def _inputs(prefix: str) -> dict[str, claripy.ast.BV]:
    values = symbolic_registers(prefix)
    for field in PREDEF_FIELDS:
        values[field] = claripy.BVS(f"{prefix}_{field}", 8)
    values["palette"] = claripy.BVS(f"{prefix}_palette", 8)
    for kind in ("predef", "delay"):
        for register in REGISTERS:
            values[f"{kind}_out_{register}"] = (
                claripy.Concat(
                    claripy.BVS(f"{prefix}_{kind}_out_flags", 4),
                    claripy.BVV(0, 4),
                )
                if register == "f"
                else claripy.BVS(f"{prefix}_{kind}_out_{register}", 8)
            )
    return values


def _setup(state: angr.SimState, values: dict[str, claripy.ast.BV]) -> None:
    for field in PREDEF_FIELDS:
        state.globals[field] = values[field]
    for kind in ("predef", "delay"):
        for register in REGISTERS:
            state.globals[f"{kind}_out_{register}"] = values[
                f"{kind}_out_{register}"
            ]
    state.globals["call_predef"] = claripy.BVV(0, 112)
    state.globals["call_delay"] = claripy.BVV(0, 96)


def _calls(state: angr.SimState) -> claripy.ast.BV:
    return claripy.Concat(
        state.globals["call_predef"], state.globals["call_delay"]
    )


def _assembly(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    location = symbol_location(SYMBOLS, "ChangeBGPalColor0_4Frames")
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
    project.hook(base, AssemblyPredefSummary(base + 3), length=3)
    project.hook(base + 3, Sm83LoadAHighImmediate(0x47, base + 5), length=2)
    project.hook(base + 5, Sm83OrRegister("b", base + 6), length=1)
    project.hook(base + 6, Sm83StoreAHighImmediate(0x47, base + 8), length=2)
    project.hook(base + 10, AssemblyDelaySummary(base + 13), length=3)
    project.hook(base + 13, Sm83LoadAHighImmediate(0x47, base + 15), length=2)
    project.hook(base + 15, Sm83AndImmediateExact(0xFC, base + 17), length=2)
    project.hook(base + 17, Sm83StoreAHighImmediate(0x47, base + 19), length=2)
    state = project.factory.blank_state(addr=base)
    set_assembly_registers(state, values)
    state.regs.sp = claripy.BVV(STACK, 16)
    state.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    state.memory.store(R_BGP, values["palette"])
    _setup(state, values)
    returned = collect_returns(project, state, RETURN)
    assert len(returned) == 1
    end = returned[0]
    return [
        Endpoint(
            **assembly_registers(end),
            predef=claripy.Concat(
                *(end.globals[field] for field in PREDEF_FIELDS)
            ),
            calls=_calls(end),
            palette=end.memory.load(R_BGP, 1),
            constraints=tuple(end.solver.constraints),
        )
    ]


def _native(values: dict[str, claripy.ast.BV]) -> list[Endpoint]:
    project = angr.Project(NATIVE_ELF, auto_load_libs=False)
    function = project.loader.find_symbol(
        "port_change_bg_pal_color0_4frames_private"
    )
    predef = project.loader.find_symbol("port_get_predef_registers")
    delay = project.loader.find_symbol("port_delay_frames")
    assert function is not None and predef is not None and delay is not None
    project.hook(predef.rebased_addr, NativePredefSummary())
    project.hook(delay.rebased_addr, NativeDelaySummary())
    state = project.factory.call_state(
        function.rebased_addr, NATIVE_STATE, NATIVE_MEMORY
    )
    store_native_registers(state, NATIVE_STATE, values)
    for offset, field in enumerate(PREDEF_FIELDS, 8):
        state.memory.store(NATIVE_STATE + offset, values[field])
    state.memory.store(NATIVE_MEMORY + R_BGP, values["palette"])
    _setup(state, values)
    manager = project.factory.simulation_manager(state)
    manager.run()
    assert not manager.errored
    return [
        Endpoint(
            **native_registers(end, NATIVE_STATE),
            predef=end.memory.load(NATIVE_STATE + 8, len(PREDEF_FIELDS)),
            calls=_calls(end),
            palette=end.memory.load(NATIVE_MEMORY + R_BGP, 1),
            constraints=tuple(end.solver.constraints),
        )
        for end in manager.deadended
    ]


@pytest.mark.skipif(not NATIVE_ELF.exists(), reason="run native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(), reason="run `make red`")
def test_change_bg_pal_color0_4frames_private_pathwise_equivalence() -> None:
    values = _inputs("change_bg_pal_color0_4frames")
    assert_pathwise_equivalent(
        _assembly(values),
        _native(values),
        (*REGISTERS, "predef", "calls", "palette"),
    )
