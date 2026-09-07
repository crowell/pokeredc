from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import (
    REGISTERS, assembly_registers, native_registers, set_assembly_registers,
    store_native_registers, symbolic_registers,
)
from verification.harness.rom import linked_bytes, rom_window, symbol_location
from verification.harness.sm83_shims import (
    Sm83LoadAFromRegister, Sm83Scf, Sm83StoreAImmediate,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMBOLS = ROOT / "pokered.sym"
NS = 0x100000
NM = 0x200000
DONE = 0xEFFF
W_NAMED = 0xD11E
W_CUR_ITEM = 0xCF91
W_QUANTITY = 0xCF96
W_BAG = 0xD31D
W_NAME_INDEX = 0xD0B5
W_NAME_TYPE = 0xD0B6
W_PREDEF_BANK = 0xD0B7
H_LOADED = 0xFFB8
R_ROMB = 0x2000
W_NAME_BUFFER = 0xCD6D
W_STRING_BUFFER = 0xCF4B
EXPECTED = bytes.fromhex("78ea1ed1ea91cf79ea96cf211dd3cdcf2bd0cdcf2fcd263837c9")
GLOBALS = (W_NAMED, W_CUR_ITEM, W_QUANTITY, W_NAME_INDEX, W_NAME_TYPE,
           W_PREDEF_BANK, H_LOADED, R_ROMB)


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
    calls: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _regs(values: list[claripy.ast.BV], carry: bool | None = None) -> list[claripy.ast.BV]:
    result = list(values)
    if carry is not None:
        result[1] = claripy.BVV(0x10 if carry else 0, 8)
    return result


def _set_asm_regs(state: angr.SimState, values: list[claripy.ast.BV]) -> None:
    from verification.harness.rom import sm83_flags_to_z80
    for name, value in zip(REGISTERS, values, strict=True):
        setattr(state.regs, name, sm83_flags_to_z80(value) if name == "f" else value)


def _call_input_asm(state: angr.SimState) -> claripy.ast.BV:
    regs = assembly_registers(state)
    return claripy.Concat(*(regs[x] for x in REGISTERS),
                          *(state.memory.load(x, 1) for x in GLOBALS))


def _call_input_native(state: angr.SimState, address: claripy.ast.BV) -> claripy.ast.BV:
    regs = native_registers(state, address)
    return claripy.Concat(*(regs[x] for x in REGISTERS),
                          *(state.memory.load(NM + x, 1) for x in GLOBALS))


class LoadHL(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.state.regs.h = claripy.BVV(0xD3, 8)
        self.state.regs.l = claripy.BVV(0x1D, 8)
        self.jump(0x3E3C)


class AssemblyAdd(angr.SimProcedure):
    def __init__(self, post: list[claripy.ast.BV]) -> None:
        super().__init__(); self.post = post
    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.state.globals["add_call"] = _call_input_asm(self.state)
        _set_asm_regs(self.state, self.post)
        self.jump(0x3E3F)


class BranchNC(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        carry = (self.state.regs.f & 1) != 0
        self.successors.add_successor(self.state.copy(), 0x3E40, carry, "Ijk_Boring")
        self.successors.add_successor(self.state.copy(), DONE, claripy.Not(carry), "Ijk_Boring")


class End(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.jump(DONE)


def _name_input_asm(state: angr.SimState) -> claripy.ast.BV:
    regs = assembly_registers(state)
    return claripy.Concat(*(regs[x] for x in REGISTERS),
                          state.memory.load(W_NAME_INDEX, 1),
                          state.memory.load(W_NAME_TYPE, 1),
                          state.memory.load(W_PREDEF_BANK, 1),
                          state.memory.load(W_NAMED, 1),
                          state.memory.load(H_LOADED, 1),
                          state.memory.load(R_ROMB, 1))


class AssemblyName(angr.SimProcedure):
    def __init__(self, post: list[claripy.ast.BV], globals_post: list[claripy.ast.BV]) -> None:
        super().__init__(); self.post = post; self.globals_post = globals_post
    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        self.state.globals["name_call"] = _name_input_asm(self.state)
        _set_asm_regs(self.state, self.post)
        for address, value in zip((W_NAME_INDEX, W_NAME_TYPE, W_PREDEF_BANK,
                                   W_NAMED, H_LOADED, R_ROMB), self.globals_post):
            self.state.memory.store(address, value)
        self.state.memory.store(W_NAME_BUFFER, self.state.globals["name_post"])
        self.jump(0x3E43)


class AssemblyCopy(angr.SimProcedure):
    def __init__(self, post: list[claripy.ast.BV]) -> None:
        super().__init__(); self.post = post
    def run(self) -> None:  # type: ignore[override]
        self.inhibit_autoret = True
        regs = assembly_registers(self.state)
        self.state.globals["copy_call"] = claripy.Concat(
            *(regs[x] for x in REGISTERS), self.state.memory.load(W_NAME_BUFFER, 20),
            self.state.memory.load(W_STRING_BUFFER, 20))
        _set_asm_regs(self.state, self.post)
        self.state.memory.store(W_STRING_BUFFER, self.state.globals["string_post"])
        self.jump(0x3E46)


class NativeAdd(angr.SimProcedure):
    def __init__(self, post: list[claripy.ast.BV]) -> None:
        super().__init__(); self.post = post
    def run(self, address: claripy.ast.BV, memory: claripy.ast.BV) -> None:  # type: ignore[override]
        self.state.globals["add_call"] = _call_input_native(self.state, address)
        for i, value in enumerate(self.post): self.state.memory.store(address + i, value)


class NativeName(angr.SimProcedure):
    def __init__(self, post: list[claripy.ast.BV], globals_post: list[claripy.ast.BV]) -> None:
        super().__init__(); self.post = post; self.globals_post = globals_post
    def run(self, address: claripy.ast.BV, memory: claripy.ast.BV) -> None:  # type: ignore[override]
        self.state.globals["name_call"] = self.state.memory.load(address, 14)
        for i, value in enumerate(self.post): self.state.memory.store(address + i, value)
        for i, value in enumerate(self.globals_post): self.state.memory.store(address + 8 + i, value)
        self.state.memory.store(NM + W_NAME_BUFFER, self.state.globals["name_post"])


class NativeCopy(angr.SimProcedure):
    def __init__(self, post: list[claripy.ast.BV]) -> None:
        super().__init__(); self.post = post
    def run(self, address: claripy.ast.BV, memory: claripy.ast.BV) -> None:  # type: ignore[override]
        regs = native_registers(self.state, address)
        self.state.globals["copy_call"] = claripy.Concat(
            *(regs[x] for x in REGISTERS), self.state.memory.load(NM + W_NAME_BUFFER, 20),
            self.state.memory.load(NM + W_STRING_BUFFER, 20))
        for i, value in enumerate(self.post): self.state.memory.store(address + i, value)
        self.state.memory.store(NM + W_STRING_BUFFER, self.state.globals["string_post"])


def _setup(state: angr.SimState, values: dict[str, object], base: int = 0) -> None:
    for address, value in zip(GLOBALS, values["globals"]): state.memory.store(base + address, value)
    state.memory.store(base + W_BAG, values["bag"])
    state.memory.store(base + W_NAME_BUFFER, values["name_input"])
    state.memory.store(base + W_STRING_BUFFER, values["string_input"])
    state.globals["name_post"] = values["name_post"]
    state.globals["string_post"] = values["string_post"]


def _memory(state: angr.SimState, base: int = 0) -> claripy.ast.BV:
    return claripy.Concat(*(state.memory.load(base + x, 1) for x in GLOBALS),
                          state.memory.load(base + W_BAG, 42),
                          state.memory.load(base + W_NAME_BUFFER, 20),
                          state.memory.load(base + W_STRING_BUFFER, 20))


def _assembly(values: dict[str, object], success: bool) -> list[Endpoint]:
    loc = symbol_location(SYMBOLS, "GiveItem")
    p = angr.Project(rom_window(ROM, loc.bank), auto_load_libs=False,
        rebase_granularity=0x100, main_opts={"backend":"blob", "arch":ArchPcode("z80:LE:16:default"), "base_addr":0, "entry_point":loc.address})
    p.hook(0x3E2E, Sm83LoadAFromRegister("b", 0x3E2F), length=1)
    p.hook(0x3E2F, Sm83StoreAImmediate(W_NAMED, 0x3E32), length=3)
    p.hook(0x3E32, Sm83StoreAImmediate(W_CUR_ITEM, 0x3E35), length=3)
    p.hook(0x3E35, Sm83LoadAFromRegister("c", 0x3E36), length=1)
    p.hook(0x3E36, Sm83StoreAImmediate(W_QUANTITY, 0x3E39), length=3)
    p.hook(0x3E39, LoadHL(), length=3)
    p.hook(0x3E3C, AssemblyAdd(values["add_post"]), length=3)
    p.hook(0x3E3F, BranchNC(), length=1)
    if success:
        p.hook(0x3E40, AssemblyName(values["name_regs_post"], values["name_globals_post"]), length=3)
        p.hook(0x3E43, AssemblyCopy(values["copy_post"]), length=3)
        p.hook(0x3E46, Sm83Scf(0x3E47), length=1)
        p.hook(0x3E47, End(), length=1)
    s=p.factory.blank_state(addr=loc.address); set_assembly_registers(s,values); _setup(s,values)
    m=p.factory.simulation_manager(s); m.explore(find=DONE,num_find=1); assert not m.errored and len(m.found)==1
    e=m.found[0]; zero=claripy.BVV(0,1)
    return [Endpoint(**assembly_registers(e),memory=_memory(e),calls=claripy.Concat(e.globals["add_call"],e.globals.get("name_call",zero),e.globals.get("copy_call",zero)),constraints=tuple(e.solver.constraints))]


def _native(values: dict[str, object], success: bool) -> list[Endpoint]:
    p=angr.Project(ELF,auto_load_libs=False); f=p.loader.find_symbol("port_give_item"); a=p.loader.find_symbol("port_add_item_to_inventory_home"); n=p.loader.find_symbol("port_get_item_name"); c=p.loader.find_symbol("port_copy_to_string_buffer"); assert f and a and n and c
    p.hook(a.rebased_addr,NativeAdd(values["add_post"])); p.hook(n.rebased_addr,NativeName(values["name_regs_post"],values["name_globals_post"])); p.hook(c.rebased_addr,NativeCopy(values["copy_post"]))
    s=p.factory.call_state(f.rebased_addr,NS,NM); store_native_registers(s,NS,values); _setup(s,values,NM)
    m=p.factory.simulation_manager(s); m.run(); assert not m.errored and len(m.deadended)==1; e=m.deadended[0]; zero=claripy.BVV(0,1)
    return [Endpoint(**native_registers(e,NS),memory=_memory(e,NM),calls=claripy.Concat(e.globals["add_call"],e.globals.get("name_call",zero),e.globals.get("copy_call",zero)),constraints=tuple(e.solver.constraints))]


@pytest.mark.skipif(not ELF.exists(),reason="native")
@pytest.mark.skipif(not ROM.exists() or not SYMBOLS.exists(),reason="rom")
@pytest.mark.parametrize("success",(False,True),ids=("inventory-full","success"))
def test_give_item_pathwise_equivalence(success: bool) -> None:
    prefix=f"give_{int(success)}"; v:dict[str,object]=symbolic_registers(prefix)
    v["globals"]=[claripy.BVS(f"{prefix}_g{i}",8) for i in range(len(GLOBALS))]
    v["bag"]=claripy.BVS(f"{prefix}_bag",42*8); v["name_input"]=claripy.BVS(f"{prefix}_ni",160); v["string_input"]=claripy.BVS(f"{prefix}_si",160)
    v["name_post"]=claripy.BVS(f"{prefix}_np",160); v["string_post"]=claripy.BVS(f"{prefix}_sp",160)
    v["add_post"]=_regs([claripy.BVS(f"{prefix}_ap{i}",8) for i in range(8)],success)
    v["name_regs_post"]=_regs([claripy.BVS(f"{prefix}_nr{i}",8) for i in range(8)])
    v["name_regs_post"][1]=claripy.Concat(claripy.BVS(f"{prefix}_nrf",4),claripy.BVV(0,4))
    v["name_globals_post"]=[claripy.BVS(f"{prefix}_ng{i}",8) for i in range(6)]
    v["copy_post"]=_regs([claripy.BVS(f"{prefix}_cp{i}",8) for i in range(8)])
    v["copy_post"][1]=claripy.Concat(claripy.BVS(f"{prefix}_cpf",4),claripy.BVV(0,4))
    assert linked_bytes(ROM,symbol_location(SYMBOLS,"GiveItem"),len(EXPECTED))==EXPECTED
    assert_pathwise_equivalent(_assembly(v,success),_native(v,success),(*REGISTERS,"memory","calls"))
