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
from verification.harness.rom import (
    linked_bytes, rom_window, sm83_flags_to_z80, symbol_location,
    z80_flags_to_sm83,
)
from verification.harness.sm83_shims import (
    Sm83AddHlRegisterPair, Sm83AddRegister, Sm83CpImmediate, Sm83CpRegister,
    Sm83DecRegister, Sm83IncRegister, Sm83LoadAAtHlIncrement,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMS = ROOT / "pokered.sym"
NS = 0x100000
NM = 0x200000
STACK = 0xD800
RETURN = 0xFFFF
DONE_MACHINE = 0xEFFE
BUFFER = 0xCD6D
EXPECTED = bytes.fromhex(
    "fab5d0ea1ed1fec4d2f32ff0b8f5e5c5d5fab6d03d200bcd9e2f210b00195d54"
    "1840fab7d0e0b8ea0020fab6d03d8716005f300114215d37192ae0967ee095f095"
    "67f0966ffab5d0470e00545d2afe5020fb0c78b920f4626b116dcd011400cdb500"
    "7bea8dcf7aea8ecfd1c1e1f1e0b8ea0020c9"
)
GLOBAL_NAMES = (
    "index", "type", "predef", "named", "loaded", "rom", "swap",
    "swap_plus", "unused_low", "unused_high",
)


@dataclass(frozen=True)
class E:
    a: claripy.ast.BV; f: claripy.ast.BV; b: claripy.ast.BV; c: claripy.ast.BV
    d: claripy.ast.BV; e: claripy.ast.BV; h: claripy.ast.BV; l: claripy.ast.BV
    globals: claripy.ast.BV; buffer: claripy.ast.BV; saved: claripy.ast.BV
    calls: claripy.ast.BV; result: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


def _concat_regs(values: dict[str, claripy.ast.BV]) -> claripy.ast.BV:
    return claripy.Concat(*(values[name] for name in REGISTERS))


class LoadGlobal(angr.SimProcedure):
    def __init__(self, name: str, nxt: int) -> None:
        super().__init__(); self.name = name; self.nxt = nxt
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a = self.state.globals[self.name]; self.jump(self.nxt)


class StoreGlobal(angr.SimProcedure):
    def __init__(self, name: str, nxt: int) -> None:
        super().__init__(); self.name = name; self.nxt = nxt
    def run(self) -> None:  # type: ignore[override]
        self.state.globals[self.name] = self.state.regs.a; self.jump(self.nxt)


class CopyRegister(angr.SimProcedure):
    def __init__(self, destination: str, source: str, nxt: int) -> None:
        super().__init__(); self.destination = destination; self.source = source; self.nxt = nxt
    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.destination, getattr(self.state.regs, self.source)); self.jump(self.nxt)


class LoadRegisterImmediate(angr.SimProcedure):
    def __init__(self, register: str, value: int, nxt: int) -> None:
        super().__init__(); self.register = register; self.value = value; self.nxt = nxt
    def run(self) -> None:  # type: ignore[override]
        setattr(self.state.regs, self.register, claripy.BVV(self.value, 8)); self.jump(self.nxt)


def _apply_regs(state: angr.SimState, prefix: str) -> None:
    for name in REGISTERS:
        value = state.globals[f"{prefix}_{name}"]
        if name == "f": value = sm83_flags_to_z80(value)
        setattr(state.regs, name, value)


class MachineSummary(angr.SimProcedure):
    def run(self) -> None:  # type: ignore[override]
        self.state.globals["machine_call"] = _concat_regs(assembly_registers(self.state))
        _apply_regs(self.state, "machine")
        self.state.globals["named"] = self.state.globals["machine_named"]
        for i in range(5):
            self.state.memory.store(BUFFER + i, self.state.globals[f"machine_buffer{i}"])
        self.jump(DONE_MACHINE)


class MonSummary(angr.SimProcedure):
    def __init__(self, nxt: int) -> None:
        super().__init__(); self.nxt = nxt
    def run(self) -> None:  # type: ignore[override]
        self.state.globals["mon_call"] = _concat_regs(assembly_registers(self.state))
        _apply_regs(self.state, "mon")
        for name in ("named", "loaded", "rom"):
            self.state.globals[name] = self.state.globals[f"mon_{name}"]
        for i in range(11):
            self.state.memory.store(BUFFER + i, self.state.globals[f"mon_buffer{i}"])
        self.jump(self.nxt)


class NativeMachineSummary(angr.SimProcedure):
    def run(self, state_ptr: claripy.ast.BV, memory: claripy.ast.BV) -> None:  # type: ignore[override]
        self.state.globals["machine_call"] = self.state.memory.load(state_ptr, 8)
        for i, name in enumerate(REGISTERS):
            self.state.memory.store(state_ptr + i, self.state.globals[f"machine_{name}"])
        self.state.memory.store(state_ptr + 8, self.state.globals["machine_named"])
        for i in range(5):
            self.state.memory.store(memory + BUFFER + i, self.state.globals[f"machine_buffer{i}"])


class NativeMonSummary(angr.SimProcedure):
    def run(self, state_ptr: claripy.ast.BV, memory: claripy.ast.BV) -> None:  # type: ignore[override]
        self.state.globals["mon_call"] = self.state.memory.load(state_ptr, 8)
        for i, name in enumerate(REGISTERS):
            self.state.memory.store(state_ptr + i, self.state.globals[f"mon_{name}"])
        for i, name in enumerate(("named", "loaded", "rom"), 8):
            self.state.memory.store(state_ptr + i, self.state.globals[f"mon_{name}"])
        for i in range(11):
            self.state.memory.store(memory + BUFFER + i, self.state.globals[f"mon_buffer{i}"])


class CopySummary(angr.SimProcedure):
    def __init__(self, nxt: int) -> None:
        super().__init__(); self.nxt = nxt
    def run(self) -> None:  # type: ignore[override]
        self.state.globals["copy_call"] = _concat_regs(assembly_registers(self.state))
        hl = self.state.regs.hl + 20; de = self.state.regs.de
        for i in range(20): self.state.memory.store(de + i, self.state.globals[f"copy{i}"])
        self.state.regs.a = 0; self.state.regs.f = sm83_flags_to_z80(claripy.BVV(0x80, 8))
        self.state.regs.bc = 0; self.state.regs.hl = hl; self.state.regs.de = de + 20
        self.jump(self.nxt)


class NativeCopySummary(angr.SimProcedure):
    def run(self, regs: claripy.ast.BV, memory: claripy.ast.BV) -> None:  # type: ignore[override]
        self.state.globals["copy_call"] = self.state.memory.load(regs, 8)
        hl = self.state.memory.load(regs + 6, 2) + 20
        de = self.state.memory.load(regs + 4, 2)
        for i in range(20):
            self.state.memory.store(memory + claripy.ZeroExt(48, de) + i, self.state.globals[f"copy{i}"])
        self.state.memory.store(regs, claripy.BVV(0x80, 16)); self.state.memory.store(regs + 2, claripy.BVV(0, 16))
        self.state.memory.store(regs + 4, de + 20); self.state.memory.store(regs + 6, hl)


def _values(tag: str) -> dict[str, claripy.ast.BV]:
    v = symbolic_registers(tag)
    for name in GLOBAL_NAMES: v[name] = claripy.BVS(f"{tag}_{name}", 8)
    for prefix in ("machine", "mon"):
        for name in REGISTERS:
            v[f"{prefix}_{name}"] = (claripy.Concat(claripy.BVS(f"{tag}_{prefix}_flags", 4), claripy.BVV(0, 4))
                                        if name == "f" else claripy.BVS(f"{tag}_{prefix}_{name}", 8))
    for name in ("machine_named", "mon_named", "mon_loaded", "mon_rom"):
        v[name] = claripy.BVS(f"{tag}_{name}", 8)
    for i in range(20):
        v[f"initial{i}"] = claripy.BVS(f"{tag}_initial{i}", 8)
        v[f"copy{i}"] = claripy.BVS(f"{tag}_copy{i}", 8)
        if i < 11: v[f"mon_buffer{i}"] = claripy.BVS(f"{tag}_mon_buffer{i}", 8)
        if i < 5: v[f"machine_buffer{i}"] = claripy.BVS(f"{tag}_machine_buffer{i}", 8)
    v["pointer_low"] = claripy.BVS(f"{tag}_pointer_low", 8)
    v["pointer_high"] = claripy.BVS(f"{tag}_pointer_high", 8)
    return v


def _put_globals_asm(state: angr.SimState, v: dict[str, claripy.ast.BV], list_type: int) -> None:
    for name in GLOBAL_NAMES: state.globals[name] = (claripy.BVV(list_type, 8) if name == "type" else v[name])
    for name, value in v.items(): state.globals[name] = value
    state.globals["type"] = claripy.BVV(list_type, 8)
    state.globals["machine_call"] = claripy.BVV(0, 64); state.globals["mon_call"] = claripy.BVV(0, 64); state.globals["copy_call"] = claripy.BVV(0, 64)
    for i in range(20): state.memory.store(BUFFER + i, v[f"initial{i}"])
    if list_type != 1:
        address = 0x375D + 2 * (list_type - 1)
        state.memory.store(address, v["pointer_low"]); state.memory.store(address + 1, v["pointer_high"])


def _put_globals_native(state: angr.SimState, v: dict[str, claripy.ast.BV], list_type: int) -> None:
    offsets = {name: 8 + i for i, name in enumerate(GLOBAL_NAMES)}
    for name in GLOBAL_NAMES:
        state.memory.store(NS + offsets[name], claripy.BVV(list_type, 8) if name == "type" else v[name])
    for name, value in v.items(): state.globals[name] = value
    state.globals["machine_call"] = claripy.BVV(0, 64); state.globals["mon_call"] = claripy.BVV(0, 64); state.globals["copy_call"] = claripy.BVV(0, 64)
    for i in range(20): state.memory.store(NM + BUFFER + i, v[f"initial{i}"])
    if list_type != 1:
        address = 0x375D + 2 * (list_type - 1)
        state.memory.store(NM + address, v["pointer_low"]); state.memory.store(NM + address + 1, v["pointer_high"])


def _stack_saved(state: angr.SimState) -> claripy.ast.BV:
    sp = state.regs.sp
    return claripy.Concat(state.memory.load(sp + 7, 1), z80_flags_to_sm83(state.memory.load(sp + 6, 1)),
                           state.memory.load(sp + 3, 1), state.memory.load(sp + 2, 1),
                           state.memory.load(sp + 1, 1), state.memory.load(sp, 1),
                           state.memory.load(sp + 5, 1), state.memory.load(sp + 4, 1))


def _endpoint(state: angr.SimState, native: bool, result: claripy.ast.BV) -> E:
    regs = native_registers(state, NS) if native else assembly_registers(state)
    if native:
        glob = state.memory.load(NS + 8, 10); buf = state.memory.load(NM + BUFFER, 20)
        saved = claripy.If(result == 2, state.memory.load(NS + 18, 8), claripy.BVV(0, 64))
    else:
        glob = claripy.Concat(*(state.globals[n] for n in GLOBAL_NAMES)); buf = state.memory.load(BUFFER, 20)
        saved = claripy.If(result == 2, _stack_saved(state), claripy.BVV(0, 64))
    calls = claripy.Concat(state.globals["machine_call"], state.globals["mon_call"], state.globals["copy_call"])
    return E(**regs, globals=glob, buffer=buf, saved=saved, calls=calls, result=result, constraints=tuple(state.solver.constraints))


def _project(entry: int) -> angr.Project:
    loc = symbol_location(SYMS, "GetName")
    return angr.Project(rom_window(ROM, loc.bank), auto_load_libs=False, rebase_granularity=0x100,
                        main_opts={"backend": "blob", "arch": ArchPcode("z80:LE:16:default"), "base_addr": 0, "entry_point": entry})


def _hooks_begin(p: angr.Project) -> tuple[int, int]:
    b = symbol_location(SYMS, "GetName").address; scan = symbol_location(SYMS, "GetName.nextName").address
    p.hook(b, LoadGlobal("index", b + 3), length=3); p.hook(b + 3, StoreGlobal("named", b + 6), length=3)
    p.hook(b + 6, Sm83CpImmediate(0xC4, b + 8), length=2)
    p.hook(symbol_location(SYMS, "GetMachineName").address, MachineSummary(), length=1)
    p.hook(b + 11, LoadGlobal("loaded", b + 13), length=2); p.hook(b + 17, LoadGlobal("type", b + 20), length=3)
    p.hook(b + 20, Sm83DecRegister("a", b + 21), length=1); p.hook(b + 23, MonSummary(b + 26), length=3)
    p.hook(b + 29, Sm83AddHlRegisterPair("de", b + 30), length=1)
    p.hook(b + 34, LoadGlobal("predef", b + 37), length=3); p.hook(b + 37, StoreGlobal("loaded", b + 39), length=2); p.hook(b + 39, StoreGlobal("rom", b + 42), length=3)
    p.hook(b + 42, LoadGlobal("type", b + 45), length=3); p.hook(b + 45, Sm83DecRegister("a", b + 46), length=1); p.hook(b + 46, Sm83AddRegister("a", b + 47), length=1)
    p.hook(b + 57, Sm83LoadAAtHlIncrement(b + 58), length=1)
    p.hook(b + 58, StoreGlobal("swap_plus", b + 60), length=2); p.hook(b + 61, StoreGlobal("swap", b + 63), length=2)
    p.hook(b + 63, LoadGlobal("swap", b + 65), length=2); p.hook(b + 66, LoadGlobal("swap_plus", b + 68), length=2); p.hook(b + 69, LoadGlobal("index", b + 72), length=3)
    p.hook(b + 72, CopyRegister("b", "a", b + 73), length=1); p.hook(b + 73, LoadRegisterImmediate("c", 0, b + 75), length=2)
    p.hook(b + 99, StoreGlobal("unused_low", b + 102), length=3); p.hook(b + 103, StoreGlobal("unused_high", b + 106), length=3)
    p.hook(b + 110, StoreGlobal("loaded", b + 112), length=2); p.hook(b + 112, StoreGlobal("rom", b + 115), length=3)
    return b, scan


def _asm_begin(v: dict[str, claripy.ast.BV], list_type: int) -> list[E]:
    b = symbol_location(SYMS, "GetName").address; p = _project(b); _, scan = _hooks_begin(p)
    s = p.factory.blank_state(addr=b); set_assembly_registers(s, v); _put_globals_asm(s, v, list_type)
    s.regs.sp = STACK; s.memory.store(STACK, claripy.BVV(RETURN, 16), endness="Iend_LE")
    m = p.factory.simulation_manager(s); m.explore(find=lambda x: x.addr in (DONE_MACHINE, RETURN, scan), num_find=2); assert not m.errored
    return [_endpoint(x, False, claripy.BVV(0 if x.addr == DONE_MACHINE else (2 if x.addr == scan else 1), 8)) for x in m.found]


def _native_begin(v: dict[str, claripy.ast.BV], list_type: int) -> list[E]:
    p = angr.Project(ELF, auto_load_libs=False); fn=p.loader.find_symbol("port_get_name_begin"); ma=p.loader.find_symbol("port_get_machine_name"); mo=p.loader.find_symbol("port_get_mon_name"); assert fn and ma and mo
    p.hook(ma.rebased_addr, NativeMachineSummary()); p.hook(mo.rebased_addr, NativeMonSummary())
    s=p.factory.call_state(fn.rebased_addr,NS,NM); store_native_registers(s,NS,v); _put_globals_native(s,v,list_type)
    m=p.factory.simulation_manager(s);m.run();assert not m.errored
    return [_endpoint(x,True,x.regs.rax[7:0]) for x in m.deadended]


def _simple_phase(symbol: str, native_symbol: str, values: dict[str, claripy.ast.BV], stop: int) -> tuple[list[E], list[E]]:
    entry=symbol_location(SYMS,symbol).address;p=_project(entry);s=p.factory.blank_state(addr=entry);set_assembly_registers(s,values)
    m=p.factory.simulation_manager(s);m.explore(find=stop);assert not m.errored
    aa=[E(**assembly_registers(x),globals=claripy.BVV(0,80),buffer=claripy.BVV(0,160),saved=claripy.BVV(0,64),calls=claripy.BVV(0,192),result=claripy.BVV(0,8),constraints=tuple(x.solver.constraints)) for x in m.found]
    q=angr.Project(ELF,auto_load_libs=False);fn=q.loader.find_symbol(native_symbol);assert fn;ns=q.factory.call_state(fn.rebased_addr,NS);store_native_registers(ns,NS,values);nm=q.factory.simulation_manager(ns);nm.run();assert not nm.errored
    nn=[E(**native_registers(x,NS),globals=claripy.BVV(0,80),buffer=claripy.BVV(0,160),saved=claripy.BVV(0,64),calls=claripy.BVV(0,192),result=claripy.BVV(0,8),constraints=tuple(x.solver.constraints)) for x in nm.deadended]
    return aa,nn


def _scan_char(values: dict[str, claripy.ast.BV], native: bool, hl_value: int) -> list[E]:
    if not native:
        entry=symbol_location(SYMS,"GetName.nextChar").address; next_name=symbol_location(SYMS,"GetName.nextName").address; finish=symbol_location(SYMS,"GetName.gotPtr").address-0x0b
        p=_project(entry);p.hook(entry,Sm83LoadAAtHlIncrement(entry+1),length=1);p.hook(entry+1,Sm83CpImmediate(0x50,entry+3),length=2);p.hook(entry+5,Sm83IncRegister("c",entry+6),length=1);p.hook(entry+7,Sm83CpRegister("c",entry+8),length=1)
        s=p.factory.blank_state(addr=entry);set_assembly_registers(s,values);s.regs.hl=hl_value;s.memory.store(hl_value,values["fetched"])
        m=p.factory.simulation_manager(s);m.step();m.explore(find=lambda x:x.addr in(entry,next_name,finish),num_find=3);assert not m.errored
        return [E(**assembly_registers(x),globals=claripy.BVV(0,80),buffer=claripy.BVV(0,160),saved=claripy.BVV(0,64),calls=claripy.BVV(0,192),result=claripy.BVV(0 if x.addr==entry else (1 if x.addr==next_name else 2),8),constraints=tuple(x.solver.constraints)) for x in m.found]
    p=angr.Project(ELF,auto_load_libs=False);fn=p.loader.find_symbol("port_get_name_scan_char");assert fn;s=p.factory.call_state(fn.rebased_addr,NS,NM);store_native_registers(s,NS,values);s.memory.store(NS+6,claripy.BVV(hl_value,16));s.memory.store(NM+hl_value,values["fetched"]);m=p.factory.simulation_manager(s);m.run();assert not m.errored
    return [E(**native_registers(x,NS),globals=claripy.BVV(0,80),buffer=claripy.BVV(0,160),saved=claripy.BVV(0,64),calls=claripy.BVV(0,192),result=x.regs.rax[7:0],constraints=tuple(x.solver.constraints)) for x in m.deadended]


def _finish(v: dict[str,claripy.ast.BV],saved:dict[str,claripy.ast.BV],native:bool)->list[E]:
    b=symbol_location(SYMS,"GetName").address;entry=b+0x57
    if not native:
        p=_project(entry);p.hook(b+0x5f,CopySummary(b+0x62),length=3);p.hook(b+0x63,StoreGlobal("unused_low",b+0x66),length=3);p.hook(b+0x67,StoreGlobal("unused_high",b+0x6a),length=3);p.hook(b+0x6e,StoreGlobal("loaded",b+0x70),length=2);p.hook(b+0x70,StoreGlobal("rom",b+0x73),length=3)
        s=p.factory.blank_state(addr=entry);set_assembly_registers(s,v);_put_globals_asm(s,v,2);s.regs.sp=STACK
        pairs=(claripy.Concat(saved['d'],saved['e']),claripy.Concat(saved['b'],saved['c']),claripy.Concat(saved['h'],saved['l']),claripy.Concat(saved['a'],sm83_flags_to_z80(saved['f'])))
        for i,pair in enumerate(pairs):s.memory.store(STACK+2*i,pair,endness='Iend_LE')
        s.memory.store(STACK+8,claripy.BVV(RETURN,16),endness='Iend_LE');s.globals['copy_call']=claripy.BVV(0,64);m=p.factory.simulation_manager(s);m.explore(find=RETURN);assert not m.errored
        return [_endpoint(x,False,claripy.BVV(0,8)) for x in m.found]
    p=angr.Project(ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_get_name_finish_scan');cp=p.loader.find_symbol('port_copy_data');assert fn and cp;p.hook(cp.rebased_addr,NativeCopySummary());s=p.factory.call_state(fn.rebased_addr,NS,NM);store_native_registers(s,NS,v);_put_globals_native(s,v,2);s.memory.store(NS+18,_concat_regs(saved));s.memory.store(NS+26,saved['a']);m=p.factory.simulation_manager(s);m.run();assert not m.errored
    return [_endpoint(x,True,claripy.BVV(0,8)) for x in m.deadended]


def _complete(paths:list[E])->None:
    s=claripy.Solver();s.add(claripy.Not(claripy.Or(*(claripy.And(*x.constraints) for x in paths))));assert not s.satisfiable()


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason="build artifacts required")
def test_get_name_pathwise_equivalence()->None:
    assert linked_bytes(ROM,symbol_location(SYMS,"GetName"),len(EXPECTED))==EXPECTED
    for list_type in range(1,8):
        v=_values(f"get_name_begin_{list_type}");a=_asm_begin(v,list_type);n=_native_begin(v,list_type);assert_pathwise_equivalent(a,n,(*REGISTERS,"globals","buffer","saved","calls","result"));_complete(a);_complete(n)
    v=symbolic_registers("get_name_start");a,n=_simple_phase("GetName.nextName","port_get_name_start_name",v,symbol_location(SYMS,"GetName.nextChar").address);assert_pathwise_equivalent(a,n,REGISTERS)
    for hl_value in (0x4000,0xffff):
        v=symbolic_registers(f"get_name_char_{hl_value:x}");v["fetched"]=claripy.BVS(f"get_name_fetched_{hl_value:x}",8);a=_scan_char(v,False,hl_value);n=_scan_char(v,True,hl_value);assert_pathwise_equivalent(a,n,(*REGISTERS,"result"));_complete(a);_complete(n)
    v=_values("get_name_finish");saved=symbolic_registers("get_name_finish_saved");assert_pathwise_equivalent(_finish(v,saved,False),_finish(v,saved,True),(*REGISTERS,"globals","buffer","calls"))
