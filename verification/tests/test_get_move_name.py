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
    collect_returns, linked_bytes, rom_window, sm83_flags_to_z80, symbol_location,
)

ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "verification/build/ports.elf"
ROM = ROOT / "pokered.gbc"
SYMS = ROOT / "pokered.sym"
NS = 0x100000
NM = 0x200000
STACK = 0xD800
RETURN = 0xFFFF
BUFFER = 0xCD6D
GLOBALS = ("index", "type", "predef", "named", "loaded", "rom", "swap", "swap_plus", "unused_low", "unused_high")
EXPECTED = bytes.fromhex("e53e02eab6d0fa1ed1eab5d03e2ceab7d0cd6b37116dcde1c9")


@dataclass(frozen=True)
class E:
    a: claripy.ast.BV; f: claripy.ast.BV; b: claripy.ast.BV; c: claripy.ast.BV
    d: claripy.ast.BV; e: claripy.ast.BV; h: claripy.ast.BV; l: claripy.ast.BV
    globals: claripy.ast.BV; buffer: claripy.ast.BV; call: claripy.ast.BV
    constraints: tuple[claripy.ast.Bool, ...]


class LoadGlobal(angr.SimProcedure):
    def __init__(self, name: str, nxt: int) -> None:
        super().__init__(); self.name=name; self.nxt=nxt
    def run(self) -> None:  # type: ignore[override]
        self.state.regs.a=self.state.globals[self.name];self.jump(self.nxt)


class StoreGlobal(angr.SimProcedure):
    def __init__(self, name: str, nxt: int) -> None:
        super().__init__(); self.name=name; self.nxt=nxt
    def run(self) -> None:  # type: ignore[override]
        self.state.globals[self.name]=self.state.regs.a;self.jump(self.nxt)


class GetNameSummary(angr.SimProcedure):
    def __init__(self,nxt:int)->None:super().__init__();self.nxt=nxt
    def run(self)->None:  # type: ignore[override]
        regs=assembly_registers(self.state);self.state.globals['call']=claripy.Concat(*(regs[n] for n in REGISTERS),*(self.state.globals[n] for n in GLOBALS))
        for n in REGISTERS:
            x=self.state.globals[f'post_{n}'];setattr(self.state.regs,n,sm83_flags_to_z80(x) if n=='f' else x)
        for n in GLOBALS:self.state.globals[n]=self.state.globals[f'post_{n}']
        for i in range(20):self.state.memory.store(BUFFER+i,self.state.globals[f'post_buffer{i}'])
        self.jump(self.nxt)


class NativeGetNameSummary(angr.SimProcedure):
    def run(self,state_ptr:claripy.ast.BV,memory:claripy.ast.BV)->None:  # type: ignore[override]
        self.state.globals['call']=claripy.Concat(self.state.memory.load(state_ptr,8),self.state.memory.load(state_ptr+8,10))
        for i,n in enumerate(REGISTERS):self.state.memory.store(state_ptr+i,self.state.globals[f'post_{n}'])
        for i,n in enumerate(GLOBALS,8):self.state.memory.store(state_ptr+i,self.state.globals[f'post_{n}'])
        for i in range(20):self.state.memory.store(memory+BUFFER+i,self.state.globals[f'post_buffer{i}'])


def _values()->dict[str,claripy.ast.BV]:
    v=symbolic_registers('get_move_name')
    for n in GLOBALS:v[n]=claripy.BVS(f'get_move_name_{n}',8);v[f'post_{n}']=claripy.BVS(f'get_move_name_post_{n}',8)
    for n in REGISTERS:v[f'post_{n}']=claripy.Concat(claripy.BVS('get_move_name_post_flags',4),claripy.BVV(0,4)) if n=='f' else claripy.BVS(f'get_move_name_post_{n}',8)
    for i in range(20):v[f'initial{i}']=claripy.BVS(f'get_move_name_initial{i}',8);v[f'post_buffer{i}']=claripy.BVS(f'get_move_name_post_buffer{i}',8)
    return v


def _asm(v:dict[str,claripy.ast.BV])->list[E]:
    loc=symbol_location(SYMS,'GetMoveName');assert linked_bytes(ROM,loc,len(EXPECTED))==EXPECTED
    p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':loc.address});b=loc.address
    p.hook(b+3,StoreGlobal('type',b+6),length=3);p.hook(b+6,LoadGlobal('named',b+9),length=3);p.hook(b+9,StoreGlobal('index',b+12),length=3);p.hook(b+14,StoreGlobal('predef',b+17),length=3);p.hook(b+17,GetNameSummary(b+20),length=3)
    s=p.factory.blank_state(addr=b);set_assembly_registers(s,v)
    for n in GLOBALS:s.globals[n]=v[n]
    for n,x in v.items():s.globals[n]=x
    s.globals['call']=claripy.BVV(0,144)
    for i in range(20):s.memory.store(BUFFER+i,v[f'initial{i}'])
    s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE')
    return [_end(x,False) for x in collect_returns(p,s,RETURN)]


def _native(v:dict[str,claripy.ast.BV])->list[E]:
    p=angr.Project(ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_get_move_name');callee=p.loader.find_symbol('port_get_name');assert fn and callee;p.hook(callee.rebased_addr,NativeGetNameSummary())
    s=p.factory.call_state(fn.rebased_addr,NS,NM);store_native_registers(s,NS,v)
    for i,n in enumerate(GLOBALS,8):s.memory.store(NS+i,v[n])
    for n,x in v.items():s.globals[n]=x
    s.globals['call']=claripy.BVV(0,144)
    for i in range(20):s.memory.store(NM+BUFFER+i,v[f'initial{i}'])
    m=p.factory.simulation_manager(s);m.run();assert not m.errored
    return [_end(x,True) for x in m.deadended]


def _end(s:angr.SimState,native:bool)->E:
    return E(**(native_registers(s,NS) if native else assembly_registers(s)),globals=(s.memory.load(NS+8,10) if native else claripy.Concat(*(s.globals[n] for n in GLOBALS))),buffer=s.memory.load((NM if native else 0)+BUFFER,20),call=s.globals['call'],constraints=tuple(s.solver.constraints))


@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build artifacts required')
def test_get_move_name_pathwise_equivalence()->None:
    v=_values();assert_pathwise_equivalent(_asm(v),_native(v),(*REGISTERS,'globals','buffer','call'))
