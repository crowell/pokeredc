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
from verification.harness.sm83_shims import (
    Sm83AddHlRegisterPair, Sm83LoadAHighImmediate, Sm83LoadAImmediate,
)

ROOT=Path(__file__).resolve().parents[2];ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMS=ROOT/'pokered.sym'
NS=0x100000;NM=0x200000;STACK=0xE000;RETURN=0xFFFF
TURN=0xFFF3;PB=0xD02D;PP=0xD188;EB=0xCFFE;EP=0xD8C1;PMI=0xCC2E;PMN=0xCC2F;EMI=0xCCE2;EMP=0xCFE8;STRIDE=44
EXPECTED=bytes.fromhex('f0f3a7212dd01188d1fa2ecc280921fecf11c1d8fae2cc06004f0934626b09f0f3a7fa2fcc2803fae8cf012c00cd873a34c9')

@dataclass(frozen=True)
class E:
    a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV
    pp:claripy.ast.BV;call:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]

class IncAtHl(angr.SimProcedure):
    def __init__(self,nxt:int)->None:super().__init__();self.nxt=nxt
    def run(self)->None:  # type: ignore[override]
        old=self.state.memory.load(self.state.regs.hl,1);result=old+1;flags=self.state.regs.f&1
        flags|=claripy.If(result==0,claripy.BVV(0x40,8),claripy.BVV(0,8));flags|=claripy.If((old&0x0f)==0x0f,claripy.BVV(0x10,8),claripy.BVV(0,8))
        self.state.memory.store(self.state.regs.hl,result);self.state.regs.f=flags;self.jump(self.nxt)

class AndA(angr.SimProcedure):
    def __init__(self,nxt:int)->None:super().__init__();self.nxt=nxt
    def run(self)->None:  # type: ignore[override]
        self.state.regs.f=claripy.If(self.state.regs.a==0,claripy.BVV(0x50,8),claripy.BVV(0x10,8));self.jump(self.nxt)

class AddSummary(angr.SimProcedure):
    def __init__(self,nxt:int)->None:super().__init__();self.nxt=nxt
    def run(self)->None:  # type: ignore[override]
        raw=claripy.Concat(*(assembly_registers(self.state)[n] for n in REGISTERS));a=self.state.regs.a;bc=self.state.regs.bc;hl=self.state.regs.hl
        self.state.globals['call']=raw;result=hl+claripy.ZeroExt(8,a)*bc;last=hl+claripy.ZeroExt(8,a-1)*bc;wide=claripy.ZeroExt(1,last)+claripy.ZeroExt(1,bc)
        flags=claripy.If(a==0,claripy.BVV(0xA0,8),claripy.BVV(0xC0,8)|claripy.If(wide[16]==1,claripy.BVV(0x10,8),claripy.BVV(0,8)))
        self.state.regs.a=0;self.state.regs.f=sm83_flags_to_z80(flags);self.state.regs.hl=result;self.jump(self.nxt)

class NativeAddSummary(angr.SimProcedure):
    def run(self,regs:claripy.ast.BV)->None:  # type: ignore[override]
        raw=self.state.memory.load(regs,8);a=self.state.memory.load(regs,1);bc=self.state.memory.load(regs+2,2);hl=self.state.memory.load(regs+6,2)
        self.state.globals['call']=raw;result=hl+claripy.ZeroExt(8,a)*bc;last=hl+claripy.ZeroExt(8,a-1)*bc;wide=claripy.ZeroExt(1,last)+claripy.ZeroExt(1,bc)
        flags=claripy.If(a==0,claripy.BVV(0xA0,8),claripy.BVV(0xC0,8)|claripy.If(wide[16]==1,claripy.BVV(0x10,8),claripy.BVV(0,8)))
        self.state.memory.store(regs,claripy.BVV(0,8));self.state.memory.store(regs+1,flags);self.state.memory.store(regs+6,result)

def _inputs(tag:str)->dict[str,claripy.ast.BV]:
    v=symbolic_registers(tag)
    for n in ('pb','pp','eb','ep'):v[n]=claripy.BVS(f'{tag}_{n}',8)
    return v

def _store(s:angr.SimState,v:dict[str,claripy.ast.BV],turn:int,move:int,which:int,base:int=0)->tuple[int,int]:
    ba=(PB if turn==0 else EB)+move;pa=(PP if turn==0 else EP)+STRIDE*which+move
    s.memory.store(base+TURN,claripy.BVV(turn,8));s.memory.store(base+PMI,claripy.BVV(move,8));s.memory.store(base+EMI,claripy.BVV(move,8));s.memory.store(base+PMN,claripy.BVV(which,8));s.memory.store(base+EMP,claripy.BVV(which,8))
    for addr,n in ((PB+move,'pb'),(PP+STRIDE*which+move,'pp'),(EB+move,'eb'),(EP+STRIDE*which+move,'ep')):s.memory.store(base+addr,v[n])
    return ba,pa

def _end(s:angr.SimState,native:bool,addresses:tuple[int,int])->E:
    base=NM if native else 0;return E(**(native_registers(s,NS) if native else assembly_registers(s)),pp=claripy.Concat(*(s.memory.load(base+a,1) for a in addresses)),call=s.globals['call'],constraints=tuple(s.solver.constraints))

def _asm(v:dict[str,claripy.ast.BV],turn:int,move:int,which:int)->list[E]:
    loc=symbol_location(SYMS,'IncrementMovePP');assert linked_bytes(ROM,loc,len(EXPECTED))==EXPECTED;p=angr.Project(rom_window(ROM,loc.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':loc.address});b=loc.address
    p.hook(b,Sm83LoadAHighImmediate(0xF3,b+2),length=2);p.hook(b+2,AndA(b+3),length=1);p.hook(b+9,Sm83LoadAImmediate(PMI,b+12),length=3);p.hook(b+20,Sm83LoadAImmediate(EMI,b+23),length=3);p.hook(b+26,Sm83AddHlRegisterPair('bc',b+27),length=1);p.hook(b+27,IncAtHl(b+28),length=1);p.hook(b+30,Sm83AddHlRegisterPair('bc',b+31),length=1);p.hook(b+31,Sm83LoadAHighImmediate(0xF3,b+33),length=2);p.hook(b+33,AndA(b+34),length=1);p.hook(b+34,Sm83LoadAImmediate(PMN,b+37),length=3);p.hook(b+39,Sm83LoadAImmediate(EMP,b+42),length=3);p.hook(b+45,AddSummary(b+48),length=3);p.hook(b+48,IncAtHl(b+49),length=1)
    s=p.factory.blank_state(addr=b);set_assembly_registers(s,v);addresses=_store(s,v,turn,move,which);s.globals['call']=claripy.BVV(0,64);s.regs.sp=STACK;s.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE');return [_end(x,False,addresses) for x in collect_returns(p,s,RETURN)]

def _native(v:dict[str,claripy.ast.BV],turn:int,move:int,which:int)->list[E]:
    p=angr.Project(ELF,auto_load_libs=False);fn=p.loader.find_symbol('port_increment_move_pp');add=p.loader.find_symbol('port_add_n_times');assert fn and add;p.hook(add.rebased_addr,NativeAddSummary());s=p.factory.call_state(fn.rebased_addr,NS,NM);store_native_registers(s,NS,v);addresses=_store(s,v,turn,move,which,NM);s.globals['call']=claripy.BVV(0,64);m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [_end(x,True,addresses) for x in m.deadended]

@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build artifacts required')
def test_increment_move_pp_pathwise_equivalence()->None:
    for turn in (0,1):
        for move in range(4):
            for which in range(6):
                v=_inputs(f'impp_{turn}_{move}_{which}');assert_pathwise_equivalent(_asm(v,turn,move,which),_native(v,turn,move,which),(*REGISTERS,'pp','call'))
