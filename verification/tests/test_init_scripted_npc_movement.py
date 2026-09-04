from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
import pytest
from archinfo import ArchPcode

from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS, assembly_registers, native_registers, set_assembly_registers, store_native_registers, symbolic_registers
from verification.harness.rom import linked_bytes, rom_window, symbol_location

ROOT=Path(__file__).resolve().parents[2]; ELF=ROOT/'verification/build/ports.elf'; ROM=ROOT/'pokered.gbc'; SYMBOLS=ROOT/'pokered.sym'
NS,NM,STACK,RET=0x100000,0x200000,0xd000,0xffff
S1,S2,OFFSET,SLOT,FRAME,INDEX,COUNTER=0xc100,0xc200,0xffda,0xffe9,0xffea,0xcd37,0xcf18
BODY=bytes.fromhex('afea37cd3e08ea18cfc3c352')

@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;state:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]

class XorA(angr.SimProcedure):
 def __init__(self,n:int):super().__init__();self.n=n
 def run(self):self.state.regs.a=claripy.BVV(0,8);self.state.regs.f=claripy.BVV(0x40,8);self.jump(self.n) # type: ignore[override]
class Imm(angr.SimProcedure):
 def __init__(self,v:int,n:int):super().__init__();self.v=v;self.n=n
 def run(self):self.state.regs.a=claripy.BVV(self.v,8);self.jump(self.n) # type: ignore[override]
class Store(angr.SimProcedure):
 def __init__(self,a:int,n:int):super().__init__();self.a=a;self.n=n
 def run(self):self.state.memory.store(self.a,self.state.regs.a);self.jump(self.n) # type: ignore[override]
class TailAnimDown(angr.SimProcedure):
 """Complete AnimScriptedNPCMovement transition for facing-down/non-rollover domain."""
 def run(self):
  v=self.state.memory.load(S2+14,1); slot=((v-1)<<4)|claripy.LShR(v-1,4); self.state.regs.b=slot; self.state.regs.h=claripy.BVV(0xc1,8); self.state.regs.a=slot; self.state.regs.f=claripy.If(slot==0,claripy.BVV(0x40,8),claripy.BVV(0,8))|claripy.If(((v-1)&15)>15,claripy.BVV(0x10,8),claripy.BVV(0,8)); self.state.memory.store(SLOT,slot)
  self.state.regs.a=claripy.BVV(1,8); self.state.regs.l=claripy.BVV(7,8); self.state.memory.store(S1+7,self.state.regs.a); self.state.regs.f=claripy.BVV(0x12,8)
  self.state.regs.a=claripy.BVV(2,8); self.state.regs.l=claripy.BVV(2,8); self.state.regs.f=claripy.BVV(0,8); self.state.regs.a=self.state.memory.load(SLOT,1); self.state.regs.b=self.state.regs.a; self.state.regs.a=self.state.memory.load(FRAME,1); wide=claripy.ZeroExt(1,self.state.regs.a)+claripy.ZeroExt(1,self.state.regs.b); self.state.regs.a=wide[7:0]; self.state.regs.f=claripy.If(self.state.regs.a==0,claripy.BVV(0x40,8),claripy.BVV(0,8))|claripy.If((self.state.regs.a&15)<self.state.regs.b&15,claripy.BVV(0x10,8),claripy.BVV(0,8))|claripy.ZeroExt(7,wide[8]); self.state.memory.store(S1+2,self.state.regs.a); self.jump(RET) # type: ignore[override]

def setup(s:angr.SimState,b:int,v:claripy.ast.BV,o:claripy.ast.BV)->None:
 for a in (*range(S1,S1+16),*range(S2,S2+16)):s.memory.store(b+a,claripy.BVV(0,8))
 for a,x in ((OFFSET,0),(S2+14,v),(S1+9,0),(S1+7,0),(S1+8,0),(S1+2,0),(SLOT,0),(FRAME,o),(INDEX,0xaa),(COUNTER,0xbb)):s.memory.store(b+a,x if isinstance(x,claripy.ast.BV) else claripy.BVV(x,8))
def end(s:angr.SimState,n:bool)->E:
 b=NM if n else 0;r=native_registers(s,NS) if n else assembly_registers(s); w=(*range(S1,S1+16),*range(S2,S2+16),OFFSET,SLOT,FRAME,INDEX,COUNTER);return E(**r,state=claripy.Concat(*(s.memory.load(b+x,1) for x in w)),constraints=tuple(s.solver.constraints))
def asm(v:dict[str,claripy.ast.BV])->list[E]:
 l=symbol_location(SYMBOLS,'InitScriptedNPCMovement');assert linked_bytes(ROM,l,len(BODY))==BODY;p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});q=l.address;p.hook(q,XorA(q+1),length=1);p.hook(q+1,Store(INDEX,q+4),length=3);p.hook(q+4,Imm(8,q+6),length=2);p.hook(q+6,Store(COUNTER,q+9),length=3);p.hook(q+9,TailAnimDown(),length=3);s=p.factory.blank_state(addr=q);set_assembly_registers(s,v);setup(s,0,v['vram'],v['output']);s.regs.sp=claripy.BVV(STACK,16);s.memory.store(STACK,claripy.BVV(RET,16),endness='Iend_LE');m=p.factory.simulation_manager(s);m.explore(find=RET);assert not m.errored and m.found;return [end(x,False) for x in m.found]
def native(v:dict[str,claripy.ast.BV])->list[E]:
 p=angr.Project(ELF,auto_load_libs=False);f=p.loader.find_symbol('port_init_scripted_npc_movement');assert f;s=p.factory.call_state(f.rebased_addr,NS,NM);store_native_registers(s,NS,v);setup(s,NM,v['vram'],v['output']);m=p.factory.simulation_manager(s);m.run();assert not m.errored and m.deadended;return [end(x,True) for x in m.deadended]
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMBOLS.exists(),reason='build artifacts missing')
def test_init_scripted_npc_movement_pathwise_equivalence()->None:
 v=symbolic_registers('init_scripted_npc');v['vram']=claripy.BVS('init_scripted_vram',8);v['output']=claripy.BVS('init_scripted_output',8);assert_pathwise_equivalent(asm(v),native(v),(*REGISTERS,'state'))
