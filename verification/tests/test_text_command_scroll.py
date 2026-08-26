from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83DecRegister,Sm83LoadAAtHlIncrement,Sm83StoreAAtHlIncrement,Sm83StoreAImmediate
ROOT=Path(__file__).resolve().parents[2];ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMS=ROOT/'pokered.sym';NS=0x100000;NM=0x200000;STACK=0xd000;RETURN=0xffff
REGION=0xc4a4;REGION_LEN=80;CONT=0x1b55
HANDLER=0x1be7;SCROLL=0x1b18
HANDLER_EXPECTED=bytes.fromhex('3e7feaf2c4cd181bcd181be101e1c4c3551be1')
SCROLL_EXPECTED=bytes.fromhex('21b8c411a4c4063c2a12130520fa21e1c43e7f0612220520fc0605cdaf200520fac9')
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;hl:claripy.ast.BV
 region:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 v=symbolic_registers(p);v['region_in']=claripy.BVS(f'{p}_region_in',8*REGION_LEN);v['pushed_hl']=claripy.BVS(f'{p}_pushed_hl',16)
 return v
def setup(s,v,native:bool):
 o=NM if native else 0
 s.memory.store(o+REGION,v['region_in'])
class LdHLConst(angr.SimProcedure):
 def __init__(self,val:int,n:int)->None:
  super().__init__();self._v=val;self._n=n
 def run(self):
  self.state.regs.hl=claripy.BVV(self._v,16);self.jump(self._n)
class LdDEConst(angr.SimProcedure):
 def __init__(self,val:int,n:int)->None:
  super().__init__();self._v=val;self._n=n
 def run(self):
  self.state.regs.de=claripy.BVV(self._v,16);self.jump(self._n)
class LoadBConst(angr.SimProcedure):
 def __init__(self,val:int,n:int)->None:
  super().__init__();self._v=val;self._n=n
 def run(self):
  self.state.regs.b=claripy.BVV(self._v,8);self.jump(self._n)
class StoreADE(angr.SimProcedure):
 def __init__(self,n:int)->None:
  super().__init__();self._n=n
 def run(self):
  self.state.memory.store(self.state.regs.de,self.state.regs.a);self.jump(self._n)
class IncDE(angr.SimProcedure):
 def __init__(self,n:int)->None:
  super().__init__();self._n=n
 def run(self):
  self.state.regs.de=self.state.regs.de+1;self.jump(self._n)
class LoadAConst(angr.SimProcedure):
 def __init__(self,val:int,n:int)->None:
  super().__init__();self._v=val;self._n=n
 def run(self):
  self.state.regs.a=claripy.BVV(self._v,8);self.jump(self._n)
class LdBCConst(angr.SimProcedure):
 """SM83 `LD BC,nn`."""
 def __init__(self,val:int,n:int)->None:
  super().__init__();self._v=val;self._n=n
 def run(self):
  self.state.regs.bc=claripy.BVV(self._v,16);self.jump(self._n)
class PopHL(angr.SimProcedure):
 """SM83 `POP HL`: L:=[SP], H:=[SP+1], SP:=SP+2."""
 def __init__(self,n:int)->None:
  super().__init__();self._n=n
 def run(self):
  sp=self.state.solver.eval(self.state.regs.sp)
  self.state.regs.l=self.state.memory.load(sp,1);self.state.regs.h=self.state.memory.load(sp+1,1)
  self.state.regs.sp=claripy.BVV(sp+2,16);self.jump(self._n)
class Jmp(angr.SimProcedure):
 def __init__(self,t:int)->None:
  super().__init__();self._t=t
 def run(self):
  self.jump(self._t)
class DelayFrameSite(angr.SimProcedure):
 """Proved DelayFrame composition boundary at the call site: the
 acknowledged-VBlank terminal leaves A := 0 and F := $50 in the raw
 assembly flag byte."""
 def __init__(self,n:int)->None:
  super().__init__();self._n=n
 def run(self):
  self.state.regs.a=claripy.BVV(0,8);self.state.regs.f=claripy.BVV(0x50,8);self.jump(self._n)
def assembly(v):
 l=symbol_location(SYMS,'TextCommand_SCROLL');s=symbol_location(SYMS,'ScrollTextUpOneLine');n=symbol_location(SYMS,'NextTextCommand')
 assert l.bank==0 and s.bank==0 and s.address==SCROLL and n.address==CONT
 assert linked_bytes(ROM,l,len(HANDLER_EXPECTED))==HANDLER_EXPECTED
 assert linked_bytes(ROM,s,len(SCROLL_EXPECTED))==SCROLL_EXPECTED
 p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});b=l.address;s=s.address
 p.hook(b+0,LoadAConst(0x7f,b+2),length=2)                      # ld a,$7f
 p.hook(b+2,Sm83StoreAImmediate(0xc4f2,b+5),length=3)           # ld [$c4f2],a
 p.hook(b+11,PopHL(b+12),length=1)                              # pop hl
 p.hook(b+12,LdBCConst(0xc4e1,b+15),length=3)                   # ld bc,$c4e1
 p.hook(b+15,Jmp(CONT),length=3)                                # jp NextTextCommand (continuation)
 # Nested ScrollTextUpOneLine chain (the proved callee executes for real)
 p.hook(s+0,LdHLConst(0xc4b8,s+3),length=3)
 p.hook(s+3,LdDEConst(0xc4a4,s+6),length=3)
 p.hook(s+6,LoadBConst(60,s+8),length=2)
 p.hook(s+8,Sm83LoadAAtHlIncrement(s+9),length=1)
 p.hook(s+9,StoreADE(s+10),length=1)
 p.hook(s+10,IncDE(s+11),length=1)
 p.hook(s+11,Sm83DecRegister('b',s+12),length=1)
 p.hook(s+14,LdHLConst(0xc4e1,s+17),length=3)
 p.hook(s+17,LoadAConst(0x7f,s+19),length=2)
 p.hook(s+19,LoadBConst(18,s+21),length=2)
 p.hook(s+21,Sm83StoreAAtHlIncrement(s+22),length=1)
 p.hook(s+22,Sm83DecRegister('b',s+23),length=1)
 p.hook(s+25,LoadBConst(5,s+27),length=2)
 p.hook(s+27,DelayFrameSite(s+30),length=3)
 p.hook(s+30,Sm83DecRegister('b',s+31),length=1)
 sp=STACK-2
 st=p.factory.blank_state(addr=b);set_assembly_registers(st,v);setup(st,v,False);st.regs.sp=sp
 st.memory.store(sp,v['pushed_hl'],endness='Iend_LE');st.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE')
 m=p.factory.simulation_manager(st);m.explore(find=lambda st:st.addr==CONT,num_find=64);assert not m.errored and len(m.found)==1
 out=[]
 for x in m.found:
  ar=assembly_registers(x)
  out.append(E(**{**{k:v for k,v in ar.items() if k not in ('h','l')},'hl':x.regs.hl},region=claripy.Concat(*(x.memory.load(REGION+i,1) for i in range(REGION_LEN))),constraints=tuple(x.solver.constraints)))
 return out
def native(v):
 p=angr.Project(ELF,auto_load_libs=False)
 f=p.loader.find_symbol('port_text_command_scroll');assert f
 s=p.factory.call_state(f.rebased_addr,NS,NM);store_native_registers(s,NS,v);setup(s,v,True)
 # The C models the dispatcher's `pop hl` as the entry HL: seed it with
 # the pushed text pointer the assembly side reads from its stack.
 s.memory.store(NS+6,v['pushed_hl'][15:8]);s.memory.store(NS+7,v['pushed_hl'][7:0])
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==1
 out=[]
 for x in m.deadended:
  nr=native_registers(x,NS)
  out.append(E(**{**{k:v for k,v in nr.items() if k not in ('h','l')},'hl':claripy.Concat(nr['h'],nr['l'])},region=claripy.Concat(*(x.memory.load(NM+REGION+i,1) for i in range(REGION_LEN))),constraints=tuple(x.solver.constraints)))
 return out
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
def test_text_command_scroll_pathwise_equivalence():
 v=inputs('tscr');assert_pathwise_equivalent(assembly(v),native(v),('a','f','b','c','d','e','hl','region'))
