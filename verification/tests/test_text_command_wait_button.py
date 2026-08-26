from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
ROOT=Path(__file__).resolve().parents[2];ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMS=ROOT/'pokered.sym';NS=0x100000;NM=0x200000;STACK=0xd000;RETURN=0xffff
WLINKSTATE=0xd12b;CONT=0x1b55;HANDLER=0x1c9a
HANDLER_EXPECTED=bytes.fromhex('c5cd9838c1e1c3551b')
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;hl:claripy.ast.BV
 link:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 v=symbolic_registers(p)
 v['a']=claripy.BVS(f'{p}_a',8);v['f']=claripy.BVV(0,8)
 v['b']=claripy.BVS(f'{p}_b',8);v['c']=claripy.BVS(f'{p}_c',8)
 v['h']=claripy.BVV(0xd3,8);v['l']=claripy.BVV(0x60,8)
 v['d']=claripy.BVS(f'{p}_d',8);v['e']=claripy.BVS(f'{p}_e',8)
 v['link']=claripy.BVV(0,8)
 return v
def setup(s,v,native:bool):
 o=NM if native else 0
 s.memory.store(o+WLINKSTATE,v['link'])
class PushBC(angr.SimProcedure):
 def __init__(self,n:int)->None:
  super().__init__();self._n=n
 def run(self):
  sp=self.state.solver.eval(self.state.regs.sp)
  self.state.memory.store(sp-1,self.state.regs.b);self.state.memory.store(sp-2,self.state.regs.c)
  self.state.regs.sp=claripy.BVV(sp-2,16);self.jump(self._n)
class PopBC(angr.SimProcedure):
 def __init__(self,n:int)->None:
  super().__init__();self._n=n
 def run(self):
  sp=self.state.solver.eval(self.state.regs.sp)
  self.state.regs.c=self.state.memory.load(sp,1);self.state.regs.b=self.state.memory.load(sp+1,1)
  self.state.regs.sp=claripy.BVV(sp+2,16);self.jump(self._n)
class PopHL(angr.SimProcedure):
 def __init__(self,n:int)->None:
  super().__init__();self._n=n
 def run(self):
  sp=self.state.solver.eval(self.state.regs.sp)
  lo=self.state.memory.load(sp,1);hi=self.state.memory.load(sp+1,1)
  self.state.regs.hl=claripy.Concat(lo,hi)
  self.state.regs.sp=claripy.BVV(sp+2,16);self.jump(self._n)
class Jmp(angr.SimProcedure):
 def __init__(self,t:int)->None:
  super().__init__();self._t=t
 def run(self):
  self.jump(self._t)
class ManualTextScrollSite(angr.SimProcedure):
 """Proved ManualTextScroll composition boundary at the call site under
 its terminating A/B observation (the established text-poll boundary
 precedent): the saved registers pass through and A := SFX_PRESS_AB with
 F := the entry F. The link-battling branch loops through the dispatcher
 and is out of this domain (wLinkState is concrete non-battling)."""
 def __init__(self,n:int)->None:
  super().__init__();self._n=n
 def run(self):
  self.state.regs.a=claripy.BVV(0x90,8)
  self.jump(self._n)
def assembly(v):
 l=symbol_location(SYMS,'TextCommand_WAIT_BUTTON');m=symbol_location(SYMS,'ManualTextScroll')
 assert l.bank==0 and l.address==HANDLER and m.address==0x3898
 assert linked_bytes(ROM,l,len(HANDLER_EXPECTED))==HANDLER_EXPECTED
 p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});b=l.address
 p.hook(b+0x00,PushBC(b+0x01),length=1)                         # push bc
 p.hook(b+0x01,ManualTextScrollSite(b+0x04),length=3)           # call ManualTextScroll (proved boundary)
 p.hook(b+0x04,PopBC(b+0x05),length=1)                          # pop bc
 p.hook(b+0x05,PopHL(b+0x06),length=1)                          # pop hl
 p.hook(b+0x06,Jmp(CONT),length=3)                              # jp NextTextCommand (continuation)
 st=p.factory.blank_state(addr=b);set_assembly_registers(st,v);setup(st,v,False)
 sp=STACK-2
 st.regs.sp=sp;st.memory.store(sp,v['l'],endness='Iend_LE');st.memory.store(sp+1,v['h'],endness='Iend_LE');st.memory.store(STACK,claripy.BVV(RETURN,16),endness='Iend_LE')
 m=p.factory.simulation_manager(st);m.explore(find=lambda st:st.addr==CONT,num_find=64);assert not m.errored and len(m.found)==1
 out=[]
 for x in m.found:
  ar=assembly_registers(x)
  out.append(E(**{**{k:v for k,v in ar.items() if k not in ('h','l')},'hl':claripy.Concat(x.regs.l,x.regs.h)},link=x.memory.load(WLINKSTATE,1),constraints=tuple(x.solver.constraints)))
 return out
def native(v):
 p=angr.Project(ELF,auto_load_libs=False)
 f=p.loader.find_symbol('port_text_command_wait_button');assert f
 s=p.factory.call_state(f.rebased_addr,NS,NM);store_native_registers(s,NS,v);setup(s,v,True)
 m=p.factory.simulation_manager(s);m.run();assert not m.errored and len(m.deadended)==1
 out=[]
 for x in m.deadended:
  nr=native_registers(x,NS)
  out.append(E(**{**{k:v for k,v in nr.items() if k not in ('h','l')},'hl':claripy.Concat(nr['h'],nr['l'])},link=x.memory.load(NM+WLINKSTATE,1),constraints=tuple(x.solver.constraints)))
 return out
@pytest.mark.skipif(not ELF.exists() or not ROM.exists() or not SYMS.exists(),reason='build')
def test_text_command_wait_button_pathwise_equivalence():
 v=inputs('twtb');assert_pathwise_equivalent(assembly(v),native(v),('a','f','b','c','d','e','hl','link'))
