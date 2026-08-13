from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddRegister,Sm83AndImmediate,Sm83DecRegister,Sm83SubImmediate
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000
EMPTY=0xeff7;REPEAT=0xeff8;RIGHT=0xeff9;FILL=0xeffa;DONE=0xeffb;RETURN=0xeffc
NAMES=('hp_bar_type','written0','written1','write_h','write_l','saved_b','saved_c','saved_d','saved_e','saved_h','saved_l')
class Boundary(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)
class Branch(angr.SimProcedure):
 def __init__(self,mask,want,taken,n):super().__init__();self.mask=mask;self.want=want;self.taken=taken;self.n=n
 def run(self):
  self.inhibit_autoret=True;condition=(self.state.regs.f&self.mask)!=0
  if not self.want:condition=claripy.Not(condition)
  self.successors.add_successor(self.state.copy(),self.taken,condition,'Ijk_Boring');self.successors.add_successor(self.state.copy(),self.n,claripy.Not(condition),'Ijk_Boring')
class PushSave(angr.SimProcedure):
 def __init__(self,pair,n,save=True):super().__init__();self.pair=pair;self.n=n;self.save=save
 def run(self):
  if self.save:
   self.state.globals['saved_'+self.pair[0]]=getattr(self.state.regs,self.pair[0]);self.state.globals['saved_'+self.pair[1]]=getattr(self.state.regs,self.pair[1])
  self.jump(self.n)
class PopSaved(angr.SimProcedure):
 def __init__(self,pair,n,add=0):super().__init__();self.pair=pair;self.n=n;self.add=add
 def run(self):
  value=claripy.Concat(self.state.globals['saved_'+self.pair[0]],self.state.globals['saved_'+self.pair[1]])+self.add
  setattr(self.state.regs,self.pair[0],value[15:8]);setattr(self.state.regs,self.pair[1],value[7:0]);self.jump(self.n)
class Read(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.regs.a=self.state.globals[self.key];self.jump(self.n)
class Store(angr.SimProcedure):
 def __init__(self,slot,n,increment=False,first=False):super().__init__();self.slot=slot;self.n=n;self.increment=increment;self.first=first
 def run(self):
  self.state.globals[self.slot]=self.state.regs.a
  if self.first:self.state.globals['write_h']=self.state.regs.h;self.state.globals['write_l']=self.state.regs.l
  if self.increment:self.state.regs.hl=self.state.regs.hl+1
  self.jump(self.n)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;continuation:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for n in NAMES:i[n]=claripy.BVS(p+'_'+n,8)
 return i
def project():
 l=symbol_location(SYMBOLS,'DrawHPBar');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});return p,l.address
def setup(s,i):
 set_assembly_registers(s,i)
 for n in NAMES:s.globals[n]=i[n]
def ep(x,c):return E(**assembly_registers(x),memory=claripy.Concat(*(x.globals[n] for n in NAMES)),continuation=claripy.BVV(c,8),constraints=tuple(x.solver.constraints))
def collect(m,targets):
 m.stashes['found']=[]
 while m.active:
  m.move(from_stash='active',to_stash='found',filter_func=lambda x:x.addr in targets)
  if m.active:m.step()
 return m.found
def assembly_setup(i):
 p,q=project();p.hook(q,PushSave('hl',q+1),length=1);p.hook(q+1,PushSave('de',q+2),length=1);p.hook(q+2,PushSave('bc',q+3),length=1);p.hook(q+5,Store('written0',q+6,True,True),length=1);p.hook(q+8,Store('written1',q+9,True),length=1);p.hook(q+9,PushSave('hl',q+10,False),length=1);p.hook(q+12,Boundary(EMPTY),length=1);s=p.factory.blank_state(addr=q);setup(s,i);ends=collect(p.factory.simulation_manager(s),{EMPTY});return [ep(x,0) for x in ends]
def assembly_empty(i):
 p,q=project();p.hook(q+12,Store('written0',q+13,True,True),length=1);p.hook(q+13,Sm83DecRegister('d',q+14),length=1);p.hook(q+14,Branch(0x40,False,REPEAT,RIGHT),length=2);s=p.factory.blank_state(addr=q+12);setup(s,i);ends=collect(p.factory.simulation_manager(s),{REPEAT,RIGHT});return [ep(x,1 if x.addr==REPEAT else 0) for x in ends]
def assembly_right(i):
 p,q=project();p.hook(q+16,Read('hp_bar_type',q+19),length=3);p.hook(q+19,Sm83DecRegister('a',q+20),length=1);p.hook(q+22,Branch(0x40,True,q+25,q+24),length=2);p.hook(q+24,Sm83DecRegister('a',q+25),length=1);p.hook(q+25,Store('written0',q+26,False,True),length=1);p.hook(q+26,PopSaved('hl',q+27,2),length=1);p.hook(q+27,Boundary(DONE),length=1);s=p.factory.blank_state(addr=q+16);setup(s,i);ends=collect(p.factory.simulation_manager(s),{DONE});return [ep(x,0) for x in ends]
def assembly_select(i):
 p,q=project();p.hook(q+28,Sm83AndImmediate(0xff,q+29),length=1);p.hook(q+29,Branch(0x40,False,FILL,q+31),length=2);p.hook(q+32,Sm83AndImmediate(0xff,q+33),length=1);p.hook(q+33,Branch(0x40,True,DONE,q+35),length=2);p.hook(q+37,Boundary(FILL),length=1);p.hook(q+56,Boundary(DONE),length=1);s=p.factory.blank_state(addr=q+27);setup(s,i);ends=collect(p.factory.simulation_manager(s),{FILL,DONE});return [ep(x,1 if x.addr==FILL else 0) for x in ends]
def assembly_fill(i):
 p,q=project();p.hook(q+38,Sm83SubImmediate(8,q+40),length=2);p.hook(q+40,Branch(1,True,q+52,q+42),length=2);p.hook(q+45,Store('written0',q+46,True,True),length=1);p.hook(q+47,Sm83AndImmediate(0xff,q+48),length=1);p.hook(q+48,Branch(0x40,True,DONE,REPEAT),length=2);p.hook(q+54,Sm83AddRegister('e',q+55),length=1);p.hook(q+55,Store('written0',DONE,False,True),length=1);s=p.factory.blank_state(addr=q+37);setup(s,i);ends=collect(p.factory.simulation_manager(s),{REPEAT,DONE});return [ep(x,1 if x.addr==REPEAT else 0) for x in ends]
def assembly_finish(i):
 p,q=project();p.hook(q+56,PopSaved('bc',q+57),length=1);p.hook(q+57,PopSaved('de',q+58),length=1);p.hook(q+58,PopSaved('hl',RETURN),length=1);s=p.factory.blank_state(addr=q+56);setup(s,i);ends=collect(p.factory.simulation_manager(s),{RETURN});return [ep(x,0) for x in ends]
def native(name,i,returns):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(name);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[n] for n in NAMES)));m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(NAMES)),continuation=(x.regs.rax[7:0] if returns else claripy.BVV(0,8)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
CASES=((assembly_setup,'port_draw_hp_bar_setup',False),(assembly_empty,'port_draw_hp_bar_empty_step',True),(assembly_right,'port_draw_hp_bar_right',False),(assembly_select,'port_draw_hp_bar_select_fill',True),(assembly_fill,'port_draw_hp_bar_fill_step',True),(assembly_finish,'port_draw_hp_bar_finish',False))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('assembly,name,returns',CASES)
def test_equivalence(assembly,name,returns):
 i=inputs(name);assert_pathwise_equivalent(assembly(i),native(name,i,returns),(*REGISTERS,'memory','continuation'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'DrawHPBar');assert linked_bytes(ROM,l,60)==bytes.fromhex('e5d5c53e71223e6222e53e63221520fcfa94cf3d3e6d28013d77e17ba7200679a728151e017bd608380a5f3e6b227ba7280618f13e638377c1d1e1c9')
