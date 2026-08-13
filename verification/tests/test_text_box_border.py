from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair,Sm83DecRegister,Sm83IncRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000
REPEAT=0xeff9;DONE=0xeffa
NAMES=('written','write_h','write_l','saved_h','saved_l')
class Boundary(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)
class EnterChars(Boundary):
 def run(self):self.state.regs.d=self.state.regs.c;self.jump(self.n)
class SetA(Boundary):
 def __init__(self,value,n):super().__init__(n);self.value=value
 def run(self):self.state.regs.a=self.value;self.jump(self.n)
class SetDE(Boundary):
 def run(self):self.state.regs.d=0;self.state.regs.e=20;self.jump(self.n)
class Save(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['saved_h']=self.state.regs.h;self.state.globals['saved_l']=self.state.regs.l;self.jump(self.n)
class Restore(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.h=self.state.globals['saved_h'];self.state.regs.l=self.state.globals['saved_l'];self.jump(self.n)
class Store(angr.SimProcedure):
 def __init__(self,n,value=None,inc=False):super().__init__();self.n=n;self.value=value;self.inc=inc
 def run(self):
  self.state.globals['written']=self.state.regs.a if self.value is None else claripy.BVV(self.value,8);self.state.globals['write_h']=self.state.regs.h;self.state.globals['write_l']=self.state.regs.l
  if self.inc:self.state.regs.hl=self.state.regs.hl+1
  self.jump(self.n)
class Branch(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  self.inhibit_autoret=True;c=(self.state.regs.f&0x40)==0;self.successors.add_successor(self.state.copy(),REPEAT,c,'Ijk_Boring');self.successors.add_successor(self.state.copy(),self.n,claripy.Not(c),'Ijk_Boring')
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;continuation:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for n in NAMES:i[n]=claripy.BVS(p+'_'+n,8)
 return i
def project():
 l=symbol_location(SYMBOLS,'TextBoxBorder');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});return p,l.address
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
def run(i,start,hooks,targets={DONE}):
 p,q=project()
 for off,proc,length in hooks:
  if hasattr(proc,'n') and proc.n < 0x100:proc.n+=q
  if hasattr(proc,'_next_address') and proc._next_address < 0x100:proc._next_address+=q
  p.hook(q+off,proc,length=length)
 s=p.factory.blank_state(addr=q+start);setup(s,i);return [ep(x,1 if x.addr==REPEAT else 0) for x in collect(p.factory.simulation_manager(s),targets)]
def assembly_top_begin(i):return run(i,0,((0,Save(1),1),(1,SetA(0x79,3),2),(3,Store(4,None,True),1),(4,Sm83IncRegister('a',5),1),(5,EnterChars(DONE),3)))
def assembly_char(i):return run(i,46,((46,Store(47,None,True),1),(47,Sm83DecRegister('d',48),1),(48,Branch(DONE),2)),{REPEAT,DONE})
def assembly_top_end(i):return run(i,8,((8,Sm83IncRegister('a',9),1),(9,Store(10),1),(10,Restore(11),1),(11,SetDE(14),3),(14,Sm83AddHlRegisterPair('de',DONE),1)))
def assembly_middle_begin(i):return run(i,15,((15,Save(16),1),(16,SetA(0x7c,18),2),(18,Store(19,None,True),1),(19,SetA(0x7f,21),2),(21,EnterChars(DONE),3)))
def assembly_middle_end(i):return run(i,24,((24,Store(26,0x7c),2),(26,Restore(27),1),(27,SetDE(30),3),(30,Sm83AddHlRegisterPair('de',31),1),(31,Sm83DecRegister('b',32),1),(32,Branch(DONE),2)),{REPEAT,DONE})
def assembly_bottom_begin(i):return run(i,34,((34,SetA(0x7d,36),2),(36,Store(37,None,True),1),(37,SetA(0x7a,39),2),(39,EnterChars(DONE),3)))
def assembly_bottom_end(i):return run(i,42,((42,Store(DONE,0x7e),2),))
def native(name,i,returns):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(name);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[n] for n in NAMES)));m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(NAMES)),continuation=(x.regs.rax[7:0] if returns else claripy.BVV(0,8)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
CASES=((assembly_top_begin,'port_text_box_border_top_begin',False),(assembly_char,'port_text_box_border_place_char_step',True),(assembly_top_end,'port_text_box_border_top_end',False),(assembly_middle_begin,'port_text_box_border_middle_begin',False),(assembly_middle_end,'port_text_box_border_middle_end',True),(assembly_bottom_begin,'port_text_box_border_bottom_begin',False),(assembly_bottom_end,'port_text_box_border_bottom_end',False))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('assembly,name,returns',CASES)
def test_equivalence(assembly,name,returns):
 i=inputs(name);assert_pathwise_equivalent(assembly(i),native(name,i,returns),(*REGISTERS,'memory','continuation'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'TextBoxBorder');assert linked_bytes(ROM,l,51)==bytes.fromhex('e53e79223ccd4f193c77e111140019e53e7c223e7fcd4f19367ce1111400190520ed3e7d223e7acd4f19367ec951221520fcc9')
