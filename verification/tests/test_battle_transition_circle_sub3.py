from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair,Sm83AndImmediate,Sm83CpImmediate,Sm83DecRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000
LOOP1=0xeffa;ROW=0xeffb;REPEAT=0xeffc;RETURN=0xeffd;RESTART=0xeffe;LOOP2=0xefff
NAMES=('quadrant_y','quadrant_x','fetched','written','write_h','write_l','saved_h','saved_l')
class Load(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.regs.a=self.state.globals[self.key];self.jump(self.n)
class Save(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['saved_h']=self.state.regs.h;self.state.globals['saved_l']=self.state.regs.l;self.jump(self.n)
class Restore(Save):
 def run(self):self.state.regs.h=self.state.globals['saved_h'];self.state.regs.l=self.state.globals['saved_l'];self.jump(self.n)
class Boundary(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)
class LoopWrite(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  if self.state.globals.get('entered',False):self.jump(REPEAT)
  else:
   self.state.globals['entered']=True;self.state.globals['written']=claripy.BVV(0xff,8);self.state.globals['write_h']=self.state.regs.h;self.state.globals['write_l']=self.state.regs.l;self.jump(self.n)
class LoopStart(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  if self.state.globals.get('entered',False):self.jump(REPEAT)
  else:self.state.globals['entered']=True;self.jump(self.n)
class LoopLoad(LoopStart):
 def run(self):
  if self.state.globals.get('entered',False):self.jump(REPEAT)
  else:self.state.globals['entered']=True;self.state.regs.a=self.state.globals['quadrant_x'];self.jump(self.n)
class BranchZ(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  self.inhibit_autoret=True;self.successors.add_successor(self.state.copy(),RETURN,(self.state.regs.f&0x40)!=0,'Ijk_Boring');self.successors.add_successor(self.state.copy(),self.n,(self.state.regs.f&0x40)==0,'Ijk_Boring')
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;continuation:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for n in NAMES:i[n]=claripy.BVS(p+'_'+n,8)
 return i
def project():
 l=symbol_location(SYMBOLS,'BattleTransition_Circle_Sub3');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});return p,l.address
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
def assembly_entry(i):
 p,q=project();p.hook(q,Save(q+1),length=1);p.hook(q+1,Load('fetched',q+2),length=1);p.hook(q+4,Boundary(LOOP1),length=2);s=p.factory.blank_state(addr=q);setup(s,i);m=p.factory.simulation_manager(s);m.explore(find=LOOP1);return [ep(x,1) for x in m.found]
def assembly_loop1(i):
 p,q=project();p.hook(q+4,LoopWrite(q+6),length=2);p.hook(q+6,Load('quadrant_x',q+9),length=3);p.hook(q+9,Sm83AndImmediate(0xff,q+10),length=1);p.hook(q+16,Sm83DecRegister('c',q+17),length=1);p.hook(q+19,Restore(ROW),length=1);s=p.factory.blank_state(addr=q+4);setup(s,i);ends=collect(p.factory.simulation_manager(s),{REPEAT,ROW});return [ep(x,1 if x.addr==REPEAT else 0) for x in ends]
def assembly_row(i):
 p,q=project();p.hook(q+20,Load('quadrant_y',q+23),length=3);p.hook(q+23,Sm83AndImmediate(0xff,q+24),length=1);p.hook(q+32,Sm83AddHlRegisterPair('bc',q+33),length=1);p.hook(q+33,Load('fetched',q+34),length=1);p.hook(q+35,Sm83CpImmediate(0xff,q+37),length=2);p.hook(q+37,BranchZ(q+38),length=1);p.hook(q+38,Sm83AndImmediate(0xff,q+39),length=1);p.hook(q,Boundary(RESTART),length=1);p.hook(q+42,Boundary(LOOP2),length=3);s=p.factory.blank_state(addr=q+20);setup(s,i);ends=collect(p.factory.simulation_manager(s),{RETURN,RESTART,LOOP2});codes={RETURN:0,RESTART:2,LOOP2:3};return [ep(x,codes[x.addr]) for x in ends]
def assembly_loop2(i):
 p,q=project();p.hook(q+42,LoopLoad(q+45),length=3);p.hook(q+45,Sm83AndImmediate(0xff,q+46),length=1);p.hook(q+52,Sm83DecRegister('c',q+53),length=1);p.hook(q,Boundary(RESTART),length=1);s=p.factory.blank_state(addr=q+42);setup(s,i);ends=collect(p.factory.simulation_manager(s),{REPEAT,RESTART});return [ep(x,3 if x.addr==REPEAT else 2) for x in ends]
def native(name,i):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(name);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[n] for n in NAMES)));m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(NAMES)),continuation=x.regs.rax[7:0],constraints=tuple(x.solver.constraints)) for x in m.deadended]
CASES=((assembly_entry,'port_battle_transition_circle_entry'),(assembly_loop1,'port_battle_transition_circle_loop1_step'),(assembly_row,'port_battle_transition_circle_row'),(assembly_loop2,'port_battle_transition_circle_loop2_step'))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('assembly,name',CASES)
def test_equivalence(assembly,name):
 i=inputs(name);assert_pathwise_equivalent(assembly(i),native(name,i),(*REGISTERS,'memory','continuation'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'BattleTransition_Circle_Sub3');assert linked_bytes(ROM,l,57)==bytes.fromhex('e51a4f1336fffa3ecda728032318012b0d20f1e1fa3dcda7011400280301ecff091a13feffc8a728d74ffa3ecda728032b1801230d20f318c7')
