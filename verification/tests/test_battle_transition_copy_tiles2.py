from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83AddHlRegisterPair,Sm83AddImmediate,Sm83DecRegister,Sm83IncRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000
OUTER=0xeff8;INNER=0xeff9;REPEAT=0xeffa;OUTER_FINISH=0xeffb;FILL=0xeffc;DONE=0xeffd
NAMES=('offset_low','offset_high','fetched','written','write_h','write_l','saved_b','saved_c','saved_h','saved_l','saved_d','saved_e')
class Load(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.regs.a=self.state.globals[self.key];self.jump(self.n)
class Store(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.globals[self.key]=self.state.regs.a;self.jump(self.n)
class SaveAll(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  for x in 'bcdehl':self.state.globals['saved_'+x]=getattr(self.state.regs,x)
  self.jump(self.n)
class CrossRestore(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.h=self.state.globals['saved_d'];self.state.regs.l=self.state.globals['saved_e'];self.state.regs.d=self.state.globals['saved_h'];self.state.regs.e=self.state.globals['saved_l'];self.jump(self.n)
class RestoreBc(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.regs.b=self.state.globals['saved_b'];self.state.regs.c=self.state.globals['saved_c'];self.jump(self.n)
class Boundary(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)
class LoopLoad(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  if self.state.globals.get('entered',False):self.jump(REPEAT)
  else:self.state.globals['entered']=True;self.state.regs.a=self.state.globals['fetched'];self.jump(self.n)
class Write(angr.SimProcedure):
 def __init__(self,n,ff=False):super().__init__();self.n=n;self.ff=ff
 def run(self):self.state.globals['written']=claripy.BVV(0xff,8) if self.ff else self.state.regs.a;self.state.globals['write_h']=self.state.regs.h if self.ff else self.state.regs.d;self.state.globals['write_l']=self.state.regs.l if self.ff else self.state.regs.e;self.jump(self.n)
class FillHead(Write):
 def run(self):
  if self.state.globals.get('entered',False):self.jump(FILL)
  else:self.state.globals['entered']=True;self.state.globals['written']=claripy.BVV(0xff,8);self.state.globals['write_h']=self.state.regs.h;self.state.globals['write_l']=self.state.regs.l;self.jump(self.n)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;continuation:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for n in NAMES:i[n]=claripy.BVS(p+'_'+n,8)
 return i
def project():
 l=symbol_location(SYMBOLS,'BattleTransition_CopyTiles2');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});return p,l.address
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
 p,q=project();p.hook(q+1,Store('offset_low',q+4),length=3);p.hook(q+5,Store('offset_high',q+8),length=3);p.hook(q+10,Boundary(OUTER),length=1);s=p.factory.blank_state(addr=q);setup(s,i);m=p.factory.simulation_manager(s);m.explore(find=OUTER);return [ep(x,1) for x in m.found]
def assembly_begin(i):
 p,q=project();p.hook(q+10,SaveAll(q+13),length=3);p.hook(q+15,Boundary(INNER),length=1);s=p.factory.blank_state(addr=q+10);setup(s,i);m=p.factory.simulation_manager(s);m.explore(find=INNER);return [ep(x,0) for x in m.found]
def assembly_inner(i):
 p,q=project();p.hook(q+15,LoopLoad(q+16),length=1);p.hook(q+16,Write(q+17),length=1);p.hook(q+18,Sm83AddImmediate(20,q+20),length=2);p.hook(q+22,Sm83IncRegister('d',q+23),length=1);p.hook(q+25,Sm83AddImmediate(20,q+27),length=2);p.hook(q+29,Sm83IncRegister('h',q+30),length=1);p.hook(q+31,Sm83DecRegister('c',q+32),length=1);p.hook(q+34,Boundary(OUTER_FINISH),length=1);s=p.factory.blank_state(addr=q+15);setup(s,i);ends=collect(p.factory.simulation_manager(s),{REPEAT,OUTER_FINISH});return [ep(x,1 if x.addr==REPEAT else 0) for x in ends]
def assembly_outer(i):
 p,q=project();p.hook(q+34,CrossRestore(q+36),length=2);p.hook(q+36,Load('offset_low',q+39),length=3);p.hook(q+40,Load('offset_high',q+43),length=3);p.hook(q+44,Sm83AddHlRegisterPair('bc',q+45),length=1);p.hook(q+45,RestoreBc(q+46),length=1);p.hook(q+46,Sm83DecRegister('c',q+47),length=1);p.hook(q+10,Boundary(OUTER),length=1);p.hook(q+56,Boundary(FILL),length=2);s=p.factory.blank_state(addr=q+34);setup(s,i);ends=collect(p.factory.simulation_manager(s),{OUTER,FILL});return [ep(x,1 if x.addr==OUTER else 2) for x in ends]
def assembly_fill(i):
 p,q=project();p.hook(q+56,FillHead(q+58,True),length=2);p.hook(q+58,Sm83AddHlRegisterPair('de',q+59),length=1);p.hook(q+59,Sm83DecRegister('c',q+60),length=1);p.hook(q+62,Boundary(DONE),length=1);s=p.factory.blank_state(addr=q+56);setup(s,i);ends=collect(p.factory.simulation_manager(s),{FILL,DONE});return [ep(x,2 if x.addr==FILL else 0) for x in ends]
def native(name,i,returns,constant):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(name);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[n] for n in NAMES)));m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(NAMES)),continuation=(x.regs.rax[7:0] if returns else claripy.BVV(constant,8)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
CASES=((assembly_setup,'port_battle_transition_copy_tiles2_setup',True,0),(assembly_begin,'port_battle_transition_copy_tiles2_row_begin',False,0),(assembly_inner,'port_battle_transition_copy_tiles2_inner_step',True,0),(assembly_outer,'port_battle_transition_copy_tiles2_outer_finish',True,0),(assembly_fill,'port_battle_transition_copy_tiles2_fill_step',True,0))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('assembly,name,returns,constant',CASES)
def test_equivalence(assembly,name,returns,constant):
 i=inputs(name);assert_pathwise_equivalent(assembly(i),native(name,i,returns,constant),(*REGISTERS,'memory','continuation'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'BattleTransition_CopyTiles2');assert linked_bytes(ROM,l,63)==bytes.fromhex('79ea3dcd78ea3ecd0e09c5e5d50e127e127bc6143001145f7dc6143001246f0d20ede1d1fa3dcd4ffa3ecd4709c10d20d96b621114000e1236ff190d20fac9')
