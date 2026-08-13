from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import angr,claripy,pytest
from archinfo import ArchPcode
from verification.harness.equivalence import assert_pathwise_equivalent
from verification.harness.registers import REGISTERS,assembly_registers,native_registers,set_assembly_registers,store_native_registers,symbolic_registers
from verification.harness.rom import linked_bytes,rom_window,symbol_location
from verification.harness.sm83_shims import Sm83DecRegister,Sm83IncRegister,Sm83RrRegister
ROOT=Path(__file__).resolve().parents[2];NATIVE_ELF=ROOT/'verification/build/ports.elf';ROM=ROOT/'pokered.gbc';SYMBOLS=ROOT/'pokered.sym';NATIVE_STATE=0x100000
LOOP=0xeffb;REPEAT=0xeffc;FINISH=0xeffd;DONE=0xeffe
NAMES=('visited_low','visited_high','written','write_h','write_l')
class Load(angr.SimProcedure):
 def __init__(self,key,n):super().__init__();self.key=key;self.n=n
 def run(self):self.state.regs.a=self.state.globals[self.key];self.jump(self.n)
class WriteA(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.state.globals['written']=self.state.regs.a;self.state.globals['write_h']=self.state.regs.h;self.state.globals['write_l']=self.state.regs.l;self.jump(self.n)
class WriteFF(WriteA):
 def run(self):self.state.globals['written']=claripy.BVV(0xff,8);self.state.globals['write_h']=self.state.regs.h;self.state.globals['write_l']=self.state.regs.l;self.jump(self.n)
class Boundary(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):self.jump(self.n)
class LoopSrl(angr.SimProcedure):
 def __init__(self,n):super().__init__();self.n=n
 def run(self):
  if self.state.globals.get('entered',False):self.jump(REPEAT)
  else:
   self.state.globals['entered']=True;v=self.state.regs.d;r=claripy.LShR(v,1);self.state.regs.d=r;self.state.regs.f=claripy.If(r==0,claripy.BVV(0x40,8),claripy.BVV(0,8))|claripy.ZeroExt(7,v[0]);self.jump(self.n)
@dataclass(frozen=True)
class E:
 a:claripy.ast.BV;f:claripy.ast.BV;b:claripy.ast.BV;c:claripy.ast.BV;d:claripy.ast.BV;e:claripy.ast.BV;h:claripy.ast.BV;l:claripy.ast.BV;memory:claripy.ast.BV;continuation:claripy.ast.BV;constraints:tuple[claripy.ast.Bool,...]
def inputs(p):
 i=symbolic_registers(p)
 for n in NAMES:i[n]=claripy.BVS(p+'_'+n,8)
 return i
def project():
 l=symbol_location(SYMBOLS,'BuildFlyLocationsList');p=angr.Project(rom_window(ROM,l.bank),auto_load_libs=False,rebase_granularity=0x100,main_opts={'backend':'blob','arch':ArchPcode('z80:LE:16:default'),'base_addr':0,'entry_point':l.address});return p,l.address
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
 p,q=project();p.hook(q+3,WriteFF(q+5),length=2);p.hook(q+6,Load('visited_low',q+9),length=3);p.hook(q+10,Load('visited_high',q+13),length=3);p.hook(q+17,Boundary(LOOP),length=2);s=p.factory.blank_state(addr=q);setup(s,i);m=p.factory.simulation_manager(s);m.explore(find=LOOP);return [ep(x,1) for x in m.found]
def assembly_step(i):
 p,q=project();p.hook(q+17,LoopSrl(q+19),length=2);p.hook(q+19,Sm83RrRegister('e',q+21),length=2);p.hook(q+26,WriteA(q+27),length=1);p.hook(q+28,Sm83IncRegister('b',q+29),length=1);p.hook(q+29,Sm83DecRegister('c',q+30),length=1);p.hook(q+32,Boundary(FINISH),length=2);s=p.factory.blank_state(addr=q+17);setup(s,i);ends=collect(p.factory.simulation_manager(s),{REPEAT,FINISH});return [ep(x,1 if x.addr==REPEAT else 0) for x in ends]
def assembly_finish(i):
 p,q=project();p.hook(q+32,WriteFF(q+34),length=2);p.hook(q+34,Boundary(DONE),length=1);s=p.factory.blank_state(addr=q+32);setup(s,i);m=p.factory.simulation_manager(s);m.explore(find=DONE);return [ep(x,0) for x in m.found]
def native(name,i,returns):
 p=angr.Project(NATIVE_ELF,auto_load_libs=False);fn=p.loader.find_symbol(name);assert fn;s=p.factory.call_state(fn.rebased_addr,NATIVE_STATE);store_native_registers(s,NATIVE_STATE,i);s.memory.store(NATIVE_STATE+8,claripy.Concat(*(i[n] for n in NAMES)));m=p.factory.simulation_manager(s);m.run();assert not m.errored;return [E(**native_registers(x,NATIVE_STATE),memory=x.memory.load(NATIVE_STATE+8,len(NAMES)),continuation=(x.regs.rax[7:0] if returns else claripy.BVV(0,8)),constraints=tuple(x.solver.constraints)) for x in m.deadended]
CASES=((assembly_setup,'port_build_fly_locations_setup',True),(assembly_step,'port_build_fly_locations_step',True),(assembly_finish,'port_build_fly_locations_finish',False))
@pytest.mark.skipif(not NATIVE_ELF.exists(),reason='native')
@pytest.mark.parametrize('assembly,name,returns',CASES)
def test_equivalence(assembly,name,returns):
 i=inputs(name);assert_pathwise_equivalent(assembly(i),native(name,i,returns),(*REGISTERS,'memory','continuation'))
def test_exact_body():
 l=symbol_location(SYMBOLS,'BuildFlyLocationsList');assert linked_bytes(ROM,l,35)==bytes.fromhex('213dcd36ff23fa0bd75ffa0cd757010b00cb3acb1b3efe3001787723040d20f136ffc9')
